/*
Copyright 2019 The Machine Controller Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nutanix

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kubermatic/machine-controller/pkg/apis/cluster/common"
	"github.com/kubermatic/machine-controller/pkg/apis/cluster/v1alpha1"
	cloudprovidererrors "github.com/kubermatic/machine-controller/pkg/cloudprovider/errors"
	"github.com/kubermatic/machine-controller/pkg/cloudprovider/instance"
	nutanixtypes "github.com/kubermatic/machine-controller/pkg/cloudprovider/provider/nutanix/types"
	cloudprovidertypes "github.com/kubermatic/machine-controller/pkg/cloudprovider/types"
	"github.com/kubermatic/machine-controller/pkg/providerconfig"
	providerconfigtypes "github.com/kubermatic/machine-controller/pkg/providerconfig/types"
	v1 "k8s.io/api/core/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"

	nutanix "github.com/tecbiz-ch/nutanix-go-sdk"
	nutanixschema "github.com/tecbiz-ch/nutanix-go-sdk/schema"
)

// Possible instance statuses.
const (
	statusInstanceRunning = "ON"
	statusInstanceStopped = "OFF"
)

type provider struct {
	configVarResolver *providerconfig.ConfigVarResolver
}

// New returns a nutanix provider
func New(configVarResolver *providerconfig.ConfigVarResolver) cloudprovidertypes.Provider {
	return &provider{configVarResolver: configVarResolver}
}

// Config contains nutanix provider configuration.
type Config struct {
	ImageName     string
	SubnetName    string
	Username      string
	Password      string
	NutanixURL    string
	Cluster       string
	AllowInsecure bool
	CPUs          int32
	MemoryMB      int64
	DiskSizeGB    *int64
	Tags          []string
}

const (
	createCheckTimeout     = 5 * time.Minute
	cloudinitStackScriptID = 392559
)

// Ensures that provider implements Provider interface.
var _ cloudprovidertypes.Provider = &provider{}

type nutanixInstance struct {
	nutanix *nutanixschema.VMIntent
}

func (d *nutanixInstance) Name() string {
	return d.nutanix.Spec.Name
}

func (d *nutanixInstance) ID() string {
	return d.nutanix.Metadata.UUID
}

func (d *nutanixInstance) Addresses() map[string]v1.NodeAddressType {
	addresses := map[string]v1.NodeAddressType{}
	if len(d.nutanix.Spec.Resources.NicList) > 0 {
		for _, n := range d.nutanix.Spec.Resources.NicList {
			addresses[n.IPEndpointList[0].IP] = v1.NodeInternalIP
		}
	}
	return addresses
}

func (d *nutanixInstance) Status() instance.Status {
	// Todo Check provisioning Status
	switch d.nutanix.Spec.Resources.PowerState {
	case statusInstanceRunning:
		return instance.StatusRunning
	case statusInstanceStopped:
		return instance.StatusDeleting
	default:
		// Cloning, Migrating, Offline, Rebooting,
		// Rebuilding, Resizing, Restoring, ShuttingDown
		return instance.StatusUnknown
	}
}

func (p *provider) AddDefaults(spec v1alpha1.MachineSpec) (v1alpha1.MachineSpec, error) {
	return spec, nil
}

func (p *provider) Get(machine *v1alpha1.Machine, _ *cloudprovidertypes.ProviderData) (instance.Instance, error) {
	c, _, err := p.getConfig(machine.Spec.ProviderSpec)
	if err != nil {
		return nil, cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("Failed to parse MachineSpec, due to %v", err),
		}
	}

	ctx := context.TODO()
	client := getClient(c.Username, c.Password, c.NutanixURL)

	vms, err := client.VM.List(
		ctx,
		&nutanixschema.DSMetadata{Filter: fmt.Sprintf("vm_name==%s", machine.Spec.Name)},
	)

	if err != nil {
		return nil, err
	}

	for _, vm := range vms.Entities {
		return &nutanixInstance{nutanix: vm}, nil
	}

	return nil, cloudprovidererrors.ErrInstanceNotFound
}

func (p *provider) Cleanup(machine *v1alpha1.Machine, data *cloudprovidertypes.ProviderData) (bool, error) {
	instance, err := p.Get(machine, data)
	if err != nil {
		if err == cloudprovidererrors.ErrInstanceNotFound {
			return true, nil
		}
		return false, err
	}

	c, _, err := p.getConfig(machine.Spec.ProviderSpec)
	if err != nil {
		return false, cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("Failed to parse MachineSpec, due to %v", err),
		}
	}
	ctx := context.TODO()
	client := getClient(c.Username, c.Password, c.NutanixURL)

	vm, err := client.VM.Get(ctx, instance.ID())
	if err != nil {
		return false, err
	}

	err = client.VM.Delete(ctx, vm)
	if err != nil {
		return false, err
	}

	return false, nil
}

func (p *provider) Create(machine *v1alpha1.Machine, _ *cloudprovidertypes.ProviderData, userdata string) (instance.Instance, error) {
	c, pc, err := p.getConfig(machine.Spec.ProviderSpec)
	if err != nil {
		return nil, cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("Failed to parse MachineSpec, due to %v", err),
		}
	}

	var containerLinuxUserdata string
	if pc.OperatingSystem == providerconfigtypes.OperatingSystemCoreos ||
		pc.OperatingSystem == providerconfigtypes.OperatingSystemFlatcar {
		containerLinuxUserdata = userdata
	}

	ctx := context.TODO()
	client := getClient(c.Username, c.Password, c.NutanixURL)

	cluster, err := client.Cluster.Get(ctx, c.Cluster)
	if err != nil {
		return nil, fmt.Errorf("cluster not found %s", c.Cluster)
	}

	image, err := client.Image.Get(ctx, c.ImageName)
	if err != nil {
		return nil, fmt.Errorf("image not found %s", c.ImageName)
	}

	subnet, err := client.Subnet.Get(ctx, c.SubnetName)
	if err != nil {
		return nil, fmt.Errorf("subnet not found %s", c.SubnetName)
	}

	guestCustomization := &nutanixschema.GuestCustomization{
		CloudInit: &nutanixschema.GuestCustomizationCloudInit{
			UserData: base64.StdEncoding.EncodeToString([]byte(containerLinuxUserdata)),
		},
	}

	req := &nutanixschema.VMIntent{
		Spec: &nutanixschema.VM{
			Name: machine.Spec.Name,
			Resources: &nutanixschema.VMResources{
				GuestCustomization: guestCustomization,
				MemorySizeMib:      c.MemoryMB,
				NumSockets:         1,
				SerialPortList: []*nutanixschema.VMSerialPort{
					{
						Index:       0,
						IsConnected: true,
					},
				},
				DiskList: []*nutanixschema.VMDisk{
					{
						DeviceProperties: &nutanixschema.VMDiskDeviceProperties{
							DeviceType: "DISK",
							DiskAddress: &nutanixschema.DiskAddress{
								AdapterType: "SCSI",
							},
						},
						DataSourceReference: &nutanixschema.Reference{
							Kind: "image",
							UUID: image.Metadata.UUID,
						},
					},
				},
				NicList: []*nutanixschema.VMNic{
					{
						IsConnected: true,
						SubnetReference: &nutanixschema.Reference{
							Kind: "subnet",
							UUID: subnet.Metadata.UUID,
						},
					},
				},
			},
			ClusterReference: &nutanixschema.Reference{
				Kind: "cluster",
				UUID: cluster.Metadata.UUID,
			},
		},
		Metadata: &nutanixschema.Metadata{
			Kind: "vm",
		},
	}

	result, err := client.VM.Create(ctx, req)
	if err != nil {
		return nil, err
	}

	//taskUUID := result.Status.ExecutionContext.TaskUUID.(string)

	return &nutanixInstance{nutanix: result}, err

}

func (p *provider) GetCloudConfig(spec v1alpha1.MachineSpec) (config string, name string, err error) {
	return "", "", nil
}

func (p *provider) MigrateUID(machine *v1alpha1.Machine, new ktypes.UID) error {
	return nil
}

func (p *provider) MachineMetricsLabels(machine *v1alpha1.Machine) (map[string]string, error) {
	labels := make(map[string]string)

	c, _, err := p.getConfig(machine.Spec.ProviderSpec)
	if err == nil {
		labels["size"] = fmt.Sprintf("%d-cpus-%d-mb", c.CPUs, c.MemoryMB)
		labels["cluster"] = c.Cluster
	}

	return labels, err
}

func (p *provider) SetMetricsForMachines(machines v1alpha1.MachineList) error {
	return nil
}

func (p *provider) Validate(spec v1alpha1.MachineSpec) error {
	ctx := context.Background()

	c, pc, err := p.getConfig(spec.ProviderSpec)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	if c.Username == "" {
		return errors.New("username is missing")
	}

	if c.Password == "" {
		return errors.New("password is missing")
	}

	if c.NutanixURL == "" {
		return errors.New("nutanixurl is missing")
	}

	if c.Cluster == "" {
		return errors.New("cluster is missing")
	}

	if c.SubnetName == "" {
		return errors.New("subnetname is missing")
	}

	if c.ImageName == "" {
		return errors.New("imagename is missing")
	}

	client := getClient(c.Username, c.Password, c.NutanixURL)

	klog.V(6).Infof("Validate Cluster %s", c.Cluster)

	_, err = client.Cluster.Get(ctx, c.Cluster)
	if err != nil {
		return fmt.Errorf("cluster not found: %v", err)
	}

	klog.V(4).Infof("Validate Image %s", c.ImageName)

	_, err = client.Image.Get(ctx, c.ImageName)
	if err != nil {
		return err
	}

	klog.V(4).Infof("Validate Subnet %s", c.SubnetName)

	_, err = client.Subnet.Get(ctx, c.SubnetName)
	if err != nil {
		return err
	}

	if pc.OperatingSystem != providerconfigtypes.OperatingSystemCoreos &&
		pc.OperatingSystem != providerconfigtypes.OperatingSystemFlatcar {
		return fmt.Errorf("invalid/not supported operating system specified %q: %v", pc.OperatingSystem, providerconfigtypes.ErrOSNotSupported)
	}

	return nil
}

func (p *provider) getConfig(s v1alpha1.ProviderSpec) (*Config, *providerconfigtypes.Config, error) {
	if s.Value == nil {
		return nil, nil, fmt.Errorf("machine.spec.providerconfig.value is nil")
	}
	pconfig := providerconfigtypes.Config{}
	err := json.Unmarshal(s.Value.Raw, &pconfig)
	if err != nil {
		return nil, nil, err
	}
	rawConfig := nutanixtypes.RawConfig{}
	err = json.Unmarshal(pconfig.CloudProviderSpec.Raw, &rawConfig)
	if err != nil {
		return nil, nil, err
	}

	c := Config{}
	c.Username, err = p.configVarResolver.GetConfigVarStringValueOrEnv(rawConfig.Username, "NUTANIX_USERNAME")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get the value of \"username\" field, error = %v", err)
	}
	c.Password, err = p.configVarResolver.GetConfigVarStringValueOrEnv(rawConfig.Username, "NUTANIX_PASSWORD")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get the value of \"password\" field, error = %v", err)
	}
	c.NutanixURL, err = p.configVarResolver.GetConfigVarStringValueOrEnv(rawConfig.Username, "NUTANIX_URL")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get the value of \"nutanixurl\" field, error = %v", err)
	}
	c.Cluster, err = p.configVarResolver.GetConfigVarStringValue(rawConfig.Cluster)
	if err != nil {
		return nil, nil, err
	}
	c.ImageName, err = p.configVarResolver.GetConfigVarStringValue(rawConfig.ImageName)
	if err != nil {
		return nil, nil, err
	}
	c.SubnetName, err = p.configVarResolver.GetConfigVarStringValue(rawConfig.SubnetName)
	if err != nil {
		return nil, nil, err
	}

	for _, tag := range rawConfig.Tags {
		tagVal, err := p.configVarResolver.GetConfigVarStringValue(tag)
		if err != nil {
			return nil, nil, err
		}
		c.Tags = append(c.Tags, tagVal)
	}

	return &c, &pconfig, err
}

func getClient(username, password, apiurl string) *nutanix.Client {
	configCreds := nutanix.Credentials{
		Username: username,
		Password: password,
	}
	opts := []nutanix.ClientOption{
		nutanix.WithCredentials(&configCreds),
		nutanix.WithEndpoint(apiurl),
	}
	client := nutanix.NewClient(opts...)

	return client
}
