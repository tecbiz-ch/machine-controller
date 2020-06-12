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

package types

import (
	providerconfigtypes "github.com/kubermatic/machine-controller/pkg/providerconfig/types"
)

// RawConfig represents vsphere specific configuration.
type RawConfig struct {
	ImageName  providerconfigtypes.ConfigVarString `json:"imageName"`
	SubnetName providerconfigtypes.ConfigVarString `json:"subnetName"`
	Username   providerconfigtypes.ConfigVarString `json:"username"`
	Password   providerconfigtypes.ConfigVarString `json:"password"`
	NutanixURL providerconfigtypes.ConfigVarString `json:"nutanixURL"`
	Cluster    providerconfigtypes.ConfigVarString `json:"cluster"`

	CPUs          int32                                 `json:"cpus"`
	MemoryMB      int64                                 `json:"memoryMB"`
	DiskSizeGB    *int64                                `json:"diskSizeGB,omitempty"`
	AllowInsecure providerconfigtypes.ConfigVarBool     `json:"allowInsecure"`
	Tags          []providerconfigtypes.ConfigVarString `json:"tags,omitempty"`
}
