/*
Copyright 2020 Weaveworks.

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

package v1alpha1

import (
	"errors"

	"github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"
	"k8s.io/apimachinery/pkg/conversion"
)

var errDowngradingConversion = errors.New("invalid conversion, downgrading conversions are not supported")

func Convert_v1alpha1_APIServer_To_v1alpha3_APIServer(_ *APIServer, _ *v1alpha3.APIServer, _ conversion.Scope) error {
	// in.ExternalLoadBalancer is unused in v1alpha3
	return nil
}

func Convert_v1alpha1_ClusterSpec_To_v1alpha3_ClusterSpec(in *ClusterSpec, out *v1alpha3.ClusterSpec, s conversion.Scope) error {
	// in.ObjectMeta is only used for preserving comments
	return autoConvert_v1alpha1_ClusterSpec_To_v1alpha3_ClusterSpec(in, out, s)
}

func Convert_v1alpha3_ClusterSpec_To_v1alpha1_ClusterSpec(_ *v1alpha3.ClusterSpec, _ *ClusterSpec, _ conversion.Scope) error {
	// Downgrading conversions are not supported
	return errDowngradingConversion
}

func Convert_v1alpha1_MachineSpec_To_v1alpha3_MachineSpec(in *MachineSpec, out *v1alpha3.MachineSpec, s conversion.Scope) error {
	// in.ObjectMeta is only used for preserving comments
	// in.Address is unused in v1alpha3
	// in.Port is unused in v1alpha3
	// in.PrivateAddress is unused in v1alpha3
	// in.PrivateInterface is unused in v1alpha3
	return autoConvert_v1alpha1_MachineSpec_To_v1alpha3_MachineSpec(in, out, s)
}

func Convert_v1alpha3_MachineSpec_To_v1alpha1_MachineSpec(_ *v1alpha3.MachineSpec, _ *MachineSpec, _ conversion.Scope) error {
	// Downgrading conversions are not supported
	return errDowngradingConversion
}
