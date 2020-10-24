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

package v1alpha3

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This runtime.Object/DeepCopy tag is here for MachineSpec, in order to facilitate easier
// automated conversions from the earlier v1alpha1.
// +kubebuilder:object:root=true

// MachineSpec defines the desired state of ExistingInfraMachine
type MachineSpec struct {
	// This TypeMeta is not stored on encode, it is here just
	// to provide runtime.Object compliance for conversion.
	metav1.TypeMeta `json:"-"`

	Private    EndPoint `json:"private,omitempty"`
	Public     EndPoint `json:"public,omitempty"`
	ProviderID string   `json:"providerID,omitempty"`
}

// MachineStatus defines the observed state of ExistingInfraMachine
type MachineStatus struct {
	Ready bool `json:"ready"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status

// ExistingInfraMachine is the Schema for the existinginframachines API
type ExistingInfraMachine struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MachineSpec   `json:"spec,omitempty"`
	Status MachineStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ExistingInfraMachineList contains a list of ExistingInfraMachine
type ExistingInfraMachineList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ExistingInfraMachine `json:"items"`
}

// EndPoint groups the details required to establish a connection.
type EndPoint struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

const (
	// MachineFinalizer allows ReconcileExistingInfraMachine to clean up before
	// removing it from the apiserver.
	ExistingInfraMachineFinalizer = "existinginframachine.cluster.weave.works"
)

func init() {
	SchemeBuilder.Register(&ExistingInfraMachine{}, &ExistingInfraMachineList{})
}
