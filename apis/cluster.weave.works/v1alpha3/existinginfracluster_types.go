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

// This runtime.Object/DeepCopy tag is here for ClusterSpec, in order to facilitate easier
// automated conversions from the earlier v1alpha1.
// +kubebuilder:object:root=true

// ClusterSpec defines the desired state of ExistingInfraCluster
type ClusterSpec struct {
	// This TypeMeta is not stored on encode, it is here just
	// to provide runtime.Object compliance for conversion.
	metav1.TypeMeta `json:"-"`

	User                     string `json:"user"`
	KubernetesVersion        string `json:"kubernetesVersion,omitempty"`
	ControllerImage          string `json:"controllerImage,omitempty"`
	ControlPlaneMachineCount string `json:"controlPlaneMachineCount,omitempty"`
	WorkerMachineCount       string `json:"workerMachineCount,omitempty"`
	DeprecatedSSHKeyPath     string `json:"sshKeyPath,omitempty"`
	HTTPProxy                string `json:"httpProxy,omitempty"`

	WorkloadCluster bool `json:"workloadCluster,omitempty"`

	Authentication *AuthenticationWebhook `json:"authenticationWebhook,omitempty"`
	Authorization  *AuthorizationWebhook  `json:"authorizationWebhook,omitempty"`

	OS              OSConfig         `json:"os,omitempty"`
	CRI             ContainerRuntime `json:"cri"`
	ImageRepository string           `json:"imageRepository,omitempty"`

	ControlPlaneEndpoint string    `json:"controlPlaneEndpoint,omitempty"`
	APIServer            APIServer `json:"apiServer,omitempty"`

	KubeletArguments []ServerArgument `json:"kubeletArguments,omitempty"`

	Addons []Addon `json:"addons,omitempty"`

	CloudProvider string `json:"cloudProvider,omitempty"`
}

// ClusterStatus defines the observed state of ExistingInfraCluster
type ClusterStatus struct {
	Ready bool `json:"ready"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status

// ExistingInfraCluster is the Schema for the existinginfraclusters API
type ExistingInfraCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterSpec   `json:"spec,omitempty"`
	Status ClusterStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ExistingInfraClusterList contains a list of ExistingInfraCluster
type ExistingInfraClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ExistingInfraCluster `json:"items"`
}

type OSConfig struct {
	Files []FileSpec `json:"files,omitempty"`
}

type FileSpec struct {
	Source      SourceSpec `json:"source"`
	Destination string     `json:"destination"`
}

type SourceSpec struct {
	ConfigMap string `json:"configmap"`
	Key       string `json:"key"`
	Contents  string `json:"contents,omitempty"`
}

type ContainerRuntime struct {
	Kind    string `json:"kind"`
	Package string `json:"package"`
	Version string `json:"version"`
}

type APIServer struct {
	AdditionalSANs []string         `json:"additionalSANs,omitempty"`
	ExtraArguments []ServerArgument `json:"extraArguments,omitempty"`
}

type ServerArgument struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type AuthenticationWebhook struct {
	CacheTTL   string `json:"cacheTTL,omitempty"`
	URL        string `json:"url"`
	SecretFile string `json:"secretFile"`
}

type AuthorizationWebhook struct {
	CacheAuthorizedTTL   string `json:"cacheAuthorizedTTL,omitempty"`
	CacheUnauthorizedTTL string `json:"cacheUnauthorizedTTL,omitempty"`
	URL                  string `json:"url"`
	SecretFile           string `json:"secretFile"`
}

// Addon describes an addon to install on the cluster.
type Addon struct {
	Name   string            `json:"name"`
	Params map[string]string `json:"params,omitempty"`
	Deps   []string          `json:"deps,omitempty"`
}

func init() {
	SchemeBuilder.Register(&ExistingInfraCluster{}, &ExistingInfraClusterList{})
}
