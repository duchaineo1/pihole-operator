/*
Copyright 2025.

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WhitelistSpec defines the desired state of Whitelist
type WhitelistSpec struct {
	// Domains is a list of domains to whitelist (allow)
	// Each entry should be a plain domain name (e.g. "example.com")
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=1000
	Domains []string `json:"domains"`

	// Enabled determines if this whitelist should be active
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Description is a human-readable description of why these domains are whitelisted
	// +optional
	// +kubebuilder:validation:MaxLength=200
	Description string `json:"description,omitempty"`
}

// WhitelistStatus defines the observed state of Whitelist
type WhitelistStatus struct {
	// Conditions represent the latest available observations of the Whitelist's state
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastSyncTime is the last time the whitelist was successfully synced
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// DomainsCount is the total number of whitelisted domains
	// +optional
	DomainsCount int32 `json:"domainsCount,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wl
// +kubebuilder:printcolumn:name="Domains",type="integer",JSONPath=".status.domainsCount",description="Number of whitelisted domains"
// +kubebuilder:printcolumn:name="Enabled",type="boolean",JSONPath=".spec.enabled",description="Whether whitelist is enabled"
// +kubebuilder:printcolumn:name="Last Sync",type="date",JSONPath=".status.lastSyncTime",description="Last sync time"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// Whitelist is the Schema for the whitelists API
type Whitelist struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WhitelistSpec   `json:"spec,omitempty"`
	Status WhitelistStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WhitelistList contains a list of Whitelist
type WhitelistList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Whitelist `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Whitelist{}, &WhitelistList{})
}
