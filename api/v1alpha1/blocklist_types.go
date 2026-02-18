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

// BlocklistSpec defines the desired state of Blocklist
type BlocklistSpec struct {
	// Sources is a list of URLs pointing to blocklist files
	// Each URL should return a hosts file format or domain list
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	Sources []string `json:"sources"`

	// Enabled determines if this blocklist should be active
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// SyncInterval defines how often to refresh the blocklist (in minutes)
	// +optional
	// +kubebuilder:default=1440
	// +kubebuilder:validation:Minimum=60
	// +kubebuilder:validation:Maximum=10080
	SyncInterval int32 `json:"syncInterval,omitempty"`

	// Description is a human-readable description of what this blocklist blocks
	// +optional
	// +kubebuilder:validation:MaxLength=200
	Description string `json:"description,omitempty"`

	// TargetNamespaces lists namespaces to search for Pihole instances.
	// If empty or not set, only Pihole instances in the same namespace are used (default behavior).
	// Use ["*"] to target all namespaces (fleet-wide).
	// +optional
	TargetNamespaces []string `json:"targetNamespaces,omitempty"`
}

// BlocklistStatus defines the observed state of Blocklist
type BlocklistStatus struct {
	// Conditions represent the latest available observations of the Blocklist's state
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastSyncTime is the last time the blocklist was successfully synced
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// EntriesCount is the total number of blocked domains in this list
	// +optional
	EntriesCount int32 `json:"entriesCount,omitempty"`

	// SourcesStatus contains the status of each source URL
	// +optional
	SourcesStatus []SourceStatus `json:"sourcesStatus,omitempty"`
}

// SourceStatus represents the status of a single blocklist source
type SourceStatus struct {
	// URL is the source URL
	URL string `json:"url"`

	// Status indicates if the source was successfully fetched
	// +kubebuilder:validation:Enum=Success;Failed;Pending
	Status string `json:"status"`

	// EntriesCount is the number of entries from this source
	// +optional
	EntriesCount int32 `json:"entriesCount,omitempty"`

	// LastError contains the error message if fetch failed
	// +optional
	LastError string `json:"lastError,omitempty"`

	// LastFetchTime is when this source was last fetched
	// +optional
	LastFetchTime *metav1.Time `json:"lastFetchTime,omitempty"`
}

// PiholeReference represents a Pihole instance using this blocklist
type PiholeReference struct {
	// Name is the name of the Pihole instance
	Name string `json:"name"`

	// Namespace is the namespace of the Pihole instance
	Namespace string `json:"namespace"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=bl
// +kubebuilder:printcolumn:name="Sources",type="integer",JSONPath=".spec.sources[*]",description="Number of sources"
// +kubebuilder:printcolumn:name="Entries",type="integer",JSONPath=".status.entriesCount",description="Total blocked domains"
// +kubebuilder:printcolumn:name="Enabled",type="boolean",JSONPath=".spec.enabled",description="Whether blocklist is enabled"
// +kubebuilder:printcolumn:name="Last Sync",type="date",JSONPath=".status.lastSyncTime",description="Last sync time"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// Blocklist is the Schema for the blocklists API
type Blocklist struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BlocklistSpec   `json:"spec,omitempty"`
	Status BlocklistStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BlocklistList contains a list of Blocklist
type BlocklistList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Blocklist `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Blocklist{}, &BlocklistList{})
}
