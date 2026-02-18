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

// PiholeDNSRecordSpec defines the desired state of PiholeDNSRecord
type PiholeDNSRecordSpec struct {
	// Hostname is the DNS name to create a record for
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Hostname string `json:"hostname"`

	// RecordType is the type of DNS record (A, AAAA, or CNAME)
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=A;AAAA;CNAME
	RecordType string `json:"recordType"`

	// IPAddress is the IP address for A or AAAA records
	// +optional
	IPAddress string `json:"ipAddress,omitempty"`

	// CNAMETarget is the target hostname for CNAME records
	// +optional
	CNAMETarget string `json:"cnameTarget,omitempty"`

	// Description is a human-readable description of this DNS record
	// +optional
	// +kubebuilder:validation:MaxLength=200
	Description string `json:"description,omitempty"`

	// TargetNamespaces lists namespaces to search for Pihole instances.
	// If empty or not set, only Pihole instances in the same namespace are used (default behavior).
	// Use ["*"] to target all namespaces (fleet-wide).
	// +optional
	TargetNamespaces []string `json:"targetNamespaces,omitempty"`
}

// PiholeDNSRecordStatus defines the observed state of PiholeDNSRecord
type PiholeDNSRecordStatus struct {
	// Conditions represent the latest available observations of the PiholeDNSRecord's state
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastSyncTime is the last time the DNS record was successfully synced
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=dnsrec
// +kubebuilder:printcolumn:name="Hostname",type="string",JSONPath=".spec.hostname",description="DNS hostname"
// +kubebuilder:printcolumn:name="Type",type="string",JSONPath=".spec.recordType",description="Record type"
// +kubebuilder:printcolumn:name="IP",type="string",JSONPath=".spec.ipAddress",description="IP address",priority=1
// +kubebuilder:printcolumn:name="CNAME",type="string",JSONPath=".spec.cnameTarget",description="CNAME target",priority=1
// +kubebuilder:printcolumn:name="Last Sync",type="date",JSONPath=".status.lastSyncTime",description="Last sync time"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// PiholeDNSRecord is the Schema for the piholednsrecords API
type PiholeDNSRecord struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PiholeDNSRecordSpec   `json:"spec,omitempty"`
	Status PiholeDNSRecordStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PiholeDNSRecordList contains a list of PiholeDNSRecord
type PiholeDNSRecordList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PiholeDNSRecord `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PiholeDNSRecord{}, &PiholeDNSRecordList{})
}
