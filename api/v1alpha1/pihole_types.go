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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CASecretKeyRef references a key within a Secret containing a CA certificate.
// Unlike SecretKeyRef, the key field is required — there is no sensible default
// for a CA certificate key name.
type CASecretKeyRef struct {
	// Name is the name of the Secret
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Key is the key within the Secret that contains the CA certificate PEM data
	// +kubebuilder:validation:Required
	Key string `json:"key"`
}

// SecretKeyRef references a key within an existing Secret.
type SecretKeyRef struct {
	// Name is the name of the secret
	Name string `json:"name"`

	// Key is the key within the secret to use
	// +optional
	// +kubebuilder:default="password"
	Key string `json:"key,omitempty"`
}

// PiholeAPITLSConfig defines TLS verification settings for Pi-hole API communication
type PiholeAPITLSConfig struct {
	// Enabled controls whether TLS certificate verification is performed.
	// When false (default), certificate verification is skipped — suitable for
	// Pi-hole's default self-signed certificates.
	// When true, the certificate is verified. For certs signed by a public CA
	// (e.g. Let's Encrypt, GoDaddy) no further config is needed — the system
	// CA pool is used automatically. For private or internal CAs, provide the
	// CA certificate via CASecretRef.
	// +optional
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// CASecretRef references a Secret containing a CA certificate used to verify
	// Pi-hole's TLS certificate. Only needed when Enabled is true and the cert is
	// signed by a private or internal CA (not in the system CA pool).
	// The key field is required — specify whichever key in the Secret holds the
	// PEM-encoded CA certificate (e.g. "ca.crt", "tls.crt").
	// +optional
	CASecretRef *CASecretKeyRef `json:"caSecretRef,omitempty"`
}

// PiholeSpec defines the desired state of Pihole
type PiholeSpec struct {
	// Size defines the number of Pi-hole instances. Each instance gets its own
	// persistent storage. Instances are kept in sync by the operator.
	// +optional
	// +kubebuilder:default=1
	Size *int32 `json:"size,omitempty"`

	// AdminPassword is the password for the Pi-hole web interface
	// If not provided, a random password will be generated
	// +optional
	AdminPassword string `json:"adminPassword,omitempty"`

	// AdminPasswordSecretRef references an existing Secret containing the admin password.
	// When set, the operator will not create a secret and will use this reference instead.
	// +optional
	AdminPasswordSecretRef *SecretKeyRef `json:"adminPasswordSecretRef,omitempty"`

	// Timezone for Pi-hole (e.g., "America/New_York", "Europe/London")
	// +optional
	// +kubebuilder:default="UTC"
	Timezone string `json:"timezone,omitempty"`

	// StorageSize is the size of the persistent volume for Pi-hole data
	// +optional
	// +kubebuilder:default="1Gi"
	StorageSize string `json:"storageSize,omitempty"`

	// StorageClass is the storage class to use for the PVC
	// +optional
	StorageClass string `json:"storageClass,omitempty"`

	// DnsServiceType is the Kubernetes service type for DNS (ClusterIP, NodePort, LoadBalancer)
	// +optional
	// +kubebuilder:default="NodePort"
	// +kubebuilder:validation:Enum=ClusterIP;NodePort;LoadBalancer
	DnsServiceType string `json:"dnsServiceType,omitempty"`

	// WebServiceType is the Kubernetes service type for Web UI (ClusterIP, NodePort, LoadBalancer)
	// +optional
	// +kubebuilder:default="ClusterIP"
	// +kubebuilder:validation:Enum=ClusterIP;NodePort;LoadBalancer
	WebServiceType string `json:"webServiceType,omitempty"`

	// DnsLoadBalancerIP is the IP to use for DNS LoadBalancer service type
	// +optional
	DnsLoadBalancerIP string `json:"dnsLoadBalancerIP,omitempty"`

	// WebLoadBalancerIP is the IP to use for Web LoadBalancer service type
	// +optional
	WebLoadBalancerIP string `json:"webLoadBalancerIP,omitempty"`

	// Image is the Pi-hole container image to use
	// +optional
	// +kubebuilder:default="docker.io/pihole/pihole:2025.11.0"
	Image string `json:"image,omitempty"`

	// Resources defines CPU/memory requests and limits for the Pi-hole container
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// UpstreamDNS is a list of upstream DNS servers for Pi-hole to forward queries to.
	// If not set, Pi-hole will use its default upstream servers (e.g. 8.8.8.8 and 8.8.4.4).
	// Example: ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
	// +optional
	UpstreamDNS []string `json:"upstreamDNS,omitempty"`

	// Ingress configures an Ingress resource for the Pi-hole web UI
	// +optional
	Ingress *PiholeIngress `json:"ingress,omitempty"`

	// TLS configures TLS verification for Pi-hole API communication.
	// Defaults to skipping certificate verification because Pi-hole uses self-signed certificates.
	// +optional
	TLS *PiholeAPITLSConfig `json:"tls,omitempty"`
}

// PiholeIngress defines Ingress configuration for the Pi-hole web UI
type PiholeIngress struct {
	// Enabled controls whether an Ingress is created
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// IngressClassName is the Ingress class to use
	// +optional
	IngressClassName *string `json:"ingressClassName,omitempty"`

	// Host is the hostname for the Ingress rule
	// +kubebuilder:validation:Required
	Host string `json:"host"`

	// TLS configures TLS for the Ingress
	// +optional
	TLS *PiholeIngressTLS `json:"tls,omitempty"`

	// Annotations to add to the Ingress
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// PiholeIngressTLS defines TLS config for the Ingress
type PiholeIngressTLS struct {
	// Enabled controls whether TLS is configured
	Enabled bool `json:"enabled"`

	// SecretName is the name of the TLS secret
	// +optional
	SecretName string `json:"secretName,omitempty"`
}

// PiholeStatus defines the observed state of Pihole.
type PiholeStatus struct {
	// Conditions represent the latest available observations of an object's state
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// AdminPasswordSecret is the name of the secret containing the admin password
	// +optional
	AdminPasswordSecret string `json:"adminPasswordSecret,omitempty"`

	// ServiceName is the name of the service created for this Pi-hole instance
	// +optional
	ServiceName string `json:"serviceName,omitempty"`

	// ReadyReplicas is the number of ready replicas
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// QueriesTotal is the total number of DNS queries processed (from pod 0)
	// +optional
	QueriesTotal int64 `json:"queriesTotal,omitempty"`

	// QueriesBlocked is the number of DNS queries that were blocked (from pod 0)
	// +optional
	QueriesBlocked int64 `json:"queriesBlocked,omitempty"`

	// BlockPercentage is the percentage of queries that were blocked, e.g. "9.99%"
	// +optional
	BlockPercentage string `json:"blockPercentage,omitempty"`

	// GravityDomains is the number of domains in the gravity (blocklist) database (from pod 0)
	// +optional
	GravityDomains int64 `json:"gravityDomains,omitempty"`

	// UniqueClients is the number of unique clients seen by Pi-hole (from pod 0)
	// +optional
	UniqueClients int32 `json:"uniqueClients,omitempty"`

	// WebURL is the URL to access the Pi-hole web interface
	// +optional
	WebURL string `json:"webURL,omitempty"`

	// DNSIP is the IP address of the DNS service (LoadBalancer IP or ClusterIP)
	// +optional
	DNSIP string `json:"dnsIP,omitempty"`

	// StatsLastUpdated is the last time stats were fetched from Pi-hole
	// +optional
	StatsLastUpdated *metav1.Time `json:"statsLastUpdated,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Queries",type="integer",JSONPath=".status.queriesTotal",description="Total DNS queries",priority=1
// +kubebuilder:printcolumn:name="Blocked",type="string",JSONPath=".status.blockPercentage",description="Percentage blocked",priority=1
// +kubebuilder:printcolumn:name="Gravity",type="integer",JSONPath=".status.gravityDomains",description="Gravity domains",priority=1
// +kubebuilder:printcolumn:name="DNS IP",type="string",JSONPath=".status.dnsIP",description="DNS service IP"
// +kubebuilder:printcolumn:name="Web URL",type="string",JSONPath=".status.webURL",description="Web UI URL",priority=1

// Pihole is the Schema for the piholes API
type Pihole struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of Pihole
	// +required
	Spec PiholeSpec `json:"spec"`

	// status defines the observed state of Pihole
	// +optional
	Status PiholeStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// PiholeList contains a list of Pihole
type PiholeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Pihole `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Pihole{}, &PiholeList{})
}
