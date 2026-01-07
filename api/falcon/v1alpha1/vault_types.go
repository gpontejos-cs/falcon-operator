package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VaultConfig configures HashiCorp Vault integration for secret management across multiple clusters
// +k8s:openapi-gen=true
type VaultConfig struct {
	// Central Vault server address
	Address string `json:"address"`

	// Multi-cluster configuration
	MultiCluster MultiClusterConfig `json:"multiCluster"`

	// Secrets to inject
	Secrets []VaultSecret `json:"secrets"`

	// Refresh interval
	RefreshInterval *metav1.Duration `json:"refreshInterval,omitempty"`

	// TLS configuration
	TLS *VaultTLSConfig `json:"tls,omitempty"`
}

// MultiClusterConfig defines multi-cluster configuration for Vault
// +k8s:openapi-gen=true
type MultiClusterConfig struct {
	// Current cluster identifier
	ClusterID string `json:"clusterID"`

	// Vault role for this cluster
	Role string `json:"role"`

	// Auth method path (defaults to kubernetes-{clusterID})
	AuthPath string `json:"authPath,omitempty"`

	// Service account for authentication
	ServiceAccount string `json:"serviceAccount,omitempty"`

	// Namespace for the service account
	ServiceAccountNamespace string `json:"serviceAccountNamespace,omitempty"`

	// Auto-detect cluster ID from node labels/annotations
	AutoDetectCluster bool `json:"autoDetectCluster,omitempty"`
}

// VaultSecret defines a secret to retrieve from Vault
// +k8s:openapi-gen=true
type VaultSecret struct {
	Path   string `json:"path"`
	Key    string `json:"key"`
	EnvVar string `json:"envVar"`

	// Cluster-specific path prefix
	ClusterSpecific bool `json:"clusterSpecific,omitempty"`
}

// VaultTLSConfig defines TLS configuration for Vault communication
// +k8s:openapi-gen=true
type VaultTLSConfig struct {
	CASecret           string `json:"caSecret,omitempty"`
	ClientCertSecret   string `json:"clientCertSecret,omitempty"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
}