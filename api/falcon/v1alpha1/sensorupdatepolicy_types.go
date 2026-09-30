package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FalconSensorUpdatePolicySpec defines the desired state of FalconSensorUpdatePolicy
type FalconSensorUpdatePolicySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// The following markers will use OpenAPI v3 schema to validate the value
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html

	// SensorUpdatePolicy is the name of the sensor update policy.
	// +kubebuilder:validation:Required
	SensorUpdatePolicy string `json:"sensorUpdatePolicy"`

	// HostOverride overrides the Falcon API host used when creating API credentials.
	// +optional
	HostOverride string `json:"hostOverride,omitempty"`

	// PollingInterval defines how often the controller reconciles this resource.
	// Defaults to 10m if not set. Example: "5m", "1h".
	// +optional
	PollingInterval *metav1.Duration `json:"pollingInterval,omitempty"`

	// FalconSecret config is used to inject k8s secrets with sensitive data for the FalconSensor and the FalconAPI.
	// The following Falcon values are supported by k8s secret injection:
	//   falcon-cid
	//   falcon-provisioning-token
	//   falcon-client-id
	//   falcon-client-secret
	// +kubebuilder:validation:Required
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Platform Secrets Configuration",order=7
	FalconSecret FalconSecret `json:"falconSecret"`
}

// FalconSensorUpdatePolicyStatus defines the observed state of FalconSensorUpdatePolicy.
type FalconSensorUpdatePolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// sensorVersion is the sensor version resolved from the Falcon sensor update policy.
	// +optional
	SensorVersion string `json:"sensorVersion,omitempty"`

	// uninstallProtection is the uninstall protection setting on the Falcon sensor update policy.
	// Possible values: ENABLED, DISABLED, MAINTENANCE_MODE, IGNORE, UNKNOWN.
	// +optional
	UninstallProtection string `json:"uninstallProtection,omitempty"`

	// conditions represent the current state of the SensorUpdatePolicy resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Policy",type="string",JSONPath=".spec.sensorUpdatePolicy",description="Falcon sensor update policy name"
// +kubebuilder:printcolumn:name="Sensor Version",type="string",JSONPath=".status.sensorVersion",description="Sensor version from the Falcon update policy"
// +kubebuilder:printcolumn:name="Uninstall Protection",type="string",JSONPath=".status.uninstallProtection",description="Uninstall protection setting from the Falcon update policy"

// FalconSensorUpdatePolicy is the Schema for the falconsensorupdatepolicies API
type FalconSensorUpdatePolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of FalconSensorUpdatePolicy
	// +required
	Spec FalconSensorUpdatePolicySpec `json:"spec"`

	// status defines the observed state of FalconSensorUpdatePolicy
	// +optional
	Status FalconSensorUpdatePolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// FalconSensorUpdatePolicyList contains a list of FalconSensorUpdatePolicy
type FalconSensorUpdatePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []FalconSensorUpdatePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FalconSensorUpdatePolicy{}, &FalconSensorUpdatePolicyList{})
}
