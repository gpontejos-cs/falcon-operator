package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ClusterGuardAdmissionControlEnabledDefault = true
	ClusterGuardWatchEventsEnabledDefault      = true
	ClusterGuardSnapshotsEnabledDefault        = true
	ClusterGuardSnapshotIntervalDefault        = 22
)

// FalconClusterGuardNodeSpec defines configuration for the node sensor DaemonSet deployed by FalconClusterGuard.
// It is an alias of FalconNodeSensorConfig and will remain so until FalconNodeSensor is deprecated.
type FalconClusterGuardNodeSpec = FalconNodeSensorConfig

// FalconClusterGuardAdmissionSpec defines configuration for the admission controller deployed by FalconClusterGuard.
// It is an alias of FalconAdmissionConfigSpec and will remain so until FalconAdmission is deprecated.
type FalconClusterGuardAdmissionSpec = FalconAdmissionConfigSpec

// FalconClusterGuardSpec defines the desired state of FalconClusterGuard
type FalconClusterGuardSpec struct {
	// InstallNamespace is the namespace where the Falcon Cloud Guard resources will be deployed
	// +kubebuilder:default:=falcon-sensor
	// +optional
	InstallNamespace string `json:"installNamespace,omitempty"`

	// CrowdStrike Falcon sensor configuration
	// +kubebuilder:default:={}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Sensor Configuration",order=1
	Falcon FalconSensor `json:"falcon,omitempty"`

	// FalconAPI configures connection from your local Falcon operator to CrowdStrike Falcon platform.
	//
	// When configured, it will pull the sensor from registry.crowdstrike.com and deploy the appropriate sensor to the cluster.
	//
	// If using the API is not desired, the sensor can be manually configured by setting the Image field.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Platform API Configuration",order=2
	// +optional
	FalconAPI *FalconAPI `json:"falcon_api,omitempty"`

	// FalconSecret config is used to inject k8s secrets with sensitive data for the FalconAPI.
	// The following Falcon values are supported by k8s secret injection:
	//   falcon-client-id
	//   falcon-client-secret
	//   falcon-cid
	//   falcon-provisioning-token
	// +kubebuilder:default={"enabled": false}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Platform Secrets Configuration",order=2
	FalconSecret FalconSecret `json:"falconSecret,omitempty"`

	// Registry configures the container image registry used for the Cloud Guard image.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Cloud Guard Registry Configuration",order=3
	// +optional
	Registry RegistrySpec `json:"registry,omitempty"`

	// Location of the Falcon sensor image. Used for all deployed components. Use only when mirroring the image to a custom repository.
	// +kubebuilder:validation:Pattern="^.*:.*$"
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=4
	Image string `json:"image,omitempty"`

	// +kubebuilder:default=IfNotPresent
	// +kubebuilder:validation:Enum=Always;IfNotPresent;Never
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=5
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// ImagePullSecrets is an optional list of references to secrets used for pulling images across all deployed components.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=6
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// Version of the sensor to be installed. The latest version will be selected when this version specifier is missing.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Sensor Version",order=7
	// +optional
	Version *string `json:"version,omitempty"`

	// ClusterGuardConfig configures the runtime behaviour of FalconClusterGuard
	// +optional
	AdmissionConfig FalconClusterGuardAdmissionSpec `json:"admissionConfig,omitempty"`

	// NodeSensor configures the node sensor DaemonSet deployed alongside FalconClusterGuard.
	// +optional
	NodeSensor FalconClusterGuardNodeSpec `json:"nodeSensor,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Operator Version",type="string",JSONPath=".status.version",description="Version of the operator"

// FalconClusterGuard is the Schema for the falconclusterguards API
type FalconClusterGuard struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of FalconClusterGuard
	// +required
	Spec FalconClusterGuardSpec `json:"spec"`

	// status defines the observed state of FalconClusterGuard
	// +optional
	Status FalconCRStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FalconClusterGuardList contains a list of FalconClusterGuard
type FalconClusterGuardList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []FalconClusterGuard `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FalconClusterGuard{}, &FalconClusterGuardList{})
}

// FalconCRD interface implementation

// GetFalconSecretSpec returns the FalconSecret configuration
func (f *FalconClusterGuard) GetFalconSecretSpec() FalconSecret {
	return f.Spec.FalconSecret
}

// GetFalconAPISpec returns the FalconAPI configuration
func (f *FalconClusterGuard) GetFalconAPISpec() *FalconAPI {
	return f.Spec.FalconAPI
}

// SetFalconAPISpec sets the FalconAPI configuration
func (f *FalconClusterGuard) SetFalconAPISpec(api *FalconAPI) {
	f.Spec.FalconAPI = api
}

// GetFalconSpec returns the FalconSensor configuration
func (f *FalconClusterGuard) GetFalconSpec() FalconSensor {
	return f.Spec.Falcon
}

// SetFalconSpec sets the FalconSensor configuration
func (f *FalconClusterGuard) SetFalconSpec(sensor FalconSensor) {
	f.Spec.Falcon = sensor
}

// GetConditions returns a pointer to the Conditions slice for status updates
func (f *FalconClusterGuard) GetConditions() *[]metav1.Condition {
	return &f.Status.Conditions
}
