package v1alpha1

import (
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CloudGuardAdmissionControlEnabledDefault = true
	CloudGuardWatchEventsEnabledDefault      = true
	CloudGuardSnapshotsEnabledDefault        = true
	CloudGuardSnapshotIntervalDefault        = 22
)

// FalconCloudGuardNodeSpec defines configuration for the node sensor DaemonSet deployed by FalconCloudGuard.
type FalconCloudGuardNodeSpec struct {
	// Specifies tolerations for custom taints. Defaults to allowing scheduling on all nodes.
	// +optional
	// +kubebuilder:default:={{key: "node-role.kubernetes.io/master", operator: "Exists", effect: "NoSchedule"}, {key: "node-role.kubernetes.io/control-plane", operator: "Exists", effect: "NoSchedule"}}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=4
	Tolerations *[]corev1.Toleration `json:"tolerations,omitempty"`

	// Specifies node affinity for scheduling the node sensor DaemonSet. Defaults to allowing scheduling on all nodes.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=5
	NodeAffinity corev1.NodeAffinity `json:"nodeAffinity,omitempty"`

	// Type of DaemonSet update. Can be "RollingUpdate" or "OnDelete". Default is RollingUpdate.
	// +kubebuilder:default={}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="DaemonSet Update Strategy",order=6
	DSUpdateStrategy FalconNodeUpdateStrategy `json:"updateStrategy,omitempty"`

	// Kills pod after the specified amount of time (in seconds). Default is 60 seconds.
	// +kubebuilder:default:=60
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=7
	TerminationGracePeriod int64 `json:"terminationGracePeriod,omitempty"`

	// Add metadata to the node sensor DaemonSet Service Account for IAM roles.
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	ServiceAccount FalconNodeServiceAccount `json:"serviceAccount,omitempty"`

	// Disables the cleanup of the sensor through DaemonSet on the nodes.
	// Disabling might have unintended consequences for certain operations such as sensor downgrading.
	// +kubebuilder:default=false
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=8
	NodeCleanup *bool `json:"disableCleanup,omitempty"`

	// Configure resource requests and limits for the node sensor DaemonSet.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Node Sensor Resources",order=9
	SensorResources Resources `json:"resources,omitempty"`
}

// FalconCloudGuardConfigSpec defines the configurable runtime behaviour of FalconCloudGuard
type FalconCloudGuardConfigSpec struct {
	// Determines if the admission controller webhook is enabled.
	// +kubebuilder:default:=true
	// +optional
	AdmissionControlEnabled *bool `json:"admissionControlEnabled,omitempty"`

	// Determines if Kubernetes resource events are watched for cluster visibility.
	// +kubebuilder:default:=true
	// +optional
	WatchEventsEnabled *bool `json:"watchEventsEnabled,omitempty"`

	// Determines if periodic snapshots of Kubernetes resources are taken.
	// +kubebuilder:default:=true
	// +optional
	SnapshotsEnabled *bool `json:"snapshotsEnabled,omitempty"`

	// Time interval between two snapshots of Kubernetes resources.
	// +kubebuilder:default:="22h"
	// +kubebuilder:validation:Type:=string
	// +kubebuilder:validation:Format:=duration
	// +optional
	SnapshotInterval *metav1.Duration `json:"snapshotInterval,omitempty"`

	// Ignore admission control for a specific set of namespaces.
	// +optional
	DisabledNamespaces []string `json:"disabledNamespaces,omitempty"`
}

func (c *FalconCloudGuardConfigSpec) GetAdmissionControlEnabled() bool {
	if c.AdmissionControlEnabled == nil {
		return CloudGuardAdmissionControlEnabledDefault
	}
	return *c.AdmissionControlEnabled
}

func (c *FalconCloudGuardConfigSpec) GetWatchEventsEnabled() bool {
	if c.WatchEventsEnabled == nil {
		return CloudGuardWatchEventsEnabledDefault
	}
	return *c.WatchEventsEnabled
}

func (c *FalconCloudGuardConfigSpec) GetSnapshotsEnabled() bool {
	if c.SnapshotsEnabled == nil {
		return CloudGuardSnapshotsEnabledDefault
	}
	return *c.SnapshotsEnabled
}

func (c *FalconCloudGuardConfigSpec) GetSnapshotInterval() time.Duration {
	if c.SnapshotInterval == nil {
		return CloudGuardSnapshotIntervalDefault * time.Hour
	}
	return c.SnapshotInterval.Duration
}

// FalconCloudGuardSpec defines the desired state of FalconCloudGuard
type FalconCloudGuardSpec struct {
	// InstallNamespace is the namespace where the Falcon Cloud Guard resources will be deployed
	// +kubebuilder:default:=falcon-sensor
	// +optional
	InstallNamespace string `json:"installNamespace,omitempty"`

	// FalconAPI configures connection from your local Falcon operator to CrowdStrike Falcon platform.
	//
	// When configured, it will pull the sensor from registry.crowdstrike.com and deploy the appropriate sensor to the cluster.
	//
	// If using the API is not desired, the sensor can be manually configured by setting the Image field.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Platform API Configuration",order=1
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

	// CloudGuardConfig configures the runtime behaviour of FalconCloudGuard
	// +optional
	CloudGuardConfig FalconCloudGuardConfigSpec `json:"cloudGuardConfig,omitempty"`

	// NodeSensor configures the node sensor DaemonSet deployed alongside FalconCloudGuard.
	// +optional
	NodeSensor FalconCloudGuardNodeSpec `json:"nodeSensor,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Operator Version",type="string",JSONPath=".status.version",description="Version of the operator"

// FalconCloudGuard is the Schema for the falconcloudguards API
type FalconCloudGuard struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of FalconCloudGuard
	// +required
	Spec FalconCloudGuardSpec `json:"spec"`

	// status defines the observed state of FalconCloudGuard
	// +optional
	Status FalconCRStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FalconCloudGuardList contains a list of FalconCloudGuard
type FalconCloudGuardList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []FalconCloudGuard `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FalconCloudGuard{}, &FalconCloudGuardList{})
}

// FalconCRD interface implementation

// GetFalconSecretSpec returns the FalconSecret configuration
func (f *FalconCloudGuard) GetFalconSecretSpec() FalconSecret {
	return f.Spec.FalconSecret
}

// GetFalconAPISpec returns the FalconAPI configuration
func (f *FalconCloudGuard) GetFalconAPISpec() *FalconAPI {
	return f.Spec.FalconAPI
}

// SetFalconAPISpec sets the FalconAPI configuration
func (f *FalconCloudGuard) SetFalconAPISpec(api *FalconAPI) {
	f.Spec.FalconAPI = api
}

// GetFalconSpec returns an empty FalconSensor (not used by FalconCloudGuard)
func (f *FalconCloudGuard) GetFalconSpec() FalconSensor {
	return FalconSensor{}
}

// SetFalconSpec is a no-op for FalconCloudGuard (FalconSensor not used)
func (f *FalconCloudGuard) SetFalconSpec(sensor FalconSensor) {
	// No-op: FalconCloudGuard doesn't use FalconSensor
}

// GetConditions returns a pointer to the Conditions slice for status updates
func (f *FalconCloudGuard) GetConditions() *[]metav1.Condition {
	return &f.Status.Conditions
}
