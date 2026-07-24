package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	DeployWatcherDefault           = true
	SnapshotsEnabledDefault        = true
	SnapshotsIntervalDefault       = 22
	WatcherEnabledDefault          = true
	AdmissionControlEnabledDefault = true
	ConfigMapWatcherEnabledDefault = true
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// FalconAdmissionSpec defines the desired state of FalconAdmission
type FalconAdmissionSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Namespace where the Falcon Admission Controller should be installed.
	// For best security practices, this should be a dedicated namespace that is not used for any other purpose.
	// It also should not be the same namespace where the Falcon Operator or the Falcon Sensor is installed.
	// +kubebuilder:default:=falcon-kac
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=1,xDescriptors={"urn:alm:descriptor:io.kubernetes:Namespace"}
	InstallNamespace string `json:"installNamespace,omitempty"`

	// CrowdStrike Falcon sensor configuration
	// +kubebuilder:default:={}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Sensor Configuration",order=3
	Falcon FalconSensor `json:"falcon,omitempty"`

	// FalconAPI configures connection from your local Falcon operator to CrowdStrike Falcon platform.
	//
	// When configured, it will pull the sensor from registry.crowdstrike.com and deploy the appropriate sensor to the cluster.
	//
	// If using the API is not desired, the sensor can be manually configured by setting the Image and Version fields.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Platform API Configuration",order=2
	FalconAPI *FalconAPI `json:"falcon_api,omitempty"`

	// FalconSecret config is used to inject k8s secrets with sensitive data for the FalconSensor and the FalconAPI.
	// The following Falcon values are supported by k8s secret injection:
	//   falcon-cid
	//   falcon-provisioning-token
	//   falcon-client-id
	//   falcon-client-secret
	// +kubebuilder:default={"enabled": false}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Platform Secrets Configuration",order=7
	FalconSecret FalconSecret `json:"falconSecret,omitempty"`

	// ResourceQuota configures the ResourceQuota for the Falcon Admission Controller. This is useful for limiting the number of pods that can be created in the namespace.
	// +kubebuilder:default:={}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller Resource Quota",order=4
	ResQuota FalconAdmissionRQSpec `json:"resourcequota,omitempty"`

	// Registry configures container image registry to which the Admission Controller image will be pushed.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller Registry Configuration",order=6
	Registry RegistrySpec `json:"registry,omitempty"`

	// Additional configuration for Falcon Admission Controller deployment.
	// +kubebuilder:default:={}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller Configuration",order=5
	AdmissionConfig FalconAdmissionBaseConfig `json:"admissionConfig,omitempty"`

	// Location of the Falcon Sensor image. Use only in cases when you mirror the original image to your repository/name:tag, and CrowdStrike OAuth2 API is not used.
	// +kubebuilder:validation:Pattern="^.*:.*$"
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller Image URI",order=8
	Image string `json:"image,omitempty"`

	// Falcon Admission Controller Version. The latest version will be selected when version specifier is missing. Example: 6.31, 6.31.0, 6.31.0-1409, etc.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller Version",order=9
	Version *string `json:"version,omitempty"`

	// Deprecated: Use AdmissionConfig.ClusterName instead. This field will be removed in a future release.
	// Cluster Name if Falcon KAC cannot discover the cluster name. This will be overwritten if Falcon KAC is able to discover the cluster name.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Cluster Name",order=10
	ClusterName *string `json:"clusterName,omitempty"`
}

type FalconAdmissionRQSpec struct {
	// Limits the number of admission controller pods that can be created in the namespace.
	// +kubebuilder:default:="2"
	// +kubebuilder:validation:String
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Resource Quota Pod Limit",order=1,xDescriptors={"urn:alm:descriptor:com.tectonic.ui:podCount"}
	PodLimit string `json:"pods,omitempty"`
}

// FalconAdmissionStatus defines the observed state of FalconAdmission
type FalconAdmissionStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Version of the CrowdStrike Falcon Sensor
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Falcon Sensor Version",xDescriptors={"urn:alm:descriptor:text"}
	Sensor *string `json:"sensor,omitempty"`

	// Version of the CrowdStrike Falcon Operator
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Falcon Operator Version",xDescriptors={"urn:alm:descriptor:text"}
	Version string `json:"version,omitempty"`

	// +optional
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Falcon Admission Conditions",xDescriptors={"urn:alm:descriptor:io.kubernetes.conditions"}
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster
//+kubebuilder:printcolumn:name="Operator Version",type="string",JSONPath=".status.version",description="Version of the Operator"
//+kubebuilder:printcolumn:name="Falcon Sensor",type="string",JSONPath=".status.sensor",description="Version of the Falcon Admission Controller"

// FalconAdmission is the Schema for the falconadmissions API
type FalconAdmission struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FalconAdmissionSpec `json:"spec,omitempty"`
	Status FalconCRStatus      `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// FalconAdmissionList contains a list of FalconAdmission
type FalconAdmissionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FalconAdmission `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FalconAdmission{}, &FalconAdmissionList{})
}

func (ac *FalconAdmission) GetAdmissionControlEnabled() bool {
	if ac.Spec.AdmissionConfig.AdmissionControlEnabled == nil {
		return AdmissionControlEnabledDefault
	}

	return *ac.Spec.AdmissionConfig.AdmissionControlEnabled
}

func (ac *FalconAdmission) GetFalconSecretSpec() FalconSecret {
	return ac.Spec.FalconSecret
}

func (ac *FalconAdmission) GetFalconAPISpec() *FalconAPI {
	return ac.Spec.FalconAPI
}

func (ac *FalconAdmission) SetFalconAPISpec(falconApiSpec *FalconAPI) {
	ac.Spec.FalconAPI = falconApiSpec
}

func (ac *FalconAdmission) GetFalconSpec() FalconSensor {
	return ac.Spec.Falcon
}

func (ac *FalconAdmission) SetFalconSpec(falconSpec FalconSensor) {
	ac.Spec.Falcon = falconSpec
}

// GetClusterName returns the cluster name from the deprecated top-level Spec.ClusterName field.
func (ac *FalconAdmission) GetClusterName() *string {
	return ac.Spec.ClusterName
}
