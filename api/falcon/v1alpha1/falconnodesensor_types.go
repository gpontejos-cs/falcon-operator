package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// FalconNodeSensorSpec defines the desired state of FalconNodeSensor
// +k8s:openapi-gen=true
type FalconNodeSensorSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Namespace where the Falcon Sensor should be installed.
	// For best security practices, this should be a dedicated namespace that is not used for any other purpose.
	// It also should not be the same namespace where the Falcon Operator, or other Falcon resources are deployed.
	// +kubebuilder:default:=falcon-system
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=1,xDescriptors={"urn:alm:descriptor:io.kubernetes:Namespace"}
	InstallNamespace string `json:"installNamespace,omitempty"`

	// Various configuration for DaemonSet Deployment
	// +kubebuilder:default:={}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="DaemonSet Configuration",order=3
	Node FalconNodeConfig `json:"node,omitempty"`

	// +kubebuilder:default:={}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Sensor Configuration",order=2
	Falcon FalconUnified `json:"falcon,omitempty"`

	// FalconAPI configures connection from your local Falcon operator to CrowdStrike Falcon platform.
	//
	// When configured, it will pull the sensor from registry.crowdstrike.com and deploy the appropriate sensor to the cluster.
	//
	// If using the API is not desired, the sensor can be manually configured.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Platform API Configuration",order=1
	FalconAPI *FalconAPI `json:"falcon_api,omitempty"`

	// FalconSecret config is used to inject k8s secrets with sensitive data for the FalconSensor and the FalconAPI.
	// The following Falcon values are supported by k8s secret injection:
	//   falcon-cid
	//   falcon-provisioning-token
	//   falcon-client-id
	//   falcon-client-secret
	// +kubebuilder:default={"enabled": false}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Platform Secrets Configuration",order=5
	FalconSecret FalconSecret `json:"falconSecret,omitempty"`

	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Configurations used for internal testing",order=6
	Internal FalconInternal `json:"internal,omitempty"`
}

// FalconNodeConfig defines aspects about how the FalconNodeSensor DaemonSet works.
// +k8s:openapi-gen=true
type FalconNodeConfig struct {
	FalconNodeBaseConfig `json:",inline"`

	// +kubebuilder:default=Always
	// +kubebuilder:validation:Enum=Always;IfNotPresent;Never
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=3
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// Location of the Falcon Sensor image. Use only in cases when you mirror the original image to your repository/name:tag
	// +kubebuilder:validation:Pattern="^.*:.*$"
	// +operator-sdk:csv:custoomitemresourcedefinitions:type=spec,order=2
	Image string `json:"image,omitempty"`

	// ImagePullSecrets is an optional list of references to secrets in the falcon-system namespace to use for pulling image from image_override location.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=1
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
}

// FalconNodeSensorStatus defines the observed state of FalconNodeSensor
// +k8s:openapi-gen=true
type FalconNodeSensorStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// Phase or the status of the deployment

	// Version of the CrowdStrike Falcon Sensor
	Sensor *string `json:"sensor,omitempty"`

	// Version of the CrowdStrike Falcon Operator
	Version string `json:"version,omitempty"`

	// Conditions represent the latest available observations of an object's state
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster
//+kubebuilder:printcolumn:name="Operator Version",type="string",JSONPath=".status.version",description="Version of the Operator"
//+kubebuilder:printcolumn:name="Falcon Sensor",type="string",JSONPath=".status.sensor",description="Version of the Falcon Sensor"

// FalconNodeSensor is the Schema for the falconnodesensors API
// +k8s:openapi-gen=true
type FalconNodeSensor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FalconNodeSensorSpec   `json:"spec,omitempty"`
	Status            FalconNodeSensorStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// FalconNodeSensorList contains a list of FalconNodeSensor
type FalconNodeSensorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FalconNodeSensor `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FalconNodeSensor{}, &FalconNodeSensorList{})
}

func (node *FalconNodeSensor) GetTolerations() *[]corev1.Toleration {
	if node.Spec.Node.Tolerations == nil {
		return &[]corev1.Toleration{}
	}
	return node.Spec.Node.Tolerations
}

func (node *FalconNodeSensor) GetFalconSecretSpec() FalconSecret {
	return node.Spec.FalconSecret
}

func (node *FalconNodeSensor) GetFalconAPISpec() *FalconAPI {
	return node.Spec.FalconAPI
}

func (node *FalconNodeSensor) SetFalconAPISpec(falconApiSpec *FalconAPI) {
	node.Spec.FalconAPI = falconApiSpec
}

func (node *FalconNodeSensor) GetFalconSpec() FalconSensor {
	return node.Spec.Falcon.FalconSensor
}

func (node *FalconNodeSensor) SetFalconSpec(falconSpec FalconSensor) {
	node.Spec.Falcon.FalconSensor = falconSpec
}
