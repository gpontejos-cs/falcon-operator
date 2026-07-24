package v1alpha1

import (
	"time"

	arv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// FalconAdmissionBaseConfig defines the base configuration for the Falcon Admission Controller.
// It is shared between FalconAdmission and FalconClusterGuard.
type FalconAdmissionBaseConfig struct {
	// Define annotations that will be passed down to admision controller service account. This is useful for passing along AWS IAM Role or GCP Workload Identity.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Service Account Configuration",order=7
	ServiceAccount FalconAdmissionServiceAccount `json:"serviceAccount,omitempty"`

	// Port on which the Falcon Admission Controller service will listen for requests from the cluster.
	// +kubebuilder:default:=443
	// +kubebuilder:validation:XIntOrString
	// +kubebuilder:validation:Minimum:=0
	// +kubebuilder:validation:Maximum:=65535
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller Service Port",order=3,xDescriptors={"urn:alm:descriptor:com.tectonic.ui:number"}
	Port *int32 `json:"servicePort,omitempty"`

	// Port on which the Falcon Admission Controller container will listen for requests.
	// +kubebuilder:default:=4443
	// +kubebuilder:validation:XIntOrString
	// +kubebuilder:validation:Minimum:=0
	// +kubebuilder:validation:Maximum:=65535
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller Container Port",order=4,xDescriptors={"urn:alm:descriptor:com.tectonic.ui:number"}
	ContainerPort *int32 `json:"containerPort,omitempty"`

	// Configure TLS setings for the Falcon Admission Controller
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller TLS Configuration",order=8
	TLS FalconAdmissionTLS `json:"tls,omitempty"`

	// Configure the failure policy for the Falcon Admission Controller.
	// +kubebuilder:default:=Ignore
	// +kubebuilder:validation:Enum=Ignore;Fail
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller Failure Policy",order=6
	FailurePolicy arv1.FailurePolicyType `json:"failurePolicy,omitempty"`

	// Ignore admission control for a specific set of namespaces.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Ignore Namespace List",order=12
	DisabledNamespaces FalconAdmissionNamespace `json:"disabledNamespaces,omitempty"`

	// Determines if with falcon-watcher container is included in the Pod
	// +kubebuilder:default:=true
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Deploy Watcher Container",order=13
	DeployWatcher *bool `json:"deployWatcher,omitempty"`

	// Determines if Kubernetes resources are watched for cluster visibility.
	// +kubebuilder:default:=true
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Enable Resource Watcher",order=14
	WatcherEnabled *bool `json:"watcherEnabled,omitempty"`

	// Determines if snapshots of Kubernetes resources are periodically taken for cluster visibility.
	// +kubebuilder:default:=true
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Enable Resource Snapshots",order=15
	SnapshotsEnabled *bool `json:"snapshotsEnabled,omitempty"`

	// Time interval between two snapshots of Kubernetes resources in the cluster.
	// +kubebuilder:default:="22h"
	// +kubebuilder:validation:Type:=string
	// +kubebuilder:validation:Format:=duration
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Time Interval Between Two Snapshots",order=16
	SnapshotsInterval *metav1.Duration `json:"snapshotsInterval,omitempty"`

	// Determines if the admission controller webhook is enabled
	// +kubebuilder:default:=true
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Enable Admission Controller",order=18
	AdmissionControlEnabled *bool `json:"admissionControlEnabled,omitempty"`

	// Determines if the admission controller watches for configMap events
	// +kubebuilder:default:=true
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Enable ConfigMap Event Watcher",order=17
	ConfigMapWatcherEnabled *bool `json:"configMapWatcherEnabled,omitempty"`

	// Namespace where Falcon Image Analyzer is installed. KAC needs to know this to discover and communicate with IAR.
	// +kubebuilder:default:="falcon-iar"
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Image Analyzer Namespace",order=20
	FalconImageAnalyzerNamespace string `json:"falconImageAnalyzerNamespace,omitempty"`

	// Currently ignored and internally set to 1
	// +kubebuilder:default:=2
	// +kubebuilder:validation:XIntOrString
	// +kubebuilder:validation:Minimum:=0
	// +kubebuilder:validation:Maximum:=65535
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Admission Controller Replica Count",order=5,xDescriptors={"urn:alm:descriptor:com.tectonic.ui:number"}
	Replicas *int32 `json:"replicas,omitempty"`

	// +kubebuilder:default:=Always
	// +kubebuilder:validation:Enum=Always;IfNotPresent;Never
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller Image Pull Policy",order=2,xDescriptors={"urn:alm:descriptor:com.tectonic.ui:imagePullPolicy"}
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// ImagePullSecrets is an optional list of references to secrets to use for pulling image from the image location.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=1,displayName="Falcon Admission Controller Image Pull Secrets",xDescriptors={"urn:alm:descriptor:io.kubernetes:Secret"}
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller Client Resources",order=9,xDescriptors={"urn:alm:descriptor:com.tectonic.ui:resourceRequirements"}
	// +kubebuilder:default:={"limits":{"memory":"384Mi"},"requests":{"cpu":"250m","memory":"384Mi"}}
	ResourcesClient *corev1.ResourceRequirements `json:"resourcesClient,omitempty"`

	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller Client Resources",order=9,xDescriptors={"urn:alm:descriptor:com.tectonic.ui:resourceRequirements"}
	// +kubebuilder:default:={"limits":{"memory":"128Mi"},"requests":{"cpu":"100m","memory":"128Mi"}}
	ResourcesClientNoWebhook *corev1.ResourceRequirements `json:"resourcesClientNoWebhook,omitempty"`

	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller Watcher Resources",order=18,xDescriptors={"urn:alm:descriptor:com.tectonic.ui:resourceRequirements"}
	// +kubebuilder:default:={"limits":{"memory":"384Mi"},"requests":{"cpu":"250m","memory":"384Mi"}}
	ResourcesWatcher *corev1.ResourceRequirements `json:"resourcesWatcher,omitempty"`

	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller Resources",order=10,xDescriptors={"urn:alm:descriptor:com.tectonic.ui:resourceRequirements"}
	//+kubebuilder:default:={"limits":{"memory":"256Mi"},"requests":{"cpu":"100m","memory":"256Mi"}}
	ResourcesAC *corev1.ResourceRequirements `json:"resources,omitempty"`

	// Type of Deployment update. Can be "RollingUpdate" or "OnDelete". Default is RollingUpdate.
	// +kubebuilder:default:={}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Deployment Update Strategy",order=11
	DepUpdateStrategy FalconAdmissionUpdateStrategy `json:"updateStrategy,omitempty"`

	// Specifies node affinity for scheduling the Admission Controller.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=19
	NodeAffinity *corev1.NodeAffinity `json:"nodeAffinity,omitempty"`

	// Specifies tolerations for scheduling the Admission Controller.
	// +kubebuilder:default:={}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=20
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

func (acs *FalconAdmissionBaseConfig) DeployWatcherContainer() bool {
	if acs.DeployWatcher == nil {
		return DeployWatcherDefault
	}

	return *acs.DeployWatcher
}

func (acs *FalconAdmissionBaseConfig) GetWatcherEnabled() bool {
	if acs.DeployWatcher != nil && !*acs.DeployWatcher {
		return false
	}

	if acs.WatcherEnabled == nil {
		return WatcherEnabledDefault
	}

	return *acs.WatcherEnabled
}

func (acs *FalconAdmissionBaseConfig) GetSnapshotsEnabled() bool {
	if acs.DeployWatcher != nil && !*acs.DeployWatcher {
		return false
	}

	if acs.SnapshotsEnabled == nil {
		return SnapshotsEnabledDefault
	}

	return *acs.SnapshotsEnabled
}

func (acs *FalconAdmissionBaseConfig) GetSnapshotsInterval() time.Duration {
	if acs.SnapshotsInterval == nil {
		return SnapshotsIntervalDefault * time.Hour
	}

	return acs.SnapshotsInterval.Duration
}

func (acs *FalconAdmissionBaseConfig) GetConfigMapWatcherEnabled() bool {
	if acs.DeployWatcher != nil && !*acs.DeployWatcher {
		return false
	}

	if acs.ConfigMapWatcherEnabled == nil {
		return ConfigMapWatcherEnabledDefault
	}

	return *acs.ConfigMapWatcherEnabled
}

type FalconAdmissionServiceAccount struct {
	// Define annotations that will be passed down to the Service Account. This is useful for passing along AWS IAM Role or GCP Workload Identity.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Service Account Annotations",order=1
	Annotations map[string]string `json:"annotations,omitempty"`
}

type FalconAdmissionUpdateStrategy struct {
	// RollingUpdate is used to specify the strategy used to roll out a deployment
	// +kubebuilder:default:={}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller deployment update configuration",order=1,xDescriptors={"urn:alm:descriptor:com.tectonic.ui:updateStrategy"}
	RollingUpdate FalconAdmissionRollingUpdate `json:"rollingUpdate,omitempty"`
}

type FalconAdmissionRollingUpdate struct {
	// The maximum number of pods that can be unavailable during the update.
	// Value can be an absolute number (ex: 5) or a percentage of desired pods (ex: 10%).
	// +kubebuilder:default:=0
	// +optional
	MaxUnavailable *intstr.IntOrString `json:"maxUnavailable,omitempty"`

	// The maximum number of pods that can be scheduled above the desired number of pods.
	// Value can be an absolute number (ex: 5) or a percentage of desired pods (ex: 10%).
	// +kubebuilder:default:=1
	// +optional
	MaxSurge *intstr.IntOrString `json:"maxSurge,omitempty"`
}

type FalconAdmissionTLS struct {
	// Validity of the TLS certificate in days. Default is 3650 days.
	// +kubebuilder:validation:XIntOrString
	// +kubebuilder:validation:Pattern="^[0-9]{1-4}$"
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon Admission Controller TLS Validity Length (days)",order=1,xDescriptors={"urn:alm:descriptor:com.tectonic.ui:number"}
	Validity *int `json:"validity,omitempty"`
}

type FalconAdmissionNamespace struct {
	// Configure a list of namespaces to ignore admission control.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Ignore Namespace List",order=1
	Namespaces []string `json:"namespaces,omitempty"`
}
