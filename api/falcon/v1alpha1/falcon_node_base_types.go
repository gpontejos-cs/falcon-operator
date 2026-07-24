package v1alpha1

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// FalconNodeBaseConfig defines the base configuration aspects for node sensor DaemonSet deployments.
// It is shared between FalconNodeSensor and FalconClusterGuard.
// +k8s:openapi-gen=true
type FalconNodeBaseConfig struct {
	// Specifies tolerations for custom taints. Defaults to allowing scheduling on all nodes.
	// +optional
	// +kubebuilder:default:={{key: "node-role.kubernetes.io/master", operator: "Exists", effect: "NoSchedule"}, {key: "node-role.kubernetes.io/control-plane", operator: "Exists", effect: "NoSchedule"}, {key: "node-role.kubernetes.io/infra", operator: "Exists", effect: "NoSchedule"}}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=4
	Tolerations *[]corev1.Toleration `json:"tolerations"`

	// Specifies node affinity for scheduling the DaemonSet. Defaults to allowing scheduling on all nodes.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=5
	NodeAffinity corev1.NodeAffinity `json:"nodeAffinity,omitempty"`

	// Type of DaemonSet update. Can be "RollingUpdate" or "OnDelete". Default is RollingUpdate.
	// +kubebuilder:default={}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="DaemonSet Update Strategy",order=6
	DSUpdateStrategy FalconNodeUpdateStrategy `json:"updateStrategy,omitempty"`

	// Kills pod after a specificed amount of time (in seconds). Default is 60 seconds.
	// +kubebuilder:default:=60
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=7
	TerminationGracePeriod int64 `json:"terminationGracePeriod,omitempty"`

	// Add metadata to the DaemonSet Service Account for IAM roles.
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	ServiceAccount FalconNodeServiceAccount `json:"serviceAccount,omitempty"`

	// Disables the cleanup of the sensor through DaemonSet on the nodes.
	// Disabling might have unintended consequences for certain operations such as sensor downgrading.
	// +kubebuilder:default=false
	// +operator-sdk:csv:customresourcedefinitions:type=spec,order=8
	NodeCleanup *bool `json:"disableCleanup,omitempty"`

	// Configure resource requests and limits for the DaemonSet Sensor. Only applies when using the eBPF backend.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Falcon eBPF Sensor Resources",order=9
	SensorResources Resources `json:"resources,omitempty"`

	// Sets the backend to be used by the DaemonSet Sensor.
	// +kubebuilder:default=bpf
	// +kubebuilder:validation:Enum=kernel;bpf
	// +operator-sdk-csv:customresourcedefinitions:type=spec,order=10
	Backend string `json:"backend,omitempty"`

	// Enables the use of GKE Autopilot.
	// +kubebuilder:default={}
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="GKE Autopilot Settings",order=11
	GKE AutoPilot `json:"gke,omitempty"`

	// Enable priority class for the DaemonSet. This is useful for GKE Autopilot clusters, but can be set for any cluster.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Priority Class",order=12
	PriorityClass PriorityClassConfig `json:"priorityClass,omitempty"`

	// Version of the sensor to be installed. The latest version will be selected when this version specifier is missing.
	Version *string `json:"version,omitempty"`

	// Advanced configures various options that go against industry practices or are otherwise not recommended for use.
	// Adjusting these settings may result in incorrect or undesirable behavior. Proceed at your own risk.
	// For more information, please see https://github.com/CrowdStrike/falcon-operator/blob/main/docs/ADVANCED.md.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="DaemonSet Advanced Settings"
	Advanced FalconAdvanced `json:"advanced,omitempty"`

	// When running on an unmanaged K8S cluster, set a cluster name. When running on managed, K8S cluster name is resolved cloud-side
	// +kubebuilder:validation:Pattern="^[0-9a-zA-Z]{1}[0-9a-zA-Z_-]{1,99}$"
	ClusterName *string `json:"clusterName,omitempty"`
}

type PriorityClassConfig struct {
	// Enables the operator to deploy a PriorityClass instead of rolling your own. Default is false.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Deploy Priority Class to cluster",order=2
	Deploy *bool `json:"deploy,omitempty"`

	// Name of the priority class to use for the DaemonSet.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Name of the Priority Class to use",order=2
	Name string `json:"name,omitempty"`

	// Value of the priority class to use for the DaemonSet. Requires the Deploy field to be set to true.
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Priority Class Value",order=3
	Value *int32 `json:"value,omitempty"`
}

type Resources struct {
	// Sets the resource limits for the DaemonSet Sensor. Only applies when using the eBPF backend.
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	Limits ResourceList `json:"limits,omitempty"`

	// Sets the resource requests for the DaemonSet Sensor. Only applies when using the eBPF backend.
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	Requests ResourceList `json:"requests,omitempty"`
}

type ResourceList struct {
	// Minimum allowed is 250m.
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	// +kubebuilder:validation:Pattern="^(([0-9]{4,}|[2-9][5-9][0-9])m$)|[0-9]+$"
	CPU string `json:"cpu,omitempty"`

	// Minimum allowed is 500Mi.
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	// +kubebuilder:validation:Pattern="^(([5-9][0-9]{2}[Mi]+)|([0-9.]+[iEGTP]+))|(([5-9][0-9]{8})|([0-9]{10,}))$"
	Memory string `json:"memory,omitempty"`

	// +operator-sdk:csv:customresourcedefinitions:type=spec
	EphemeralStorage string `json:"ephemeral-storage,omitempty"`
}

type AutoPilot struct {
	// Enables the use of GKE Autopilot.
	// +kubebuilder:default=false
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	Enabled *bool `json:"autopilot,omitempty"`

	// Version of the GKE AutoPilot Daemonset for allow list troubleshooting purposes.
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	// +kubebuilder:validation:Pattern="^v[0-9]+\\.[0-9]+\\.[0-9]+$"
	DeployAllowListVersion *string `json:"deployAllowListVersion,omitempty"`

	// Version of the GKE AutoPilot Cleanup Daemonset for allow list troubleshooting purposes
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	// +kubebuilder:validation:Pattern="^v[0-9]+\\.[0-9]+\\.[0-9]+$"
	CleanupAllowListVersion *string `json:"cleanupAllowListVersion,omitempty"`
}

type FalconNodeUpdateStrategy struct {
	// +kubebuilder:default=RollingUpdate
	// +kubebuilder:validation:Enum=RollingUpdate;OnDelete
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	Type          appsv1.DaemonSetUpdateStrategyType `json:"type,omitempty"`
	RollingUpdate appsv1.RollingUpdateDaemonSet      `json:"rollingUpdate,omitempty"`
}

type FalconNodeServiceAccount struct {
	// Define annotations that will be passed down to the Service Account. This is useful for passing along AWS IAM Role or GCP Workload Identity.
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	Annotations map[string]string `json:"annotations,omitempty"`
}
