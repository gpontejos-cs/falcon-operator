package node_sensor

import (
	"github.com/crowdstrike/falcon-operator/pkg/common"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
)

// DaemonSet builds the DaemonSet for the FalconClusterGuard node sensor.
func (n *NodeSensor) DaemonSet() *appsv1.DaemonSet {
	return n.daemonSet()
}

// CleanupDaemonSet builds the cleanup DaemonSet that removes
// /opt/CrowdStrike from each node during FalconClusterGuard finalization.
func (n *NodeSensor) CleanupDaemonSet() *appsv1.DaemonSet {
	return n.cleanupDaemonSet()
}

// daemonSet builds the DaemonSet for the FalconClusterGuard node sensor.
func (n *NodeSensor) daemonSet() *appsv1.DaemonSet {
	namespace := n.cfg.InstallNamespace
	nodeSpec := n.cfg.NodeSensor

	dsLabels := common.CRLabels("daemonset", common.ClusterGuardSensorDaemonSetName, common.ClusterGuardComponentName)
	privileged := true
	runAsUser := int64(0)
	hostPathType := corev1.HostPathFile

	imageUri := n.cfg.Image
	if imageUri == "" && n.cfg.FalconAPI != nil && n.cfg.FalconAPI.CID != nil {
		imageUri = *n.cfg.FalconAPI.CID
	}

	imagePullPolicy := n.cfg.ImagePullPolicy
	if imagePullPolicy == "" {
		imagePullPolicy = corev1.PullIfNotPresent
	}

	terminationGracePeriod := nodeSpec.TerminationGracePeriod
	if terminationGracePeriod == 0 {
		terminationGracePeriod = 60
	}

	tolerations := []corev1.Toleration{
		{Key: "node-role.kubernetes.io/master", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
		{Key: "node-role.kubernetes.io/control-plane", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
		{Key: "kubernetes.azure.com/scalesetpriority", Operator: corev1.TolerationOpEqual, Value: "spot", Effect: corev1.TaintEffectNoSchedule},
	}
	if nodeSpec.Tolerations != nil {
		tolerations = *nodeSpec.Tolerations
	}

	updateStrategy := appsv1.DaemonSetUpdateStrategy{Type: appsv1.RollingUpdateDaemonSetStrategyType}
	if nodeSpec.DSUpdateStrategy.Type != "" {
		updateStrategy.Type = nodeSpec.DSUpdateStrategy.Type
		ru := nodeSpec.DSUpdateStrategy.RollingUpdate
		updateStrategy.RollingUpdate = &ru
	}

	containerResources := corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("300m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}
	if nodeSpec.SensorResources.Limits.Memory != "" || nodeSpec.SensorResources.Requests.CPU != "" {
		containerResources = BuildResourceRequirements(nodeSpec.SensorResources)
	}

	initArgs := []string{
		"-c",
		`set -e;
if [ ! -f /opt/CrowdStrike/falcon-daemonset-init ]; then
echo "Error: This is not a falcon node sensor(DaemonSet) image";
exit 1;
fi;
echo "Running /opt/CrowdStrike/falcon-daemonset-init -i";
/opt/CrowdStrike/falcon-daemonset-init -i;
if [ ! -f /opt/CrowdStrike/configure-cluster-id ]; then
echo "/opt/CrowdStrike/configure-cluster-id not found. Skipping.";
else
echo "Running /opt/CrowdStrike/configure-cluster-id";
/opt/CrowdStrike/configure-cluster-id;
fi`,
	}

	apiServiceName := common.ClusterGuardAPIServiceName + "." + namespace + ".svc"

	podSpec := corev1.PodSpec{
		ServiceAccountName:            common.ClusterGuardSensorServiceAccountName,
		TerminationGracePeriodSeconds: &terminationGracePeriod,
		HostNetwork:                   true,
		DNSPolicy:                     corev1.DNSClusterFirstWithHostNet,
		HostPID:                       true,
		HostIPC:                       true,
		ImagePullSecrets:              n.cfg.ImagePullSecrets,
		NodeSelector: map[string]string{
			"kubernetes.io/os": "linux",
		},
		SecurityContext: &corev1.PodSecurityContext{
			FSGroup: func() *int64 { g := int64(65534); return &g }(),
		},
		Tolerations: tolerations,
		InitContainers: []corev1.Container{
			{
				Name:            "init-falconstore",
				Image:           imageUri,
				ImagePullPolicy: imagePullPolicy,
				Command:         []string{"/bin/bash"},
				Args:            initArgs,
				SecurityContext: &corev1.SecurityContext{
					RunAsUser:                &runAsUser,
					Privileged:               &privileged,
					AllowPrivilegeEscalation: &privileged,
					ReadOnlyRootFilesystem:   func() *bool { b := false; return &b }(),
				},
				Env: []corev1.EnvVar{
					{Name: "POD_NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
					{Name: "API_SERVICE_NAME", Value: apiServiceName},
				},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "falcon-sensor-tls-certs", MountPath: "/run/secrets/tls", ReadOnly: true},
					{Name: "falcon-api-ca", MountPath: "/run/secrets/ca", ReadOnly: true},
				},
			},
		},
		Containers: []corev1.Container{
			{
				Name:            "falcon-node-sensor",
				Image:           imageUri,
				ImagePullPolicy: imagePullPolicy,
				SecurityContext: &corev1.SecurityContext{
					RunAsUser:                &runAsUser,
					Privileged:               &privileged,
					ReadOnlyRootFilesystem:   func() *bool { b := false; return &b }(),
					AllowPrivilegeEscalation: &privileged,
				},
				Resources: containerResources,
				Env: []corev1.EnvVar{
					{Name: "POD_NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
					{Name: "API_SERVICE_NAME", Value: apiServiceName},
				},
				EnvFrom: []corev1.EnvFromSource{
					{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: common.ClusterGuardSensorConfigMapName}}},
				},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "falconstore", MountPath: "/opt/CrowdStrike/falconstore"},
					{Name: "falcon-sensor-tls-certs", MountPath: "/run/secrets/tls", ReadOnly: true},
					{Name: "falcon-api-ca", MountPath: "/run/secrets/ca", ReadOnly: true},
				},
			},
		},
		Volumes: []corev1.Volume{
			{Name: "falconstore", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/CrowdStrike/falconstore", Type: &hostPathType}}},
			{Name: "falcon-sensor-tls-certs", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: common.ClusterGuardSensorTLSSecretName}}},
			{Name: "falcon-api-ca", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: common.ClusterGuardAPICASecretName}}},
		},
	}

	if nodeSpec.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil ||
		len(nodeSpec.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution) > 0 {
		podSpec.Affinity = &corev1.Affinity{NodeAffinity: &nodeSpec.NodeAffinity}
	}

	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: appsv1.SchemeGroupVersion.String(),
			Kind:       "DaemonSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.ClusterGuardSensorDaemonSetName,
			Namespace: namespace,
			Labels:    dsLabels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": common.ClusterGuardSensorDaemonSetName}},
			UpdateStrategy: updateStrategy,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      map[string]string{"app": common.ClusterGuardSensorDaemonSetName},
					Annotations: map[string]string{common.FalconContainerInjection: "disabled"},
				},
				Spec: podSpec,
			},
		},
	}
}

// cleanupDaemonSet builds the cleanup DaemonSet that removes
// /opt/CrowdStrike from each node during FalconClusterGuard finalization.
func (n *NodeSensor) cleanupDaemonSet() *appsv1.DaemonSet {
	namespace := n.cfg.InstallNamespace
	imageUri := n.cfg.Image
	imagePullPolicy := n.cfg.ImagePullPolicy
	imagePullSecrets := n.cfg.ImagePullSecrets

	dsLabels := common.CRLabels("daemonset", common.ClusterGuardSensorCleanupDaemonSetName, common.ClusterGuardComponentName)

	if imagePullPolicy == "" {
		imagePullPolicy = corev1.PullIfNotPresent
	}
	privileged := true
	runAsUser := int64(0)
	terminationGracePeriod := int64(60)
	readOnlyRootFilesystem := true
	allowPrivilegeEscalation := true
	disallowPrivilegeEscalation := false

	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: appsv1.SchemeGroupVersion.String(),
			Kind:       "DaemonSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.ClusterGuardSensorCleanupDaemonSetName,
			Namespace: namespace,
			Labels:    dsLabels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": common.ClusterGuardSensorCleanupDaemonSetName},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": common.ClusterGuardSensorCleanupDaemonSetName},
					Annotations: map[string]string{
						common.FalconContainerInjection: "disabled",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName:            common.ClusterGuardSensorCleanupServiceAccountName,
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostPID:                       true,
					ImagePullSecrets:              imagePullSecrets,
					NodeSelector: map[string]string{
						"kubernetes.io/os": "linux",
					},
					InitContainers: []corev1.Container{
						{
							Name:            "cleanup-opt-crowdstrike",
							Image:           imageUri,
							ImagePullPolicy: imagePullPolicy,
							Command:         []string{"/bin/bash"},
							Args: []string{
								"-c",
								`echo "Running /opt/CrowdStrike/falcon-daemonset-init -u"; /opt/CrowdStrike/falcon-daemonset-init -u`,
							},
							SecurityContext: &corev1.SecurityContext{
								RunAsUser:                &runAsUser,
								Privileged:               &privileged,
								AllowPrivilegeEscalation: &allowPrivilegeEscalation,
								ReadOnlyRootFilesystem:   func() *bool { b := false; return &b }(),
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:            "cleanup-sleep",
							Image:           imageUri,
							ImagePullPolicy: imagePullPolicy,
							Command:         []string{"/bin/bash"},
							Args:            []string{"-c", "sleep infinity"},
							SecurityContext: &corev1.SecurityContext{
								Privileged:               &disallowPrivilegeEscalation,
								ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
								AllowPrivilegeEscalation: &allowPrivilegeEscalation,
							},
						},
					},
				},
			},
		},
	}
}

// BuildResourceRequirements converts a falconv1alpha1.Resources spec into corev1.ResourceRequirements.
func BuildResourceRequirements(res falconv1alpha1.Resources) corev1.ResourceRequirements {
	reqs := corev1.ResourceRequirements{
		Limits:   corev1.ResourceList{},
		Requests: corev1.ResourceList{},
	}
	if res.Limits.Memory != "" {
		reqs.Limits[corev1.ResourceMemory] = resource.MustParse(res.Limits.Memory)
	}
	if res.Limits.CPU != "" {
		reqs.Limits[corev1.ResourceCPU] = resource.MustParse(res.Limits.CPU)
	}
	if res.Requests.Memory != "" {
		reqs.Requests[corev1.ResourceMemory] = resource.MustParse(res.Requests.Memory)
	}
	if res.Requests.CPU != "" {
		reqs.Requests[corev1.ResourceCPU] = resource.MustParse(res.Requests.CPU)
	}
	return reqs
}
