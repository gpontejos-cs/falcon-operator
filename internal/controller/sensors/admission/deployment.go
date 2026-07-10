package admission

import (
	"fmt"

	"github.com/crowdstrike/falcon-operator/pkg/common"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// ClusterGuardDeployment builds the Deployment for FalconClusterGuard with 3 containers:
// falcon-ac (admission controller), falcon-client (webhook), and falcon-watcher (event watcher + gRPC API).
func ClusterGuardDeployment(name, namespace, imageUri string, imagePullPolicy corev1.PullPolicy, imagePullSecrets []corev1.LocalObjectReference) *appsv1.Deployment {
	runNonRoot := true
	readOnlyRootFilesystem := true
	allowPrivilegeEscalation := false
	shareProcessNamespace := true
	sizeLimitTmp := resource.MustParse("256Mi")
	sizeLimitPrivate := resource.MustParse("4Ki")
	sizeLimitWatcher := resource.MustParse("64Mi")
	terminationGracePeriod := int64(60)
	singleReplica := int32(1)
	maxUnavailable := intstr.FromInt(0)
	maxSurge := intstr.FromInt(1)

	labels := map[string]string{
		"app": name,
	}

	apiServiceName := fmt.Sprintf("%s.%s.svc", common.ClusterGuardAPIServiceName, namespace)

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: appsv1.SchemeGroupVersion.String(),
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &singleReplica,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &maxUnavailable,
					MaxSurge:       &maxSurge,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					Annotations: map[string]string{
						common.FalconContainerInjection: "disabled",
					},
				},
				Spec: corev1.PodSpec{
					ShareProcessNamespace:         &shareProcessNamespace,
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					ServiceAccountName:            common.ClusterGuardServiceAccountName,
					PriorityClassName:             common.FalconPriorityClassName,
					ImagePullSecrets:              imagePullSecrets,
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "crowdstrike-falcon-vol0",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									SizeLimit: &sizeLimitTmp,
								},
							},
						},
						{
							Name: "crowdstrike-falcon-vol1",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									SizeLimit: &sizeLimitPrivate,
								},
							},
						},
						{
							Name: "crowdstrike-falcon-vol2",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									SizeLimit: &sizeLimitWatcher,
								},
							},
						},
						{
							Name: name + "-tls-certs",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: common.ClusterGuardTLSSecretName,
								},
							},
						},
						{
							Name: "api-tls-certs",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: common.ClusterGuardAPITLSSecretName,
								},
							},
						},
						{
							Name: "api-ca-cert",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: common.ClusterGuardAPICASecretName,
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:            "falcon-ac",
							Image:           imageUri,
							ImagePullPolicy: imagePullPolicy,
							SecurityContext: &corev1.SecurityContext{
								ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
								AllowPrivilegeEscalation: &allowPrivilegeEscalation,
								RunAsNonRoot:             &runNonRoot,
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("300m"),
									corev1.ResourceMemory: resource.MustParse("512Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("512Mi"),
								},
							},
							EnvFrom: []corev1.EnvFromSource{
								{
									ConfigMapRef: &corev1.ConfigMapEnvSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: common.ClusterGuardConfigMapName,
										},
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "crowdstrike-falcon-vol0", MountPath: "/tmp"},
								{Name: "crowdstrike-falcon-vol1", MountPath: "/var/private"},
								{Name: "crowdstrike-falcon-vol2", MountPath: "/var/falcon-watcher"},
							},
							StartupProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   common.FalconAdmissionStartupProbePath,
										Port:   intstr.FromInt32(common.ClusterGuardWebhookPort),
										Scheme: corev1.URISchemeHTTPS,
									},
								},
								PeriodSeconds:    2,
								FailureThreshold: 30,
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   common.FalconAdmissionLivenessProbePath,
										Port:   intstr.FromInt32(common.ClusterGuardWebhookPort),
										Scheme: corev1.URISchemeHTTPS,
									},
								},
								PeriodSeconds: 10,
							},
						},
						{
							Name:            "falcon-client",
							Image:           imageUri,
							ImagePullPolicy: imagePullPolicy,
							Args:            []string{"client"},
							SecurityContext: &corev1.SecurityContext{
								ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
								AllowPrivilegeEscalation: &allowPrivilegeEscalation,
								RunAsNonRoot:             &runNonRoot,
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("500m"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
							},
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: common.ClusterGuardWebhookPort,
									Name:          "webhook-port",
									Protocol:      corev1.ProtocolTCP,
								},
							},
							Env: []corev1.EnvVar{
								{
									Name: "__CS_POD_NAMESPACE",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.namespace"},
									},
								},
								{
									Name: "__CS_POD_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.name"},
									},
								},
								{
									Name: "__CS_POD_NODENAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "spec.nodeName"},
									},
								},
							},
							EnvFrom: []corev1.EnvFromSource{
								{
									ConfigMapRef: &corev1.ConfigMapEnvSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: common.ClusterGuardConfigMapName,
										},
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "crowdstrike-falcon-vol0", MountPath: "/tmp"},
								{Name: "crowdstrike-falcon-vol1", MountPath: "/var/private"},
								{Name: name + "-tls-certs", MountPath: "/run/secrets/tls", ReadOnly: true},
							},
							StartupProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   common.FalconAdmissionClientStartupProbePath,
										Port:   intstr.FromInt32(common.ClusterGuardWebhookPort),
										Scheme: corev1.URISchemeHTTPS,
									},
								},
								PeriodSeconds:    2,
								FailureThreshold: 30,
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   common.FalconAdmissionClientLivenessProbePath,
										Port:   intstr.FromInt32(common.ClusterGuardWebhookPort),
										Scheme: corev1.URISchemeHTTPS,
									},
								},
								PeriodSeconds: 10,
							},
						},
						{
							Name:            "falcon-watcher",
							Image:           imageUri,
							ImagePullPolicy: imagePullPolicy,
							Args:            []string{"client", "-app=watcher"},
							SecurityContext: &corev1.SecurityContext{
								ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
								AllowPrivilegeEscalation: &allowPrivilegeEscalation,
								RunAsNonRoot:             &runNonRoot,
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("500m"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("750m"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
							},
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: common.ClusterGuardWatcherHTTPPort,
									Name:          "watcher-health",
									Protocol:      corev1.ProtocolTCP,
								},
								{
									ContainerPort: common.ClusterGuardGRPCPort,
									Name:          "grpc-port",
									Protocol:      corev1.ProtocolTCP,
								},
							},
							Env: []corev1.EnvVar{
								{
									Name: "__CS_POD_NAMESPACE",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.namespace"},
									},
								},
								{
									Name: "__CS_POD_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.name"},
									},
								},
								{
									Name: "__CS_POD_NODENAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "spec.nodeName"},
									},
								},
								{Name: "API_SERVICE_NAME", Value: apiServiceName},
							},
							EnvFrom: []corev1.EnvFromSource{
								{
									ConfigMapRef: &corev1.ConfigMapEnvSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: common.ClusterGuardConfigMapName,
										},
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "crowdstrike-falcon-vol0", MountPath: "/tmp"},
								{Name: "crowdstrike-falcon-vol1", MountPath: "/var/private"},
								{Name: "crowdstrike-falcon-vol2", MountPath: "/var/falcon-watcher"},
								{Name: "api-tls-certs", MountPath: "/run/secrets/tls", ReadOnly: true},
								{Name: "api-ca-cert", MountPath: "/run/secrets/ca", ReadOnly: true},
							},
							StartupProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   common.FalconAdmissionClientStartupProbePath,
										Port:   intstr.FromInt32(common.ClusterGuardWatcherHTTPPort),
										Scheme: corev1.URISchemeHTTP,
									},
								},
								PeriodSeconds:    2,
								FailureThreshold: 30,
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   common.FalconAdmissionClientLivenessProbePath,
										Port:   intstr.FromInt32(common.ClusterGuardWatcherHTTPPort),
										Scheme: corev1.URISchemeHTTP,
									},
								},
								PeriodSeconds: 10,
							},
						},
					},
				},
			},
		},
	}
}
