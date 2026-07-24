package admission

import (
	"context"
	"fmt"
	"reflect"
	"strconv"

	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	pkgcommon "github.com/crowdstrike/falcon-operator/pkg/common"
	"github.com/operator-framework/operator-lib/proxy"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/util/retry"
)

// Deployment builds the Deployment for FalconClusterGuard with 3 containers:
// falcon-ac (admission controller), falcon-client (webhook), and falcon-watcher (event watcher + gRPC API).
func (a *Admission) Deployment() *appsv1.Deployment {
	name := a.prefix()
	namespace := a.cfg.InstallNamespace
	imageUri := a.cfg.Image
	imagePullPolicy := a.cfg.ImagePullPolicy
	imagePullSecrets := a.cfg.ImagePullSecrets
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

	apiServiceName := fmt.Sprintf("%s.%s.svc", pkgcommon.AdmissionAPIServiceName, namespace)

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
						pkgcommon.FalconContainerInjection: "disabled",
					},
				},
				Spec: corev1.PodSpec{
					ShareProcessNamespace:         &shareProcessNamespace,
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					ServiceAccountName:            a.prefix() + "-sa",
					PriorityClassName:             pkgcommon.FalconPriorityClassName,
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
									SecretName: a.prefix() + "-tls",
								},
							},
						},
						{
							Name: "api-tls-certs",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: pkgcommon.AdmissionAPITLSSecretName,
								},
							},
						},
						{
							Name: "api-ca-cert",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: pkgcommon.AdmissionAPICASecretName,
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
											Name: a.prefix() + "-config",
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
										Path:   pkgcommon.FalconAdmissionStartupProbePath,
										Port:   intstr.FromInt32(pkgcommon.AdmissionWebhookPort),
										Scheme: corev1.URISchemeHTTPS,
									},
								},
								PeriodSeconds:    2,
								FailureThreshold: 30,
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   pkgcommon.FalconAdmissionLivenessProbePath,
										Port:   intstr.FromInt32(pkgcommon.AdmissionWebhookPort),
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
									ContainerPort: pkgcommon.AdmissionWebhookPort,
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
											Name: a.prefix() + "-config",
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
										Path:   pkgcommon.FalconAdmissionClientStartupProbePath,
										Port:   intstr.FromInt32(pkgcommon.AdmissionWebhookPort),
										Scheme: corev1.URISchemeHTTPS,
									},
								},
								PeriodSeconds:    2,
								FailureThreshold: 30,
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   pkgcommon.FalconAdmissionClientLivenessProbePath,
										Port:   intstr.FromInt32(pkgcommon.AdmissionWebhookPort),
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
									ContainerPort: pkgcommon.AdmissionWatcherHTTPPort,
									Name:          "watcher-health",
									Protocol:      corev1.ProtocolTCP,
								},
								{
									ContainerPort: pkgcommon.AdmissionGRPCPort,
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
											Name: a.prefix() + "-config",
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
										Path:   pkgcommon.FalconAdmissionClientStartupProbePath,
										Port:   intstr.FromInt32(pkgcommon.AdmissionWatcherHTTPPort),
										Scheme: corev1.URISchemeHTTP,
									},
								},
								PeriodSeconds:    2,
								FailureThreshold: 30,
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   pkgcommon.FalconAdmissionClientLivenessProbePath,
										Port:   intstr.FromInt32(pkgcommon.AdmissionWatcherHTTPPort),
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

func (a *Admission) reconcileDeployment(ctx context.Context) error {
	dep := a.Deployment()

	// Inject operator proxy env vars into the desired spec containers before create/update.
	if len(proxy.ReadProxyVarsFromEnv()) > 0 {
		for i, container := range dep.Spec.Template.Spec.Containers {
			dep.Spec.Template.Spec.Containers[i].Env = append(container.Env, proxy.ReadProxyVarsFromEnv()...)
		}
	}

	existing := &appsv1.Deployment{}
	found, err := k8sutils.GetOrCreate(ctx, a.r, a.cfg.Request, a.cfg.Owner, a.cfg.Status, dep, existing,
		types.NamespacedName{Name: a.prefix(), Namespace: a.cfg.InstallNamespace},
		"Failed to get FalconClusterGuard Deployment")
	if !found || err != nil {
		return err
	}

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(),
			types.NamespacedName{Name: a.prefix(), Namespace: a.cfg.InstallNamespace},
			existing); err != nil {
			return err
		}

		updated := false

		if !reflect.DeepEqual(dep.Spec.Template.Spec.ImagePullSecrets, existing.Spec.Template.Spec.ImagePullSecrets) {
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: ImagePullSecrets changed",
				"old", existing.Spec.Template.Spec.ImagePullSecrets,
				"new", dep.Spec.Template.Spec.ImagePullSecrets)
			existing.Spec.Template.Spec.ImagePullSecrets = dep.Spec.Template.Spec.ImagePullSecrets
			updated = true
		}

		if !equality.Semantic.DeepEqual(existing.Spec.Strategy.RollingUpdate, dep.Spec.Strategy.RollingUpdate) {
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: RollingUpdate strategy changed",
				"old", existing.Spec.Strategy.RollingUpdate,
				"new", dep.Spec.Strategy.RollingUpdate)
			existing.Spec.Strategy.RollingUpdate = dep.Spec.Strategy.RollingUpdate
			updated = true
		}

		if !reflect.DeepEqual(dep.Spec.Replicas, existing.Spec.Replicas) {
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: Replicas changed",
				"old", existing.Spec.Replicas,
				"new", dep.Spec.Replicas)
			existing.Spec.Replicas = dep.Spec.Replicas
			updated = true
		}

		if !reflect.DeepEqual(dep.Spec.Template.Spec.TopologySpreadConstraints, existing.Spec.Template.Spec.TopologySpreadConstraints) {
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: TopologySpreadConstraints changed",
				"old", existing.Spec.Template.Spec.TopologySpreadConstraints,
				"new", dep.Spec.Template.Spec.TopologySpreadConstraints)
			existing.Spec.Template.Spec.TopologySpreadConstraints = dep.Spec.Template.Spec.TopologySpreadConstraints
			updated = true
		}

		if dep.Spec.Template.Spec.Affinity != nil {
			if existing.Spec.Template.Spec.Affinity == nil {
				existing.Spec.Template.Spec.Affinity = &corev1.Affinity{}
			}
			if !reflect.DeepEqual(dep.Spec.Template.Spec.Affinity.NodeAffinity, existing.Spec.Template.Spec.Affinity.NodeAffinity) {
				a.r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: NodeAffinity changed",
					"old", existing.Spec.Template.Spec.Affinity.NodeAffinity,
					"new", dep.Spec.Template.Spec.Affinity.NodeAffinity)
				existing.Spec.Template.Spec.Affinity.NodeAffinity = dep.Spec.Template.Spec.Affinity.NodeAffinity
				updated = true
			}
		}

		// Per-container checks: handle count change as a full replacement, otherwise
		// check each container's fields individually.
		if len(dep.Spec.Template.Spec.Containers) != len(existing.Spec.Template.Spec.Containers) {
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: container count changed",
				"old", len(existing.Spec.Template.Spec.Containers),
				"new", len(dep.Spec.Template.Spec.Containers))
			existing.Spec.Template.Spec.Containers = dep.Spec.Template.Spec.Containers
			updated = true
		} else {
			for i, container := range dep.Spec.Template.Spec.Containers {
				existingContainer := &existing.Spec.Template.Spec.Containers[i]

				if !reflect.DeepEqual(container.Image, existingContainer.Image) {
					a.r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: container image changed",
						"container", container.Name,
						"old", existingContainer.Image, "new", container.Image)
					existingContainer.Image = container.Image
					updated = true
				}

				if !reflect.DeepEqual(container.ImagePullPolicy, existingContainer.ImagePullPolicy) {
					a.r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: container ImagePullPolicy changed",
						"container", container.Name,
						"old", existingContainer.ImagePullPolicy, "new", container.ImagePullPolicy)
					existingContainer.ImagePullPolicy = container.ImagePullPolicy
					updated = true
				}

				if !reflect.DeepEqual(container.Resources, existingContainer.Resources) {
					a.r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: container resources changed",
						"container", container.Name,
						"old", existingContainer.Resources, "new", container.Resources)
					existingContainer.Resources = container.Resources
					updated = true
				}

				if !reflect.DeepEqual(container.Ports, existingContainer.Ports) {
					a.r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: container ports changed",
						"container", container.Name,
						"old", existingContainer.Ports, "new", container.Ports)
					existingContainer.Ports = container.Ports
					updated = true
				}

				if container.LivenessProbe != nil && existingContainer.LivenessProbe != nil &&
					!reflect.DeepEqual(container.LivenessProbe.ProbeHandler.HTTPGet.Port, existingContainer.LivenessProbe.ProbeHandler.HTTPGet.Port) {
					a.r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: container LivenessProbe port changed",
						"container", container.Name,
						"old", existingContainer.LivenessProbe.ProbeHandler.HTTPGet.Port,
						"new", container.LivenessProbe.ProbeHandler.HTTPGet.Port)
					existingContainer.LivenessProbe.ProbeHandler.HTTPGet.Port = container.LivenessProbe.ProbeHandler.HTTPGet.Port
					updated = true
				}

				if container.StartupProbe != nil && existingContainer.StartupProbe != nil &&
					!reflect.DeepEqual(container.StartupProbe.ProbeHandler.HTTPGet.Port, existingContainer.StartupProbe.ProbeHandler.HTTPGet.Port) {
					a.r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: container StartupProbe port changed",
						"container", container.Name,
						"old", existingContainer.StartupProbe.ProbeHandler.HTTPGet.Port,
						"new", container.StartupProbe.ProbeHandler.HTTPGet.Port)
					existingContainer.StartupProbe.ProbeHandler.HTTPGet.Port = container.StartupProbe.ProbeHandler.HTTPGet.Port
					updated = true
				}

				// Merge existing proxy env vars from the cluster into the spec env before comparing,
				// to avoid stripping proxy vars that were injected by the operator environment.
				mergedEnv := pkgcommon.MergeEnvVars(container.Env, existingContainer.Env, pkgcommon.ProxyEnvNamesWithLowerCase())
				if !equality.Semantic.DeepEqual(mergedEnv, existingContainer.Env) {
					a.r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: container env changed",
						"container", container.Name,
						"old", existingContainer.Env, "new", mergedEnv)
					existingContainer.Env = mergedEnv
					updated = true
				}
			}
		}

		// Reconcile proxy env vars: append any new proxy vars from the operator environment,
		// and update the values of any existing proxy vars that have changed.
		if len(proxy.ReadProxyVarsFromEnv()) > 0 {
			for i, container := range existing.Spec.Template.Spec.Containers {
				oldEnv := container.Env
				envAfterAppend := pkgcommon.AppendUniqueEnvVars(container.Env, proxy.ReadProxyVarsFromEnv())
				finalEnv := pkgcommon.UpdateEnvVars(envAfterAppend, proxy.ReadProxyVarsFromEnv())
				if !equality.Semantic.DeepEqual(oldEnv, finalEnv) {
					existing.Spec.Template.Spec.Containers[i].Env = finalEnv
					a.r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: proxy env vars changed",
						"container", existing.Spec.Template.Spec.Containers[i].Name,
						"old", oldEnv, "new", finalEnv)
					updated = true
				}
			}
		}

		mergedTolerations := dep.Spec.Template.Spec.Tolerations
		for _, existingTol := range existing.Spec.Template.Spec.Tolerations {
			found := false
			for _, specTol := range dep.Spec.Template.Spec.Tolerations {
				if existingTol.Key == specTol.Key && existingTol.Effect == specTol.Effect {
					found = true
					break
				}
			}
			if !found {
				mergedTolerations = append(mergedTolerations, existingTol)
			}
		}
		if !equality.Semantic.DeepEqual(existing.Spec.Template.Spec.Tolerations, mergedTolerations) {
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: Tolerations changed",
				"old", existing.Spec.Template.Spec.Tolerations,
				"new", mergedTolerations)
			existing.Spec.Template.Spec.Tolerations = mergedTolerations
			updated = true
		}

		if updated {
			existing.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("Deployment"))
			return k8sutils.Update(a.r, ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, existing)
		}
		return nil
	})
	if err != nil {
		a.r.GetLog().Error(err, "Failed to update FalconClusterGuard Deployment after retries")
		return err
	}
	return nil
}

func (a *Admission) triggerRollingDeployment(ctx context.Context) error {
	const configVersionAnnotation = "falcon.config.version"
	existing := &appsv1.Deployment{}
	if err := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(),
		types.NamespacedName{Name: a.prefix(), Namespace: a.cfg.InstallNamespace},
		existing); err != nil {
		a.r.GetLog().Error(err, "Failed to get FalconClusterGuard Deployment for rolling restart")
		return err
	}

	if existing.Spec.Template.Annotations == nil {
		existing.Spec.Template.Annotations = make(map[string]string)
	}
	if v, ok := existing.Spec.Template.Annotations[configVersionAnnotation]; ok {
		i, err := strconv.Atoi(v)
		if err != nil {
			return err
		}
		existing.Spec.Template.Annotations[configVersionAnnotation] = strconv.Itoa(i + 1)
	} else {
		existing.Spec.Template.Annotations[configVersionAnnotation] = "1"
	}

	a.r.GetLog().Info("Rolling FalconClusterGuard Deployment due to non-deployment configuration change")
	existing.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("Deployment"))
	return k8sutils.Update(a.r, ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, existing)
}
