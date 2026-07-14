package admission

import (
	"context"
	"reflect"
	"strconv"
	"time"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	pkgcommon "github.com/crowdstrike/falcon-operator/pkg/common"
	"github.com/operator-framework/operator-lib/proxy"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Reconciler is the interface the admission component requires from the controller.
type Reconciler = k8sutils.Reconciler

// Config holds the inputs needed to reconcile the admission controller component.
type Config struct {
	Request          ctrl.Request
	Owner            client.Object
	Status           *falconv1alpha1.FalconCRStatus
	InstallNamespace string
	Image            string
	ImagePullPolicy  corev1.PullPolicy
	ImagePullSecrets []corev1.LocalObjectReference
	AdmissionConfig  falconv1alpha1.FalconAdmissionConfigSpec
	RegistryTLS      falconv1alpha1.RegistryTLSSpec
	Cid              string
	Falcon           falconv1alpha1.FalconSensor
}

// Admission owns the reconciliation of all admission controller sub-resources.
type Admission struct {
	r   Reconciler
	cfg Config
}

// New returns an Admission ready to reconcile.
func New(r Reconciler, cfg Config) *Admission {
	return &Admission{r: r, cfg: cfg}
}

// Reconcile runs all admission controller reconciliation steps in order.
func (a *Admission) Reconcile(ctx context.Context) (ctrl.Result, error) {
	log := a.r.GetLog()

	if err := a.reconcileServiceAccount(ctx); err != nil {
		return ctrl.Result{}, err
	}
	if err := a.reconcileClusterRoleBinding(ctx); err != nil {
		return ctrl.Result{}, err
	}
	if err := a.reconcileRole(ctx); err != nil {
		return ctrl.Result{}, err
	}
	if err := a.reconcileRoleBinding(ctx); err != nil {
		return ctrl.Result{}, err
	}
	configUpdated, err := a.reconcileConfigMap(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	tlsSecret, err := a.reconcileTLSSecret(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := a.reconcileAPITLSSecrets(ctx); err != nil {
		return ctrl.Result{}, err
	}
	webhookServiceUpdated, err := a.reconcileWebhookService(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	apiServiceUpdated, err := a.reconcileAPIService(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	webhookUpdated, err := a.reconcileValidatingWebhook(ctx, tlsSecret.Data["ca.crt"])
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := a.reconcileDeployment(ctx); err != nil {
		return ctrl.Result{}, err
	}

	if configUpdated || webhookServiceUpdated || apiServiceUpdated || webhookUpdated {
		pod, err := k8sutils.GetReadyPod(a.r.GetK8sReader(), ctx, a.cfg.InstallNamespace,
			client.MatchingLabels{"app": pkgcommon.ClusterGuardDeploymentName})
		if err != nil && err != k8sutils.ErrNoWebhookServicePodReady {
			log.Error(err, "Failed to find Ready FalconClusterGuard pod")
			return ctrl.Result{}, err
		}
		if pod.Name == "" {
			log.Info("Looking for a Ready FalconClusterGuard pod", "namespace", a.cfg.InstallNamespace)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		return ctrl.Result{}, a.triggerRollingDeployment(ctx)
	}
	return ctrl.Result{}, nil
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
		types.NamespacedName{Name: pkgcommon.ClusterGuardDeploymentName, Namespace: a.cfg.InstallNamespace},
		"Failed to get FalconClusterGuard Deployment")
	if !found || err != nil {
		return err
	}

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(),
			types.NamespacedName{Name: pkgcommon.ClusterGuardDeploymentName, Namespace: a.cfg.InstallNamespace},
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
		types.NamespacedName{Name: pkgcommon.ClusterGuardDeploymentName, Namespace: a.cfg.InstallNamespace},
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
