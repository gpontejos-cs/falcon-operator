package admission

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"strconv"
	"time"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	pkgcommon "github.com/crowdstrike/falcon-operator/pkg/common"
	"github.com/crowdstrike/falcon-operator/pkg/tls"
	"github.com/operator-framework/operator-lib/proxy"
	arv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	Cid              string
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

	saImagePullSecretsUpdated, err := a.reconcileServiceAccount(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := a.reconcileClusterRoleBinding(ctx); err != nil {
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

	if configUpdated || webhookServiceUpdated || apiServiceUpdated || webhookUpdated || saImagePullSecretsUpdated {
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

// syncConfigMap creates or updates a ConfigMap when its Data has drifted.
// It returns true if the ConfigMap data was updated.
func (a *Admission) syncConfigMap(ctx context.Context, cm *corev1.ConfigMap, logLabel string) (bool, error) {
	existing := &corev1.ConfigMap{}
	found, err := k8sutils.GetOrCreate(ctx, a.r, a.cfg.Request, a.cfg.Owner, a.cfg.Status, cm, existing,
		types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace},
		"Failed to get "+logLabel+" ConfigMap")
	if !found || err != nil {
		return false, err
	}
	if !reflect.DeepEqual(cm.Data, existing.Data) {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(),
				types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, existing); err != nil {
				return err
			}
			for k, v := range cm.Data {
				if existing.Data[k] != v {
					a.r.GetLog().V(1).Info("Updating "+logLabel+" ConfigMap: value changed", "key", k, "old", existing.Data[k], "new", v)
				}
			}
			existing.Data = cm.Data
			existing.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
			return k8sutils.Update(a.r, ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, existing)
		})
		return err == nil, err
	}
	return false, nil
}

// reconcileServiceAccount returns true if the ImagePullSecrets changed, which requires a pod restart.
func (a *Admission) reconcileServiceAccount(ctx context.Context) (bool, error) {
	sa := a.serviceAccount()
	existing := &corev1.ServiceAccount{}
	found, err := k8sutils.GetOrCreate(ctx, a.r, a.cfg.Request, a.cfg.Owner, a.cfg.Status, sa, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardServiceAccountName, Namespace: a.cfg.InstallNamespace},
		"Failed to get FalconClusterGuard ServiceAccount")
	if !found || err != nil {
		return false, err
	}

	updated := false
	imagePullSecretsUpdated := false

	for k, v := range sa.Annotations {
		if existing.Annotations[k] != v {
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard ServiceAccount: annotations changed")
			if existing.Annotations == nil {
				existing.Annotations = make(map[string]string)
			}
			maps.Copy(existing.Annotations, sa.Annotations)
			updated = true
			break
		}
	}

	for k, v := range sa.Labels {
		if existing.Labels[k] != v {
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard ServiceAccount: labels changed")
			if existing.Labels == nil {
				existing.Labels = make(map[string]string)
			}
			maps.Copy(existing.Labels, sa.Labels)
			updated = true
			break
		}
	}

	if !reflect.DeepEqual(sa.ImagePullSecrets, existing.ImagePullSecrets) {
		a.r.GetLog().V(1).Info("Updating FalconClusterGuard ServiceAccount: ImagePullSecrets changed",
			"old", existing.ImagePullSecrets,
			"new", sa.ImagePullSecrets)
		existing.ImagePullSecrets = sa.ImagePullSecrets
		updated = true
		imagePullSecretsUpdated = true
	}

	if updated {
		existing.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ServiceAccount"))
		return imagePullSecretsUpdated, k8sutils.Update(a.r, ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, existing)
	}
	return false, nil
}

func (a *Admission) reconcileClusterRoleBinding(ctx context.Context) error {
	crb := a.clusterRoleBinding()
	existing := &rbacv1.ClusterRoleBinding{}
	found, err := k8sutils.GetOrCreate(ctx, a.r, a.cfg.Request, a.cfg.Owner, a.cfg.Status, crb, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardClusterRoleBindingName},
		"Failed to get FalconClusterGuard ClusterRoleBinding")
	if !found || err != nil {
		return err
	}
	if !reflect.DeepEqual(crb.RoleRef, existing.RoleRef) {
		a.r.GetLog().V(1).Info("Recreating FalconClusterGuard ClusterRoleBinding: RoleRef changed")
		if err := k8sutils.Delete(a.r, ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, existing); err != nil {
			return err
		}
		return k8sutils.Create(a.r, a.r.GetScheme(), ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, crb)
	} else if !reflect.DeepEqual(crb.Subjects, existing.Subjects) {
		a.r.GetLog().V(1).Info("Updating FalconClusterGuard ClusterRoleBinding: subjects changed")
		existing.Subjects = crb.Subjects
		existing.SetGroupVersionKind(rbacv1.SchemeGroupVersion.WithKind("ClusterRoleBinding"))
		return k8sutils.Update(a.r, ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, existing)
	}
	return nil
}

func (a *Admission) reconcileRoleBinding(ctx context.Context) error {
	rb := a.roleBinding()
	existing := &rbacv1.RoleBinding{}
	found, err := k8sutils.GetOrCreate(ctx, a.r, a.cfg.Request, a.cfg.Owner, a.cfg.Status, rb, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardRoleBindingName, Namespace: a.cfg.InstallNamespace},
		"Failed to get FalconClusterGuard RoleBinding")
	if !found || err != nil {
		return err
	}
	if !reflect.DeepEqual(rb.RoleRef, existing.RoleRef) {
		a.r.GetLog().V(1).Info("Recreating FalconClusterGuard RoleBinding: RoleRef changed")
		if err := k8sutils.Delete(a.r, ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, existing); err != nil {
			return err
		}
		return k8sutils.Create(a.r, a.r.GetScheme(), ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, rb)
	} else if !reflect.DeepEqual(rb.Subjects, existing.Subjects) {
		a.r.GetLog().V(1).Info("Updating FalconClusterGuard RoleBinding: subjects changed")
		existing.Subjects = rb.Subjects
		existing.SetGroupVersionKind(rbacv1.SchemeGroupVersion.WithKind("RoleBinding"))
		return k8sutils.Update(a.r, ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, existing)
	}
	return nil
}

func (a *Admission) reconcileConfigMap(ctx context.Context) (bool, error) {
	cm := a.configMap()
	return a.syncConfigMap(ctx, cm, "FalconClusterGuard")
}

func (a *Admission) reconcileTLSSecret(ctx context.Context) (*corev1.Secret, error) {
	existing := &corev1.Secret{}
	namespace := a.cfg.InstallNamespace
	err := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(), types.NamespacedName{Name: pkgcommon.ClusterGuardTLSSecretName, Namespace: namespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		svcName := fmt.Sprintf("%s.%s.svc", pkgcommon.ClusterGuardWebhookServiceName, namespace)
		altDNSNames := []string{
			svcName,
			fmt.Sprintf("%s.cluster.local", svcName),
			fmt.Sprintf("%s.%s", svcName, namespace),
		}
		cert, key, ca, err := tls.CertSetup(namespace, 3650, tls.CertInfo{CommonName: svcName, DNSNames: altDNSNames})
		if err != nil {
			a.r.GetLog().Error(err, "Failed to generate FalconClusterGuard TLS certificates")
			return &corev1.Secret{}, err
		}
		tlsSecret := assets.Secret(pkgcommon.ClusterGuardTLSSecretName, namespace, pkgcommon.ClusterGuardComponentName,
			map[string][]byte{"tls.crt": cert, "tls.key": key, "ca.crt": ca}, corev1.SecretTypeTLS)
		if err := k8sutils.Create(a.r, a.r.GetScheme(), ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, tlsSecret); err != nil {
			return &corev1.Secret{}, err
		}
		return tlsSecret, nil
	} else if err != nil {
		a.r.GetLog().Error(err, "Failed to get FalconClusterGuard TLS Secret")
		return &corev1.Secret{}, err
	}
	return existing, nil
}

// reconcileAPITLSSecrets reconciles the three PKI secrets for the gRPC API:
//   - falcon-api-tls:    server TLS cert/key for the API service
//   - falcon-api-ca:     CA cert for clients to verify the API server
//   - falcon-sensor-tls: client TLS cert/key for the node sensor
func (a *Admission) reconcileAPITLSSecrets(ctx context.Context) error {
	namespace := a.cfg.InstallNamespace
	existingAPI := &corev1.Secret{}
	errAPI := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(), types.NamespacedName{Name: pkgcommon.ClusterGuardAPITLSSecretName, Namespace: namespace}, existingAPI)
	existingCA := &corev1.Secret{}
	errCA := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(), types.NamespacedName{Name: pkgcommon.ClusterGuardAPICASecretName, Namespace: namespace}, existingCA)
	existingSensor := &corev1.Secret{}
	errSensor := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(), types.NamespacedName{Name: pkgcommon.ClusterGuardSensorTLSSecretName, Namespace: namespace}, existingSensor)
	if errAPI == nil && errCA == nil && errSensor == nil {
		return nil
	}
	apiSvcName := fmt.Sprintf("%s.%s.svc", pkgcommon.ClusterGuardAPIServiceName, namespace)
	serverCert, serverKey, ca, err := tls.CertSetup(namespace, 3650, tls.CertInfo{
		CommonName: apiSvcName,
		DNSNames:   []string{apiSvcName, fmt.Sprintf("%s.cluster.local", apiSvcName)},
	})
	if err != nil {
		a.r.GetLog().Error(err, "Failed to generate FalconClusterGuard API TLS certificates")
		return err
	}
	sensorSvcName := fmt.Sprintf("%s.%s.svc", pkgcommon.ClusterGuardSensorServiceAccountName, namespace)
	clientCert, clientKey, _, err := tls.CertSetup(namespace, 3650, tls.CertInfo{
		CommonName: "falcon-sensor-client",
		DNSNames:   []string{sensorSvcName},
	})
	if err != nil {
		a.r.GetLog().Error(err, "Failed to generate FalconClusterGuard sensor client TLS certificates")
		return err
	}
	if apierrors.IsNotFound(errAPI) {
		s := assets.Secret(pkgcommon.ClusterGuardAPITLSSecretName, namespace, pkgcommon.ClusterGuardComponentName,
			map[string][]byte{"tls.crt": serverCert, "tls.key": serverKey}, corev1.SecretTypeTLS)
		if err := k8sutils.Create(a.r, a.r.GetScheme(), ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, s); err != nil {
			return err
		}
	} else if errAPI != nil {
		a.r.GetLog().Error(errAPI, "Failed to get FalconClusterGuard API TLS Secret")
		return errAPI
	}
	if apierrors.IsNotFound(errCA) {
		s := assets.Secret(pkgcommon.ClusterGuardAPICASecretName, namespace, pkgcommon.ClusterGuardComponentName,
			map[string][]byte{"ca.crt": ca}, corev1.SecretTypeOpaque)
		if err := k8sutils.Create(a.r, a.r.GetScheme(), ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, s); err != nil {
			return err
		}
	} else if errCA != nil {
		a.r.GetLog().Error(errCA, "Failed to get FalconClusterGuard API CA Secret")
		return errCA
	}
	if apierrors.IsNotFound(errSensor) {
		s := assets.Secret(pkgcommon.ClusterGuardSensorTLSSecretName, namespace, pkgcommon.ClusterGuardComponentName,
			map[string][]byte{"tls.crt": clientCert, "tls.key": clientKey}, corev1.SecretTypeTLS)
		if err := k8sutils.Create(a.r, a.r.GetScheme(), ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, s); err != nil {
			return err
		}
	} else if errSensor != nil {
		a.r.GetLog().Error(errSensor, "Failed to get FalconClusterGuard sensor TLS Secret")
		return errSensor
	}
	return nil
}

// reconcileWebhookService returns true if the service was updated, which requires a pod restart.
func (a *Admission) reconcileWebhookService(ctx context.Context) (bool, error) {
	svc := a.webhookService()
	existing := &corev1.Service{}
	found, err := k8sutils.GetOrCreate(ctx, a.r, a.cfg.Request, a.cfg.Owner, a.cfg.Status, svc, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardWebhookServiceName, Namespace: a.cfg.InstallNamespace},
		"Failed to get FalconClusterGuard webhook Service")
	if !found || err != nil {
		return false, err
	}
	if !reflect.DeepEqual(svc.Spec.Ports, existing.Spec.Ports) || !reflect.DeepEqual(svc.Spec.Selector, existing.Spec.Selector) {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(),
				types.NamespacedName{Name: pkgcommon.ClusterGuardWebhookServiceName, Namespace: a.cfg.InstallNamespace},
				existing); err != nil {
				return err
			}
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard Service: ports or selector changed", "service", pkgcommon.ClusterGuardWebhookServiceName)
			existing.Spec.Ports = svc.Spec.Ports
			existing.Spec.Selector = svc.Spec.Selector
			existing.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Service"))
			return k8sutils.Update(a.r, ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, existing)
		})
		return err == nil, err
	}
	return false, nil
}

// reconcileAPIService returns true if the service was updated, which requires a pod restart.
func (a *Admission) reconcileAPIService(ctx context.Context) (bool, error) {
	svc := a.apiService()
	existing := &corev1.Service{}
	found, err := k8sutils.GetOrCreate(ctx, a.r, a.cfg.Request, a.cfg.Owner, a.cfg.Status, svc, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardAPIServiceName, Namespace: a.cfg.InstallNamespace},
		"Failed to get FalconClusterGuard API Service")
	if !found || err != nil {
		return false, err
	}
	if !reflect.DeepEqual(svc.Spec.Ports, existing.Spec.Ports) || !reflect.DeepEqual(svc.Spec.Selector, existing.Spec.Selector) {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(),
				types.NamespacedName{Name: pkgcommon.ClusterGuardAPIServiceName, Namespace: a.cfg.InstallNamespace},
				existing); err != nil {
				return err
			}
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard Service: ports or selector changed", "service", pkgcommon.ClusterGuardAPIServiceName)
			existing.Spec.Ports = svc.Spec.Ports
			existing.Spec.Selector = svc.Spec.Selector
			existing.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Service"))
			return k8sutils.Update(a.r, ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, existing)
		})
		return err == nil, err
	}
	return false, nil
}

// reconcileValidatingWebhook returns true if the webhook configuration was updated, which requires a pod restart.
func (a *Admission) reconcileValidatingWebhook(ctx context.Context, caBundle []byte) (bool, error) {
	webhook := a.ValidatingWebhook(caBundle)
	existing := &arv1.ValidatingWebhookConfiguration{}
	found, err := k8sutils.GetOrCreate(ctx, a.r, a.cfg.Request, a.cfg.Owner, a.cfg.Status, webhook, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardValidatingWebhookName},
		"Failed to get FalconClusterGuard ValidatingWebhookConfiguration")
	if !found || err != nil {
		return false, err
	}

	needsUpdate := len(webhook.Webhooks) != len(existing.Webhooks)
	if !needsUpdate && len(webhook.Webhooks) > 0 {
		if !reflect.DeepEqual(webhook.Webhooks[0].FailurePolicy, existing.Webhooks[0].FailurePolicy) {
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard ValidatingWebhookConfiguration: FailurePolicy changed",
				"old", existing.Webhooks[0].FailurePolicy,
				"new", webhook.Webhooks[0].FailurePolicy)
			needsUpdate = true
		}
		if !reflect.DeepEqual(webhook.Webhooks[0].ClientConfig, existing.Webhooks[0].ClientConfig) {
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard ValidatingWebhookConfiguration: ClientConfig changed")
			needsUpdate = true
		}
		if !reflect.DeepEqual(webhook.Webhooks[0].NamespaceSelector, existing.Webhooks[0].NamespaceSelector) {
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard ValidatingWebhookConfiguration: NamespaceSelector changed")
			needsUpdate = true
		}
	}

	if needsUpdate {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(),
				types.NamespacedName{Name: pkgcommon.ClusterGuardValidatingWebhookName},
				existing); err != nil {
				return err
			}
			existing.Webhooks = webhook.Webhooks
			existing.SetGroupVersionKind(arv1.SchemeGroupVersion.WithKind("ValidatingWebhookConfiguration"))
			return k8sutils.Update(a.r, ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, existing)
		})
		return err == nil, err
	}
	return false, nil
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

// triggerRollingDeployment bumps a config-version annotation on the deployment's pod template to
// force a rolling restart. This is called when non-deployment resources change (ConfigMap,
// Services, ValidatingWebhookConfiguration, ServiceAccount ImagePullSecrets).
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
