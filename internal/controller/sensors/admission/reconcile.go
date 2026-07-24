package admission

import (
	"context"
	"time"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	corev1 "k8s.io/api/core/v1"
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
	AdmissionConfig  falconv1alpha1.FalconAdmissionBaseConfig
	NamePrefix       string
	ClusterName      *string
	RegistryTLS      falconv1alpha1.RegistryTLSSpec
	Cid              string
	Falcon           falconv1alpha1.FalconSensor
}

const admissionDefaultPrefix = "falcon-clusterguard"

// prefix returns the name prefix to use for owned resources.
// If NamePrefix is set in config, it is used; otherwise the default is returned.
func (a *Admission) prefix() string {
	if a.cfg.NamePrefix != "" {
		return a.cfg.NamePrefix
	}
	return admissionDefaultPrefix
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
	clusterNameConfigUpdated, err := a.reconcileClusterNameConfigMap(ctx)
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

	if configUpdated || clusterNameConfigUpdated || webhookServiceUpdated || apiServiceUpdated || webhookUpdated {
		pod, err := k8sutils.GetReadyPod(a.r.GetK8sReader(), ctx, a.cfg.InstallNamespace,
			client.MatchingLabels{"app": a.prefix()})
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
