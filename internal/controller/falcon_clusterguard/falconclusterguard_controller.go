package controllers

import (
	"context"
	"fmt"
	"os"
	"time"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	commonctrl "github.com/crowdstrike/falcon-operator/internal/controller/common"
	"github.com/crowdstrike/falcon-operator/internal/controller/common/image"
	"github.com/crowdstrike/falcon-operator/internal/controller/sensors/admission"
	"github.com/crowdstrike/falcon-operator/internal/controller/sensors/node_sensor"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	"github.com/crowdstrike/falcon-operator/version"
	"github.com/go-logr/logr"
	arv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// FalconClusterGuardReconciler reconciles a FalconClusterGuard object
type FalconClusterGuardReconciler struct {
	client.Client
	Reader        client.Reader
	RuntimeScheme *runtime.Scheme
	OpenShift     bool
	log           logr.Logger
}

// SetupWithManager sets up the controller with the Manager.
func (r *FalconClusterGuardReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&falconv1alpha1.FalconClusterGuard{}).
		Owns(&corev1.Namespace{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&corev1.Service{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&arv1.ValidatingWebhookConfiguration{}).
		Complete(r)
}

// GetK8sClient returns the Kubernetes client
func (r *FalconClusterGuardReconciler) GetK8sClient() client.Client {
	return r.Client
}

// GetK8sReader returns the Kubernetes API reader
func (r *FalconClusterGuardReconciler) GetK8sReader() client.Reader {
	return r.Reader
}

// GetScheme returns the runtime scheme
func (r *FalconClusterGuardReconciler) GetScheme() *runtime.Scheme {
	return r.RuntimeScheme
}

// GetLog returns the reconciler logger
func (r *FalconClusterGuardReconciler) GetLog() logr.Logger {
	return r.log
}

//+kubebuilder:rbac:groups=falcon.crowdstrike.com,resources=falconclusterguards,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=falcon.crowdstrike.com,resources=falconclusterguards/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=falcon.crowdstrike.com,resources=falconclusterguards/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch;create;update;delete
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;delete
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;delete
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;delete
//+kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;delete
//+kubebuilder:rbac:groups="apps",resources=deployments,verbs=get;list;watch;create;update;delete
//+kubebuilder:rbac:groups="apps",resources=daemonsets,verbs=get;list;watch;create;update;delete
//+kubebuilder:rbac:groups="admissionregistration.k8s.io",resources=validatingwebhookconfigurations,verbs=get;list;watch;create;update;delete
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=create;get;list;update;watch;delete
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=create;get;list;update;watch;delete
//+kubebuilder:rbac:groups="coordination.k8s.io",resources=leases,verbs=get;list;watch;create;update;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *FalconClusterGuardReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.log = log.FromContext(ctx)

	r.log.Info("Reconciling FalconClusterGuard")

	falconClusterGuard := &falconv1alpha1.FalconClusterGuard{}
	err := common.GetWithFallback(ctx, r.Client, r.Reader, req.NamespacedName, falconClusterGuard)
	if err != nil {
		if apierrors.IsNotFound(err) {
			r.log.Info("FalconClusterGuard resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}

		r.log.Error(err, "Failed to get FalconClusterGuard resource")
		return ctrl.Result{}, err
	}

	// Set initial pending status when no conditions exist yet
	if len(falconClusterGuard.Status.Conditions) == 0 {
		if err := commonctrl.StatusUpdate(ctx, r.Client, r.Status(), req, r.log, falconClusterGuard,
			falconv1alpha1.ConditionPending, metav1.ConditionFalse,
			falconv1alpha1.ReasonReqNotMet, "FalconClusterGuard progressing"); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Inject sensitive values from a k8s Secret before any reconciliation that uses them
	if falconClusterGuard.Spec.FalconSecret.Enabled {
		if err := r.injectFalconSecretData(ctx, falconClusterGuard); err != nil {
			r.log.Error(err, "Failed to inject FalconSecret data")
			return ctrl.Result{}, err
		}
	}

	if falconClusterGuard.Status.Version != version.Get() {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := common.GetWithFallback(ctx, r.Client, r.Reader, req.NamespacedName, falconClusterGuard); err != nil {
				return err
			}
			falconClusterGuard.Status.Version = version.Get()
			return r.Status().Update(ctx, falconClusterGuard)
		})
		if err != nil {
			r.log.Error(err, "Failed to update FalconClusterGuard status version")
			return ctrl.Result{}, err
		}
	}

	imgCfg := image.Config{
		Image:              falconClusterGuard.Spec.Image,
		FalconAPI:          falconClusterGuard.Spec.FalconAPI,
		FalconSecret:       falconClusterGuard.Spec.FalconSecret,
		Version:            falconClusterGuard.Spec.Version,
		RelatedImageEnvVar: "RELATED_IMAGE_CLUSTER_GUARD",
	}

	// Image being set will override other image-based settings.
	var imageURI string
	if falconClusterGuard.Spec.Image != "" {
		if _, err := image.SetTag(ctx, r, imgCfg, &falconClusterGuard.Status, falconClusterGuard); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to set Falcon Cloud Guard Image version: %v", err)
		}
		imageURI = falconClusterGuard.Spec.Image
	} else if os.Getenv(imgCfg.RelatedImageEnvVar) != "" && (falconClusterGuard.Spec.FalconAPI == nil || !falconClusterGuard.Spec.FalconSecret.Enabled) {
		if _, err := image.SetTag(ctx, r, imgCfg, &falconClusterGuard.Status, falconClusterGuard); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to set Falcon Cloud Guard Image version: %v", err)
		}
		imageURI = os.Getenv(imgCfg.RelatedImageEnvVar)
	} else {
		if !meta.IsStatusConditionPresentAndEqual(falconClusterGuard.Status.Conditions, falconv1alpha1.ConditionImageReady, metav1.ConditionTrue) {
			uri, err := image.URI(ctx, r, imgCfg, &falconClusterGuard.Status, falconClusterGuard)
			if err != nil {
				time.Sleep(5 * time.Second)
				return ctrl.Result{RequeueAfter: 5 * time.Second}, fmt.Errorf("Cannot find Falcon Registry URI: %s", err)
			}
			r.log.Info("Skipping push of Falcon Cloud Guard image to local registry. Remote CrowdStrike registry will be used.")
			meta.SetStatusCondition(&falconClusterGuard.Status.Conditions, metav1.Condition{
				Status:             metav1.ConditionTrue,
				Reason:             falconv1alpha1.ReasonDiscovered,
				Message:            uri,
				Type:               falconv1alpha1.ConditionImageReady,
				ObservedGeneration: falconClusterGuard.GetGeneration(),
			})
			if err := r.Status().Update(ctx, falconClusterGuard); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		var err error
		imageURI, err = image.URI(ctx, r, imgCfg, &falconClusterGuard.Status, falconClusterGuard)
		if err != nil {
			time.Sleep(5 * time.Second)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, err
		}
	}

	if err := commonctrl.ReconcileNamespace(ctx, r, req, falconClusterGuard, &falconClusterGuard.Status, falconClusterGuard.Spec.InstallNamespace); err != nil {
		return ctrl.Result{}, err
	}

	if err := admission.Reconcile(ctx, r, admission.Config{
		Request:          req,
		Owner:            falconClusterGuard,
		Status:           &falconClusterGuard.Status,
		InstallNamespace: falconClusterGuard.Spec.InstallNamespace,
		Image:            imageURI,
		ImagePullPolicy:  falconClusterGuard.Spec.ImagePullPolicy,
		ImagePullSecrets: falconClusterGuard.Spec.ImagePullSecrets,
		AdmissionConfig:  falconClusterGuard.Spec.AdmissionConfig,
	}); err != nil {
		return ctrl.Result{}, err
	}

	return node_sensor.Reconcile(ctx, r, node_sensor.Config{
		Request:          req,
		Owner:            falconClusterGuard,
		Status:           &falconClusterGuard.Status,
		InstallNamespace: falconClusterGuard.Spec.InstallNamespace,
		Image:            imageURI,
		ImagePullPolicy:  falconClusterGuard.Spec.ImagePullPolicy,
		ImagePullSecrets: falconClusterGuard.Spec.ImagePullSecrets,
		Falcon:           falconClusterGuard.Spec.Falcon,
		FalconAPI:        falconClusterGuard.Spec.FalconAPI,
		NodeSensor:       falconClusterGuard.Spec.NodeSensor,
	})
}
