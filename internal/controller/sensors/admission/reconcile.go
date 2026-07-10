package admission

import (
	"context"
	"fmt"
	"reflect"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	pkgcommon "github.com/crowdstrike/falcon-operator/pkg/common"
	"github.com/crowdstrike/falcon-operator/pkg/tls"
	arv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Reconciler is the interface the admission component requires from the controller.
type Reconciler interface {
	client.Client
	GetK8sReader() client.Reader
	GetScheme()    *runtime.Scheme
	GetLog()       logr.Logger
}

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
}

// Reconcile runs all admission controller reconciliation steps in order.
func Reconcile(ctx context.Context, r Reconciler, cfg Config) error {
	if err := reconcileServiceAccount(ctx, r, cfg); err != nil {
		return err
	}
	if err := reconcileClusterRoleBinding(ctx, r, cfg); err != nil {
		return err
	}
	if err := reconcileRoleBinding(ctx, r, cfg); err != nil {
		return err
	}
	if err := reconcileConfigMap(ctx, r, cfg); err != nil {
		return err
	}
	tlsSecret, err := reconcileTLSSecret(ctx, r, cfg)
	if err != nil {
		return err
	}
	if err := reconcileAPITLSSecrets(ctx, r, cfg); err != nil {
		return err
	}
	if err := reconcileWebhookService(ctx, r, cfg); err != nil {
		return err
	}
	if err := reconcileAPIService(ctx, r, cfg); err != nil {
		return err
	}
	if err := reconcileValidatingWebhook(ctx, r, cfg, tlsSecret.Data["ca.crt"]); err != nil {
		return err
	}
	return reconcileDeployment(ctx, r, cfg)
}

// getOrCreate fetches existing into existing. If not found, creates desired and returns (false, nil).
// Returns (true, nil) when the resource exists. On other errors returns (false, err).
func getOrCreate(ctx context.Context, r Reconciler, cfg Config, desired, existing client.Object, key types.NamespacedName, errMsg string) (bool, error) {
	if err := pkgcommon.GetWithFallback(ctx, r, r.GetK8sReader(), key, existing); err != nil {
		if apierrors.IsNotFound(err) {
			return false, k8sutils.Create(r, r.GetScheme(), ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, desired)
		}
		r.GetLog().Error(err, errMsg)
		return false, err
	}
	return true, nil
}

// syncConfigMap creates or updates a ConfigMap when its Data has drifted.
func syncConfigMap(ctx context.Context, r Reconciler, cfg Config, cm *corev1.ConfigMap, logLabel string) error {
	existing := &corev1.ConfigMap{}
	found, err := getOrCreate(ctx, r, cfg, cm, existing,
		types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace},
		"Failed to get "+logLabel+" ConfigMap")
	if !found || err != nil {
		return err
	}
	if !reflect.DeepEqual(cm.Data, existing.Data) {
		for k, v := range cm.Data {
			if existing.Data[k] != v {
				r.GetLog().V(1).Info("Updating "+logLabel+" ConfigMap: value changed", "key", k, "old", existing.Data[k], "new", v)
			}
		}
		existing.Data = cm.Data
		existing.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
		return k8sutils.Update(r, ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, existing)
	}
	return nil
}

func reconcileServiceAccount(ctx context.Context, r Reconciler, cfg Config) error {
	sa := ClusterGuardServiceAccount(cfg.InstallNamespace)
	_, err := getOrCreate(ctx, r, cfg, sa, &corev1.ServiceAccount{},
		types.NamespacedName{Name: pkgcommon.ClusterGuardServiceAccountName, Namespace: cfg.InstallNamespace},
		"Failed to get FalconClusterGuard ServiceAccount")
	return err
}

func reconcileClusterRoleBinding(ctx context.Context, r Reconciler, cfg Config) error {
	crb := ClusterGuardClusterRoleBinding(cfg.InstallNamespace)
	existing := &rbacv1.ClusterRoleBinding{}
	found, err := getOrCreate(ctx, r, cfg, crb, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardClusterRoleBindingName},
		"Failed to get FalconClusterGuard ClusterRoleBinding")
	if !found || err != nil {
		return err
	}
	if !reflect.DeepEqual(crb.RoleRef, existing.RoleRef) {
		if err := k8sutils.Delete(r, ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, existing); err != nil {
			return err
		}
		return k8sutils.Create(r, r.GetScheme(), ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, crb)
	} else if !reflect.DeepEqual(crb.Subjects, existing.Subjects) {
		r.GetLog().V(1).Info("Updating FalconClusterGuard ClusterRoleBinding: subjects changed")
		existing.Subjects = crb.Subjects
		existing.SetGroupVersionKind(rbacv1.SchemeGroupVersion.WithKind("ClusterRoleBinding"))
		return k8sutils.Update(r, ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, existing)
	}
	return nil
}

func reconcileRoleBinding(ctx context.Context, r Reconciler, cfg Config) error {
	rb := ClusterGuardRoleBinding(cfg.InstallNamespace)
	existing := &rbacv1.RoleBinding{}
	found, err := getOrCreate(ctx, r, cfg, rb, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardRoleBindingName, Namespace: cfg.InstallNamespace},
		"Failed to get FalconClusterGuard RoleBinding")
	if !found || err != nil {
		return err
	}
	if !reflect.DeepEqual(rb.RoleRef, existing.RoleRef) {
		if err := k8sutils.Delete(r, ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, existing); err != nil {
			return err
		}
		return k8sutils.Create(r, r.GetScheme(), ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, rb)
	} else if !reflect.DeepEqual(rb.Subjects, existing.Subjects) {
		r.GetLog().V(1).Info("Updating FalconClusterGuard RoleBinding: subjects changed")
		existing.Subjects = rb.Subjects
		existing.SetGroupVersionKind(rbacv1.SchemeGroupVersion.WithKind("RoleBinding"))
		return k8sutils.Update(r, ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, existing)
	}
	return nil
}

func reconcileConfigMap(ctx context.Context, r Reconciler, cfg Config) error {
	cm := ClusterGuardConfigMap(cfg.InstallNamespace, cfg.AdmissionConfig)
	return syncConfigMap(ctx, r, cfg, cm, "FalconClusterGuard")
}

func reconcileTLSSecret(ctx context.Context, r Reconciler, cfg Config) (*corev1.Secret, error) {
	existing := &corev1.Secret{}
	namespace := cfg.InstallNamespace
	err := pkgcommon.GetWithFallback(ctx, r, r.GetK8sReader(), types.NamespacedName{Name: pkgcommon.ClusterGuardTLSSecretName, Namespace: namespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		svcName := fmt.Sprintf("%s.%s.svc", pkgcommon.ClusterGuardWebhookServiceName, namespace)
		altDNSNames := []string{
			svcName,
			fmt.Sprintf("%s.cluster.local", svcName),
			fmt.Sprintf("%s.%s", svcName, namespace),
		}
		cert, key, ca, err := tls.CertSetup(namespace, 3650, tls.CertInfo{CommonName: svcName, DNSNames: altDNSNames})
		if err != nil {
			r.GetLog().Error(err, "Failed to generate FalconClusterGuard TLS certificates")
			return &corev1.Secret{}, err
		}
		tlsSecret := assets.Secret(pkgcommon.ClusterGuardTLSSecretName, namespace, pkgcommon.ClusterGuardComponentName,
			map[string][]byte{"tls.crt": cert, "tls.key": key, "ca.crt": ca}, corev1.SecretTypeTLS)
		if err := k8sutils.Create(r, r.GetScheme(), ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, tlsSecret); err != nil {
			return &corev1.Secret{}, err
		}
		return tlsSecret, nil
	} else if err != nil {
		r.GetLog().Error(err, "Failed to get FalconClusterGuard TLS Secret")
		return &corev1.Secret{}, err
	}
	return existing, nil
}

// reconcileAPITLSSecrets reconciles the three PKI secrets for the gRPC API:
//   - falcon-api-tls:    server TLS cert/key for the API service
//   - falcon-api-ca:     CA cert for clients to verify the API server
//   - falcon-sensor-tls: client TLS cert/key for the node sensor
func reconcileAPITLSSecrets(ctx context.Context, r Reconciler, cfg Config) error {
	namespace := cfg.InstallNamespace
	existingAPI := &corev1.Secret{}
	errAPI := pkgcommon.GetWithFallback(ctx, r, r.GetK8sReader(), types.NamespacedName{Name: pkgcommon.ClusterGuardAPITLSSecretName, Namespace: namespace}, existingAPI)
	existingCA := &corev1.Secret{}
	errCA := pkgcommon.GetWithFallback(ctx, r, r.GetK8sReader(), types.NamespacedName{Name: pkgcommon.ClusterGuardAPICASecretName, Namespace: namespace}, existingCA)
	existingSensor := &corev1.Secret{}
	errSensor := pkgcommon.GetWithFallback(ctx, r, r.GetK8sReader(), types.NamespacedName{Name: pkgcommon.ClusterGuardSensorTLSSecretName, Namespace: namespace}, existingSensor)
	if errAPI == nil && errCA == nil && errSensor == nil {
		return nil
	}
	apiSvcName := fmt.Sprintf("%s.%s.svc", pkgcommon.ClusterGuardAPIServiceName, namespace)
	serverCert, serverKey, ca, err := tls.CertSetup(namespace, 3650, tls.CertInfo{
		CommonName: apiSvcName,
		DNSNames:   []string{apiSvcName, fmt.Sprintf("%s.cluster.local", apiSvcName)},
	})
	if err != nil {
		r.GetLog().Error(err, "Failed to generate FalconClusterGuard API TLS certificates")
		return err
	}
	sensorSvcName := fmt.Sprintf("%s.%s.svc", pkgcommon.ClusterGuardSensorServiceAccountName, namespace)
	clientCert, clientKey, _, err := tls.CertSetup(namespace, 3650, tls.CertInfo{
		CommonName: "falcon-sensor-client",
		DNSNames:   []string{sensorSvcName},
	})
	if err != nil {
		r.GetLog().Error(err, "Failed to generate FalconClusterGuard sensor client TLS certificates")
		return err
	}
	if apierrors.IsNotFound(errAPI) {
		s := assets.Secret(pkgcommon.ClusterGuardAPITLSSecretName, namespace, pkgcommon.ClusterGuardComponentName,
			map[string][]byte{"tls.crt": serverCert, "tls.key": serverKey}, corev1.SecretTypeTLS)
		if err := k8sutils.Create(r, r.GetScheme(), ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, s); err != nil {
			return err
		}
	} else if errAPI != nil {
		r.GetLog().Error(errAPI, "Failed to get FalconClusterGuard API TLS Secret")
		return errAPI
	}
	if apierrors.IsNotFound(errCA) {
		s := assets.Secret(pkgcommon.ClusterGuardAPICASecretName, namespace, pkgcommon.ClusterGuardComponentName,
			map[string][]byte{"ca.crt": ca}, corev1.SecretTypeOpaque)
		if err := k8sutils.Create(r, r.GetScheme(), ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, s); err != nil {
			return err
		}
	} else if errCA != nil {
		r.GetLog().Error(errCA, "Failed to get FalconClusterGuard API CA Secret")
		return errCA
	}
	if apierrors.IsNotFound(errSensor) {
		s := assets.Secret(pkgcommon.ClusterGuardSensorTLSSecretName, namespace, pkgcommon.ClusterGuardComponentName,
			map[string][]byte{"tls.crt": clientCert, "tls.key": clientKey}, corev1.SecretTypeTLS)
		if err := k8sutils.Create(r, r.GetScheme(), ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, s); err != nil {
			return err
		}
	} else if errSensor != nil {
		r.GetLog().Error(errSensor, "Failed to get FalconClusterGuard sensor TLS Secret")
		return errSensor
	}
	return nil
}

func reconcileWebhookService(ctx context.Context, r Reconciler, cfg Config) error {
	svc := ClusterGuardWebhookService(cfg.InstallNamespace)
	existing := &corev1.Service{}
	found, err := getOrCreate(ctx, r, cfg, svc, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardWebhookServiceName, Namespace: cfg.InstallNamespace},
		"Failed to get FalconClusterGuard webhook Service")
	if !found || err != nil {
		return err
	}
	if !reflect.DeepEqual(svc.Spec.Ports, existing.Spec.Ports) || !reflect.DeepEqual(svc.Spec.Selector, existing.Spec.Selector) {
		r.GetLog().V(1).Info("Updating FalconClusterGuard Service: ports or selector changed", "service", pkgcommon.ClusterGuardWebhookServiceName)
		existing.Spec.Ports = svc.Spec.Ports
		existing.Spec.Selector = svc.Spec.Selector
		existing.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Service"))
		return k8sutils.Update(r, ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, existing)
	}
	return nil
}

func reconcileAPIService(ctx context.Context, r Reconciler, cfg Config) error {
	svc := ClusterGuardAPIService(cfg.InstallNamespace)
	existing := &corev1.Service{}
	found, err := getOrCreate(ctx, r, cfg, svc, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardAPIServiceName, Namespace: cfg.InstallNamespace},
		"Failed to get FalconClusterGuard API Service")
	if !found || err != nil {
		return err
	}
	if !reflect.DeepEqual(svc.Spec.Ports, existing.Spec.Ports) || !reflect.DeepEqual(svc.Spec.Selector, existing.Spec.Selector) {
		r.GetLog().V(1).Info("Updating FalconClusterGuard Service: ports or selector changed", "service", pkgcommon.ClusterGuardAPIServiceName)
		existing.Spec.Ports = svc.Spec.Ports
		existing.Spec.Selector = svc.Spec.Selector
		existing.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Service"))
		return k8sutils.Update(r, ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, existing)
	}
	return nil
}

func reconcileValidatingWebhook(ctx context.Context, r Reconciler, cfg Config, caBundle []byte) error {
	webhook := ClusterGuardValidatingWebhook(cfg.InstallNamespace, caBundle, cfg.AdmissionConfig.DisabledNamespaces.Namespaces)
	existing := &arv1.ValidatingWebhookConfiguration{}
	found, err := getOrCreate(ctx, r, cfg, webhook, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardValidatingWebhookName},
		"Failed to get FalconClusterGuard ValidatingWebhookConfiguration")
	if !found || err != nil {
		return err
	}
	if !reflect.DeepEqual(webhook.Webhooks, existing.Webhooks) {
		r.GetLog().V(1).Info("Updating FalconClusterGuard ValidatingWebhookConfiguration: webhooks changed")
		existing.Webhooks = webhook.Webhooks
		existing.SetGroupVersionKind(arv1.SchemeGroupVersion.WithKind("ValidatingWebhookConfiguration"))
		return k8sutils.Update(r, ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, existing)
	}
	return nil
}

func reconcileDeployment(ctx context.Context, r Reconciler, cfg Config) error {
	imagePullPolicy := cfg.ImagePullPolicy
	if imagePullPolicy == "" {
		imagePullPolicy = corev1.PullIfNotPresent
	}
	dep := ClusterGuardDeployment(pkgcommon.ClusterGuardDeploymentName, cfg.InstallNamespace, cfg.Image, imagePullPolicy, cfg.ImagePullSecrets)
	existing := &appsv1.Deployment{}
	found, err := getOrCreate(ctx, r, cfg, dep, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardDeploymentName, Namespace: cfg.InstallNamespace},
		"Failed to get FalconClusterGuard Deployment")
	if !found || err != nil {
		return err
	}
	if !equality.Semantic.DeepEqual(dep.Spec.Template.Spec.Containers, existing.Spec.Template.Spec.Containers) {
		r.GetLog().V(1).Info("Updating FalconClusterGuard Deployment: container spec changed")
		existing.Spec.Template.Spec.Containers = dep.Spec.Template.Spec.Containers
		existing.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("Deployment"))
		return k8sutils.Update(r, ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, existing)
	}
	return nil
}
