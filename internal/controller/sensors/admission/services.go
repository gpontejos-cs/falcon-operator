package admission

import (
	"context"
	"reflect"

	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	pkgcommon "github.com/crowdstrike/falcon-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
)

// webhookService builds the Service that exposes the admission webhook.
func (a *Admission) webhookService() *corev1.Service {
	selector := map[string]string{"app": pkgcommon.AdmissionDeploymentName}
	labels := map[string]string{"app": pkgcommon.AdmissionDeploymentName}

	return assets.ServiceWithCustomLabels(
		pkgcommon.AdmissionWebhookServiceName,
		a.cfg.InstallNamespace,
		selector,
		labels,
		pkgcommon.FalconServiceHTTPSName,
		"webhook-port",
		pkgcommon.FalconServiceHTTPSPort,
	)
}

// apiService builds the Service that exposes the gRPC API.
func (a *Admission) apiService() *corev1.Service {
	selector := map[string]string{"app": pkgcommon.AdmissionDeploymentName}
	labels := map[string]string{"app": pkgcommon.AdmissionDeploymentName}

	return assets.ServiceWithCustomLabels(
		pkgcommon.AdmissionAPIServiceName,
		a.cfg.InstallNamespace,
		selector,
		labels,
		"grpc",
		"grpc-port",
		pkgcommon.FalconServiceHTTPSPort,
	)
}

// reconcileWebhookService returns true if the service was updated, which requires a pod restart.
func (a *Admission) reconcileWebhookService(ctx context.Context) (bool, error) {
	svc := a.webhookService()
	existing := &corev1.Service{}
	found, err := k8sutils.GetOrCreate(ctx, a.r, a.cfg.Request, a.cfg.Owner, a.cfg.Status, svc, existing,
		types.NamespacedName{Name: pkgcommon.AdmissionWebhookServiceName, Namespace: a.cfg.InstallNamespace},
		"Failed to get FalconClusterGuard webhook Service")
	if !found || err != nil {
		return false, err
	}
	if !reflect.DeepEqual(svc.Spec.Ports, existing.Spec.Ports) || !reflect.DeepEqual(svc.Spec.Selector, existing.Spec.Selector) {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(),
				types.NamespacedName{Name: pkgcommon.AdmissionWebhookServiceName, Namespace: a.cfg.InstallNamespace},
				existing); err != nil {
				return err
			}
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard Service: ports or selector changed", "service", pkgcommon.AdmissionWebhookServiceName)
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
		types.NamespacedName{Name: pkgcommon.AdmissionAPIServiceName, Namespace: a.cfg.InstallNamespace},
		"Failed to get FalconClusterGuard API Service")
	if !found || err != nil {
		return false, err
	}
	if !reflect.DeepEqual(svc.Spec.Ports, existing.Spec.Ports) || !reflect.DeepEqual(svc.Spec.Selector, existing.Spec.Selector) {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(),
				types.NamespacedName{Name: pkgcommon.AdmissionAPIServiceName, Namespace: a.cfg.InstallNamespace},
				existing); err != nil {
				return err
			}
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard Service: ports or selector changed", "service", pkgcommon.AdmissionAPIServiceName)
			existing.Spec.Ports = svc.Spec.Ports
			existing.Spec.Selector = svc.Spec.Selector
			existing.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Service"))
			return k8sutils.Update(a.r, ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, existing)
		})
		return err == nil, err
	}
	return false, nil
}
