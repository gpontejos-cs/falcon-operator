package controllers

import (
	"context"
	"reflect"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

func (r *FalconCloudGuardReconciler) reconcileWebhookService(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) error {
	selector := map[string]string{"app": common.CloudGuardDeploymentName}
	labels := map[string]string{"app": common.CloudGuardDeploymentName}

	svc := assets.ServiceWithCustomLabels(
		common.CloudGuardWebhookServiceName,
		fcg.Spec.InstallNamespace,
		selector,
		labels,
		common.FalconServiceHTTPSName,
		"webhook-port",
		common.FalconServiceHTTPSPort,
	)
	existing := &corev1.Service{}

	err := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardWebhookServiceName, Namespace: fcg.Spec.InstallNamespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		return k8sutils.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, svc)
	} else if err != nil {
		log.Error(err, "Failed to get FalconCloudGuard webhook Service")
		return err
	}

	if !reflect.DeepEqual(svc.Spec.Ports, existing.Spec.Ports) || !reflect.DeepEqual(svc.Spec.Selector, existing.Spec.Selector) {
		existing.Spec.Ports = svc.Spec.Ports
		existing.Spec.Selector = svc.Spec.Selector
		existing.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Service"))
		return k8sutils.Update(r.Client, ctx, req, log, fcg, &fcg.Status, existing)
	}

	return nil
}

func (r *FalconCloudGuardReconciler) reconcileAPIService(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) error {
	selector := map[string]string{"app": common.CloudGuardDeploymentName}
	labels := map[string]string{"app": common.CloudGuardDeploymentName}

	svc := assets.ServiceWithCustomLabels(
		common.CloudGuardAPIServiceName,
		fcg.Spec.InstallNamespace,
		selector,
		labels,
		"grpc",
		"grpc-port",
		common.FalconServiceHTTPSPort,
	)
	existing := &corev1.Service{}

	err := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardAPIServiceName, Namespace: fcg.Spec.InstallNamespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		return k8sutils.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, svc)
	} else if err != nil {
		log.Error(err, "Failed to get FalconCloudGuard API Service")
		return err
	}

	if !reflect.DeepEqual(svc.Spec.Ports, existing.Spec.Ports) || !reflect.DeepEqual(svc.Spec.Selector, existing.Spec.Selector) {
		existing.Spec.Ports = svc.Spec.Ports
		existing.Spec.Selector = svc.Spec.Selector
		existing.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Service"))
		return k8sutils.Update(r.Client, ctx, req, log, fcg, &fcg.Status, existing)
	}

	return nil
}
