package controllers

import (
	"context"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

func (r *FalconCloudGuardReconciler) reconcileNamespace(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) error {
	ns := assets.Namespace(fcg.Spec.InstallNamespace)
	existing := &corev1.Namespace{}

	err := r.Get(ctx, types.NamespacedName{Name: fcg.Spec.InstallNamespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		return k8sutils.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, ns)
	} else if err != nil {
		log.Error(err, "Failed to get FalconCloudGuard Namespace")
		return err
	}

	return nil
}
