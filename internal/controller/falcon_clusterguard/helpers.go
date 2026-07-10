package controllers

import (
	"context"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
)

func (r *FalconClusterGuardReconciler) injectFalconSecretData(ctx context.Context, fcg *falconv1alpha1.FalconClusterGuard) error {
	r.log.Info("Injecting Falcon secret data into Spec.FalconAPI - sensitive manifest values will be overwritten with values in k8s secret")
	return k8sutils.InjectFalconSecretData(ctx, r, fcg)
}
