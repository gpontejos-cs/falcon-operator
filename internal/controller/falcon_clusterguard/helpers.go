package controllers

import (
	"context"
	"reflect"
	"strings"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	"github.com/crowdstrike/falcon-operator/pkg/registry/pulltoken"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

func (r *FalconClusterGuardReconciler) injectFalconSecretData(ctx context.Context, fcg *falconv1alpha1.FalconClusterGuard) error {
	r.log.Info("Injecting Falcon secret data into Spec.FalconAPI - sensitive manifest values will be overwritten with values in k8s secret")
	return k8sutils.InjectFalconSecretData(ctx, r, fcg)
}

// isCrowdStrikeRegistry reports whether imageURI references a CrowdStrike-owned registry.
func isCrowdStrikeRegistry(imageURI string) bool {
	host := strings.SplitN(imageURI, "/", 2)[0]
	return strings.Contains(host, "crowdstrike.com") || strings.Contains(host, "crowdstrike.mil")
}

// reconcileImagePullSecret creates or updates the CrowdStrike registry pull secret in the
// install namespace so that pods can authenticate to pull images.
func (r *FalconClusterGuardReconciler) reconcileImagePullSecret(ctx context.Context, req ctrl.Request, fcg *falconv1alpha1.FalconClusterGuard) error {
	token, err := pulltoken.CrowdStrike(ctx, r.apiConfig)
	if err != nil {
		r.log.Error(err, "Failed to get CrowdStrike registry pull token")
		return err
	}

	secretData := map[string][]byte{corev1.DockerConfigJsonKey: common.CleanDecodedBase64(token)}
	desired := assets.Secret(common.FalconPullSecretName, fcg.Spec.InstallNamespace, "falcon-operator", secretData, corev1.SecretTypeDockerConfigJson)

	existing := &corev1.Secret{}
	err = common.GetWithFallback(ctx, r.Client, r.Reader,
		types.NamespacedName{Name: common.FalconPullSecretName, Namespace: fcg.Spec.InstallNamespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		return k8sutils.Create(r.Client, r.RuntimeScheme, ctx, req, r.log, fcg, &fcg.Status, desired)
	} else if err != nil {
		r.log.Error(err, "Failed to get FalconClusterGuard registry pull secret")
		return err
	}

	if !reflect.DeepEqual(desired.Data, existing.Data) {
		existing.Data = desired.Data
		existing.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Secret"))
		return k8sutils.Update(r.Client, ctx, req, r.log, fcg, &fcg.Status, existing)
	}
	return nil
}
