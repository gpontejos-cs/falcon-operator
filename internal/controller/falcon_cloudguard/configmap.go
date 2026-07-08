package controllers

import (
	"context"
	"reflect"
	"strconv"

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

func (r *FalconCloudGuardReconciler) reconcileConfigMap(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) error {
	data := map[string]string{
		"FALCON_MODE":                      "kac",
		"WEBHOOK_PORT":                     common.CloudGuardWebhookPortStr,
		"GRPC_PORT":                        common.CloudGuardGRPCPortStr,
		"WATCHER_HTTP_PORT":                common.CloudGuardWatcherHTTPPortStr,
		"__CS_ADMISSION_CONTROL_ENABLED":   strconv.FormatBool(fcg.Spec.CloudGuardConfig.GetAdmissionControlEnabled()),
		"__CS_WATCH_EVENTS_ENABLED":        strconv.FormatBool(fcg.Spec.CloudGuardConfig.GetWatchEventsEnabled()),
		"__CS_SNAPSHOTS_ENABLED":           strconv.FormatBool(fcg.Spec.CloudGuardConfig.GetSnapshotsEnabled()),
		"__CS_SNAPSHOT_INTERVAL":           fcg.Spec.CloudGuardConfig.GetSnapshotInterval().String(),
	}

	cm := assets.SensorConfigMap(common.CloudGuardConfigMapName, fcg.Spec.InstallNamespace, common.CloudGuardComponentName, data)
	existing := &corev1.ConfigMap{}

	err := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardConfigMapName, Namespace: fcg.Spec.InstallNamespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		return k8sutils.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, cm)
	} else if err != nil {
		log.Error(err, "Failed to get FalconCloudGuard ConfigMap")
		return err
	}

	if !reflect.DeepEqual(cm.Data, existing.Data) {
		for k, v := range cm.Data {
			if existing.Data[k] != v {
				log.V(1).Info("Updating FalconCloudGuard ConfigMap: value changed", "key", k, "old", existing.Data[k], "new", v)
			}
		}
		existing.Data = cm.Data
		existing.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
		return k8sutils.Update(r.Client, ctx, req, log, fcg, &fcg.Status, existing)
	}

	return nil
}
