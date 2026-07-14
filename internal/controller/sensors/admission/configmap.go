package admission

import (
	"context"
	"reflect"
	"strconv"

	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	pkgcommon "github.com/crowdstrike/falcon-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
)

// configMap builds the ConfigMap for the FalconClusterGuard admission controller.
func (a *Admission) configMap() *corev1.ConfigMap {
	cfg := a.cfg.AdmissionConfig
	data := map[string]string{
		"FALCON_MODE":                    "kac",
		"WEBHOOK_PORT":                   pkgcommon.ClusterGuardWebhookPortStr,
		"GRPC_PORT":                      pkgcommon.ClusterGuardGRPCPortStr,
		"WATCHER_HTTP_PORT":              pkgcommon.ClusterGuardWatcherHTTPPortStr,
		"__CS_ADMISSION_CONTROL_ENABLED": strconv.FormatBool(cfg.AdmissionControlEnabled != nil && *cfg.AdmissionControlEnabled),
		"__CS_WATCH_EVENTS_ENABLED":      strconv.FormatBool(cfg.GetWatcherEnabled()),
		"__CS_SNAPSHOTS_ENABLED":         strconv.FormatBool(cfg.GetSnapshotsEnabled()),
		"__CS_SNAPSHOT_INTERVAL":         cfg.GetSnapshotsInterval().String(),
		"FALCONCTL_OPT_CID":              a.cfg.Cid,
	}

	return assets.SensorConfigMap(pkgcommon.ClusterGuardConfigMapName, a.cfg.InstallNamespace, pkgcommon.ClusterGuardComponentName, data)
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

// reconcileConfigMap reconciles the admission controller ConfigMap.
func (a *Admission) reconcileConfigMap(ctx context.Context) (bool, error) {
	cm := a.configMap()
	return a.syncConfigMap(ctx, cm, "FalconClusterGuard")
}
