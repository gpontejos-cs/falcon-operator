package admission

import (
	"strconv"

	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
)

// configMap builds the ConfigMap for the FalconClusterGuard admission controller.
func (a *Admission) configMap() *corev1.ConfigMap {
	cfg := a.cfg.AdmissionConfig
	data := map[string]string{
		"FALCON_MODE":                    "kac",
		"WEBHOOK_PORT":                   common.ClusterGuardWebhookPortStr,
		"GRPC_PORT":                      common.ClusterGuardGRPCPortStr,
		"WATCHER_HTTP_PORT":              common.ClusterGuardWatcherHTTPPortStr,
		"__CS_ADMISSION_CONTROL_ENABLED": strconv.FormatBool(cfg.AdmissionControlEnabled != nil && *cfg.AdmissionControlEnabled),
		"__CS_WATCH_EVENTS_ENABLED":      strconv.FormatBool(cfg.GetWatcherEnabled()),
		"__CS_SNAPSHOTS_ENABLED":         strconv.FormatBool(cfg.GetSnapshotsEnabled()),
		"__CS_SNAPSHOT_INTERVAL":         cfg.GetSnapshotsInterval().String(),
		"FALCONCTL_OPT_CID":              a.cfg.Cid,
	}

	return assets.SensorConfigMap(common.ClusterGuardConfigMapName, a.cfg.InstallNamespace, common.ClusterGuardComponentName, data)
}
