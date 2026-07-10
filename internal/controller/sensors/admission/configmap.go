package admission

import (
	"strconv"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
)

// ClusterGuardConfigMap builds the ConfigMap for the FalconClusterGuard admission controller.
func ClusterGuardConfigMap(namespace string, cfg falconv1alpha1.FalconAdmissionConfigSpec) *corev1.ConfigMap {
	data := map[string]string{
		"FALCON_MODE":                    "kac",
		"WEBHOOK_PORT":                   common.ClusterGuardWebhookPortStr,
		"GRPC_PORT":                      common.ClusterGuardGRPCPortStr,
		"WATCHER_HTTP_PORT":              common.ClusterGuardWatcherHTTPPortStr,
		"__CS_ADMISSION_CONTROL_ENABLED": strconv.FormatBool(cfg.AdmissionControlEnabled != nil && *cfg.AdmissionControlEnabled),
		"__CS_WATCH_EVENTS_ENABLED":      strconv.FormatBool(cfg.GetWatcherEnabled()),
		"__CS_SNAPSHOTS_ENABLED":         strconv.FormatBool(cfg.GetSnapshotsEnabled()),
		"__CS_SNAPSHOT_INTERVAL":         cfg.GetSnapshotsInterval().String(),
	}

	return assets.SensorConfigMap(common.ClusterGuardConfigMapName, namespace, common.ClusterGuardComponentName, data)
}
