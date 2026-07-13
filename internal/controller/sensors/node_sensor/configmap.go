package node_sensor

import (
	"fmt"

	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
)

// configMap builds the ConfigMap for the node sensor.
func (n *NodeSensor) configMap() *corev1.ConfigMap {
	apiServiceName := fmt.Sprintf("%s.%s.svc", common.ClusterGuardAPIServiceName, n.cfg.InstallNamespace)

	data := map[string]string{
		"FALCONCTL_OPT_TRACE":              "warn",
		"FALCONCTL_OPT_BACKEND":            "bpf",
		"FLOW_ENABLED":                     "false",
		"FALCON_MODE":                      "daemonset",
		"__CS_ENABLE_K8S_METADATA_SERVICE": "true",
		"API_SERVICE_NAME":                 apiServiceName,
	}

	if n.cfg.Cid != "" {
		data["FALCONCTL_OPT_CID"] = n.cfg.Cid
	}

	return assets.SensorConfigMap(common.ClusterGuardSensorConfigMapName, n.cfg.InstallNamespace, common.ClusterGuardComponentName, data)
}
