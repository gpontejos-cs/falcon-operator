package node_sensor

import (
	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// serviceAccount builds the ServiceAccount for the node sensor.
func (n *NodeSensor) serviceAccount() *corev1.ServiceAccount {
	return assets.ServiceAccount(common.ClusterGuardSensorServiceAccountName, n.cfg.InstallNamespace, common.ClusterGuardComponentName, nil, nil)
}

// clusterRoleBinding builds the ClusterRoleBinding for the node sensor.
func (n *NodeSensor) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return assets.ClusterRoleBinding(
		common.ClusterGuardSensorClusterRoleBindingName,
		n.cfg.InstallNamespace,
		common.ClusterGuardSensorClusterRoleName,
		common.ClusterGuardSensorServiceAccountName,
		common.ClusterGuardComponentName,
		[]rbacv1.Subject{},
	)
}

// cleanupServiceAccount builds the ServiceAccount for the node sensor cleanup DaemonSet.
func (n *NodeSensor) cleanupServiceAccount() *corev1.ServiceAccount {
	return assets.ServiceAccount(common.ClusterGuardSensorCleanupServiceAccountName, n.cfg.InstallNamespace, common.ClusterGuardComponentName, nil, nil)
}
