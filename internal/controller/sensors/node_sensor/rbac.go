package node_sensor

import (
	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// ClusterGuardSensorServiceAccount builds the ServiceAccount for the node sensor.
func ClusterGuardSensorServiceAccount(namespace string) *corev1.ServiceAccount {
	return assets.ServiceAccount(common.ClusterGuardSensorServiceAccountName, namespace, common.ClusterGuardComponentName, nil, nil)
}

// ClusterGuardSensorClusterRoleBinding builds the ClusterRoleBinding for the node sensor.
func ClusterGuardSensorClusterRoleBinding(namespace string) *rbacv1.ClusterRoleBinding {
	return assets.ClusterRoleBinding(
		common.ClusterGuardSensorClusterRoleBindingName,
		namespace,
		common.ClusterGuardSensorClusterRoleName,
		common.ClusterGuardSensorServiceAccountName,
		common.ClusterGuardComponentName,
		[]rbacv1.Subject{},
	)
}

// ClusterGuardSensorCleanupServiceAccount builds the ServiceAccount for the node sensor cleanup DaemonSet.
func ClusterGuardSensorCleanupServiceAccount(namespace string) *corev1.ServiceAccount {
	return assets.ServiceAccount(common.ClusterGuardSensorCleanupServiceAccountName, namespace, common.ClusterGuardComponentName, nil, nil)
}
