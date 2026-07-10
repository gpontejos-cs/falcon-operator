package admission

import (
	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// ClusterGuardServiceAccount builds the ServiceAccount for the FalconClusterGuard admission controller.
func ClusterGuardServiceAccount(namespace string) *corev1.ServiceAccount {
	return assets.ServiceAccount(common.ClusterGuardServiceAccountName, namespace, common.ClusterGuardComponentName, nil, nil)
}

// ClusterGuardClusterRoleBinding builds the ClusterRoleBinding for the FalconClusterGuard admission controller.
func ClusterGuardClusterRoleBinding(namespace string) *rbacv1.ClusterRoleBinding {
	return assets.ClusterRoleBinding(
		common.ClusterGuardClusterRoleBindingName,
		namespace,
		common.ClusterGuardClusterRoleName,
		common.ClusterGuardServiceAccountName,
		common.ClusterGuardComponentName,
		[]rbacv1.Subject{},
	)
}

// ClusterGuardRoleBinding builds the RoleBinding for the FalconClusterGuard admission controller.
func ClusterGuardRoleBinding(namespace string) *rbacv1.RoleBinding {
	return assets.RoleBinding(common.ClusterGuardRoleBindingName, namespace, common.ClusterGuardRoleName, common.ClusterGuardServiceAccountName)
}
