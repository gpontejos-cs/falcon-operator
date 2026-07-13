package admission

import (
	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// serviceAccount builds the ServiceAccount for the FalconClusterGuard admission controller.
func (a *Admission) serviceAccount() *corev1.ServiceAccount {
	return assets.ServiceAccount(common.ClusterGuardServiceAccountName, a.cfg.InstallNamespace, common.ClusterGuardComponentName, nil, nil)
}

// clusterRoleBinding builds the ClusterRoleBinding for the FalconClusterGuard admission controller.
func (a *Admission) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return assets.ClusterRoleBinding(
		common.ClusterGuardClusterRoleBindingName,
		a.cfg.InstallNamespace,
		common.ClusterGuardClusterRoleName,
		common.ClusterGuardServiceAccountName,
		common.ClusterGuardComponentName,
		[]rbacv1.Subject{},
	)
}

// roleBinding builds the RoleBinding for the FalconClusterGuard admission controller.
func (a *Admission) roleBinding() *rbacv1.RoleBinding {
	return assets.RoleBinding(common.ClusterGuardRoleBindingName, a.cfg.InstallNamespace, common.ClusterGuardRoleName, common.ClusterGuardServiceAccountName)
}
