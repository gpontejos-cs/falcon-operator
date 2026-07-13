package admission

import (
	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
)

// webhookService builds the Service that exposes the admission webhook.
func (a *Admission) webhookService() *corev1.Service {
	selector := map[string]string{"app": common.ClusterGuardDeploymentName}
	labels := map[string]string{"app": common.ClusterGuardDeploymentName}

	return assets.ServiceWithCustomLabels(
		common.ClusterGuardWebhookServiceName,
		a.cfg.InstallNamespace,
		selector,
		labels,
		common.FalconServiceHTTPSName,
		"webhook-port",
		common.FalconServiceHTTPSPort,
	)
}

// apiService builds the Service that exposes the gRPC API.
func (a *Admission) apiService() *corev1.Service {
	selector := map[string]string{"app": common.ClusterGuardDeploymentName}
	labels := map[string]string{"app": common.ClusterGuardDeploymentName}

	return assets.ServiceWithCustomLabels(
		common.ClusterGuardAPIServiceName,
		a.cfg.InstallNamespace,
		selector,
		labels,
		"grpc",
		"grpc-port",
		common.FalconServiceHTTPSPort,
	)
}
