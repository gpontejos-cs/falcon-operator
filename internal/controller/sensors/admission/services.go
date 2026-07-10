package admission

import (
	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
)

// ClusterGuardWebhookService builds the Service that exposes the admission webhook.
func ClusterGuardWebhookService(namespace string) *corev1.Service {
	selector := map[string]string{"app": common.ClusterGuardDeploymentName}
	labels := map[string]string{"app": common.ClusterGuardDeploymentName}

	return assets.ServiceWithCustomLabels(
		common.ClusterGuardWebhookServiceName,
		namespace,
		selector,
		labels,
		common.FalconServiceHTTPSName,
		"webhook-port",
		common.FalconServiceHTTPSPort,
	)
}

// ClusterGuardAPIService builds the Service that exposes the gRPC API.
func ClusterGuardAPIService(namespace string) *corev1.Service {
	selector := map[string]string{"app": common.ClusterGuardDeploymentName}
	labels := map[string]string{"app": common.ClusterGuardDeploymentName}

	return assets.ServiceWithCustomLabels(
		common.ClusterGuardAPIServiceName,
		namespace,
		selector,
		labels,
		"grpc",
		"grpc-port",
		common.FalconServiceHTTPSPort,
	)
}
