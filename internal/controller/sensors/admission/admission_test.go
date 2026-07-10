package admission_test

import (
	"testing"

	"github.com/crowdstrike/falcon-operator/internal/controller/sensors/admission"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
)

func TestClusterGuardDeploymentReturnsDeployment(t *testing.T) {
	name := common.ClusterGuardDeploymentName
	namespace := "falcon-clusterguard"
	imageUri := "quay.io/crowdstrike/falcon-clusterguard:latest"
	imagePullPolicy := corev1.PullIfNotPresent
	imagePullSecrets := []corev1.LocalObjectReference{{Name: "mysecret"}}

	dep := admission.ClusterGuardDeployment(name, namespace, imageUri, imagePullPolicy, imagePullSecrets)

	if dep == nil {
		t.Fatal("expected non-nil Deployment")
	}
	if dep.Name != name {
		t.Errorf("expected name %q, got %q", name, dep.Name)
	}
	if dep.Namespace != namespace {
		t.Errorf("expected namespace %q, got %q", namespace, dep.Namespace)
	}
	if len(dep.Spec.Template.Spec.Containers) != 3 {
		t.Errorf("expected 3 containers, got %d", len(dep.Spec.Template.Spec.Containers))
	}
	if dep.Spec.Template.Spec.Containers[0].Image != imageUri {
		t.Errorf("expected image %q, got %q", imageUri, dep.Spec.Template.Spec.Containers[0].Image)
	}
}

func TestClusterGuardValidatingWebhookReturnsWebhook(t *testing.T) {
	namespace := "falcon-clusterguard"
	caBundle := []byte("fake-ca")
	extraDisabledNamespaces := []string{"kube-system"}

	webhook := admission.ClusterGuardValidatingWebhook(namespace, caBundle, extraDisabledNamespaces)

	if webhook == nil {
		t.Fatal("expected non-nil ValidatingWebhookConfiguration")
	}
	if webhook.Name != common.ClusterGuardValidatingWebhookName {
		t.Errorf("expected name %q, got %q", common.ClusterGuardValidatingWebhookName, webhook.Name)
	}
	if len(webhook.Webhooks) != 3 {
		t.Errorf("expected 3 webhooks, got %d", len(webhook.Webhooks))
	}
}

func TestClusterGuardValidatingWebhookDeduplicatesNamespaces(t *testing.T) {
	namespace := "falcon-clusterguard"
	caBundle := []byte("fake-ca")
	// Pass a duplicate of a default disabled namespace
	extraDisabledNamespaces := []string{namespace, namespace}

	webhook := admission.ClusterGuardValidatingWebhook(namespace, caBundle, extraDisabledNamespaces)

	if webhook == nil {
		t.Fatal("expected non-nil ValidatingWebhookConfiguration")
	}
	// The main webhook's namespace selector values should not have duplicates
	nsSelector := webhook.Webhooks[0].NamespaceSelector
	if nsSelector == nil || len(nsSelector.MatchExpressions) == 0 {
		t.Fatal("expected namespace selector with match expressions")
	}
	values := nsSelector.MatchExpressions[0].Values
	seen := map[string]int{}
	for _, v := range values {
		seen[v]++
		if seen[v] > 1 {
			t.Errorf("duplicate namespace %q found in selector values", v)
		}
	}
}
