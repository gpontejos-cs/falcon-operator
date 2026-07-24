package admission_test

import (
	"testing"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	"github.com/crowdstrike/falcon-operator/internal/controller/sensors/admission"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
)

func TestClusterGuardDeploymentReturnsDeployment(t *testing.T) {
	// Default prefix is "falcon-clusterguard" when NamePrefix is empty
	name := "falcon-clusterguard"
	namespace := "falcon-clusterguard"
	imageUri := "quay.io/crowdstrike/falcon-clusterguard:latest"
	imagePullPolicy := corev1.PullIfNotPresent
	imagePullSecrets := []corev1.LocalObjectReference{{Name: "mysecret"}}

	a := admission.New(nil, admission.Config{
		InstallNamespace: namespace,
		Image:            imageUri,
		ImagePullPolicy:  imagePullPolicy,
		ImagePullSecrets: imagePullSecrets,
	})
	dep := a.Deployment()

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

func TestClusterGuardDeploymentUsesNamePrefix(t *testing.T) {
	prefix := "my-custom-guard"
	namespace := "test-ns"
	imageUri := "quay.io/crowdstrike/falcon-clusterguard:latest"

	a := admission.New(nil, admission.Config{
		InstallNamespace: namespace,
		Image:            imageUri,
		NamePrefix:       prefix,
	})
	dep := a.Deployment()

	if dep == nil {
		t.Fatal("expected non-nil Deployment")
	}
	if dep.Name != prefix {
		t.Errorf("expected deployment name %q, got %q", prefix, dep.Name)
	}
	// SA name should be derived from prefix
	expectedSA := prefix + "-sa"
	if dep.Spec.Template.Spec.ServiceAccountName != expectedSA {
		t.Errorf("expected ServiceAccountName %q, got %q", expectedSA, dep.Spec.Template.Spec.ServiceAccountName)
	}
	// TLS volume should reference prefix-derived secret
	expectedTLSSecretName := prefix + "-tls"
	foundTLS := false
	for _, v := range dep.Spec.Template.Spec.Volumes {
		if v.VolumeSource.Secret != nil && v.VolumeSource.Secret.SecretName == expectedTLSSecretName {
			foundTLS = true
		}
	}
	if !foundTLS {
		t.Errorf("expected TLS secret name %q in volumes, not found", expectedTLSSecretName)
	}
	// ConfigMap reference should use prefix-derived name
	expectedCM := prefix + "-config"
	foundCM := false
	for _, c := range dep.Spec.Template.Spec.Containers {
		for _, ef := range c.EnvFrom {
			if ef.ConfigMapRef != nil && ef.ConfigMapRef.Name == expectedCM {
				foundCM = true
			}
		}
	}
	if !foundCM {
		t.Errorf("expected ConfigMap name %q in container envFrom, not found", expectedCM)
	}
}

func TestClusterGuardValidatingWebhookReturnsWebhook(t *testing.T) {
	namespace := "falcon-clusterguard"
	caBundle := []byte("fake-ca")
	extraDisabledNamespaces := []string{"kube-system"}

	a := admission.New(nil, admission.Config{
		InstallNamespace: namespace,
		AdmissionConfig: falconv1alpha1.FalconAdmissionBaseConfig{
			DisabledNamespaces: falconv1alpha1.FalconAdmissionNamespace{
				Namespaces: extraDisabledNamespaces,
			},
		},
	})
	webhook := a.ValidatingWebhook(caBundle)

	if webhook == nil {
		t.Fatal("expected non-nil ValidatingWebhookConfiguration")
	}
	if webhook.Name != common.AdmissionValidatingWebhookName {
		t.Errorf("expected name %q, got %q", common.AdmissionValidatingWebhookName, webhook.Name)
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

	a := admission.New(nil, admission.Config{
		InstallNamespace: namespace,
		AdmissionConfig: falconv1alpha1.FalconAdmissionBaseConfig{
			DisabledNamespaces: falconv1alpha1.FalconAdmissionNamespace{
				Namespaces: extraDisabledNamespaces,
			},
		},
	})
	webhook := a.ValidatingWebhook(caBundle)

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
