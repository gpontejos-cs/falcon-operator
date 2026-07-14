package admission

import (
	"context"
	"reflect"

	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	pkgcommon "github.com/crowdstrike/falcon-operator/pkg/common"
	arv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
)

// ValidatingWebhook builds the ValidatingWebhookConfiguration for FalconClusterGuard
// with three webhooks: pod admission, workload admission, and a test webhook.
func (a *Admission) ValidatingWebhook(caBundle []byte) *arv1.ValidatingWebhookConfiguration {
	namespace := a.cfg.InstallNamespace
	extraDisabledNamespaces := a.cfg.AdmissionConfig.DisabledNamespaces.Namespaces
	failurePolicy := arv1.Ignore
	matchPolicy := arv1.Equivalent
	sideEffects := arv1.SideEffectClassNone
	timeoutSeconds := int32(10)
	excludeOp := metav1.LabelSelectorOpNotIn
	scope := arv1.AllScopes
	webhookName := pkgcommon.ClusterGuardValidatingWebhookName
	path := "/validate"
	port := int32(443)

	excludedNamespaces := append(pkgcommon.DefaultDisabledNamespaces,
		namespace,
		"falcon-system",
		"falcon-kubernetes-protection",
	)
	excludedNamespaces = append(excludedNamespaces, extraDisabledNamespaces...)
	// deduplicate
	seen := map[string]struct{}{}
	unique := excludedNamespaces[:0]
	for _, ns := range excludedNamespaces {
		if _, ok := seen[ns]; !ok {
			seen[ns] = struct{}{}
			unique = append(unique, ns)
		}
	}
	excludedNamespaces = unique

	namespaceSelector := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "kubernetes.io/metadata.name",
				Operator: excludeOp,
				Values:   excludedNamespaces,
			},
		},
	}

	testNamespaceSelector := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "kubernetes.io/metadata.name",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"falcon-clusterguard-test"},
			},
		},
	}

	return &arv1.ValidatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: arv1.SchemeGroupVersion.String(),
			Kind:       "ValidatingWebhookConfiguration",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: webhookName,
			Labels: map[string]string{
				"app":                            pkgcommon.ClusterGuardDeploymentName,
				pkgcommon.KubernetesNameKey:      pkgcommon.ClusterGuardDeploymentName,
				pkgcommon.KubernetesComponentKey: pkgcommon.ClusterGuardComponentName,
				pkgcommon.FalconProviderKey:      pkgcommon.FalconProviderValue,
			},
		},
		Webhooks: []arv1.ValidatingWebhook{
			{
				Name:                    webhookName,
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             &sideEffects,
				FailurePolicy:           &failurePolicy,
				MatchPolicy:             &matchPolicy,
				TimeoutSeconds:          &timeoutSeconds,
				ClientConfig: arv1.WebhookClientConfig{
					CABundle: caBundle,
					Service: &arv1.ServiceReference{
						Name:      pkgcommon.ClusterGuardWebhookServiceName,
						Namespace: namespace,
						Path:      &path,
						Port:      &port,
					},
				},
				NamespaceSelector: namespaceSelector,
				Rules: []arv1.RuleWithOperations{
					{
						Operations: []arv1.OperationType{arv1.Create, arv1.Update},
						Rule: arv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods", "pods/ephemeralcontainers"},
							Scope:       &scope,
						},
					},
				},
			},
			{
				Name:                    "workload." + webhookName,
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             &sideEffects,
				FailurePolicy:           &failurePolicy,
				MatchPolicy:             &matchPolicy,
				TimeoutSeconds:          &timeoutSeconds,
				ClientConfig: arv1.WebhookClientConfig{
					CABundle: caBundle,
					Service: &arv1.ServiceReference{
						Name:      pkgcommon.ClusterGuardWebhookServiceName,
						Namespace: namespace,
						Path:      &path,
						Port:      &port,
					},
				},
				NamespaceSelector: namespaceSelector,
				Rules: []arv1.RuleWithOperations{
					{
						Operations: []arv1.OperationType{arv1.Create, arv1.Update},
						Rule: arv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"replicationcontrollers", "services"},
							Scope:       &scope,
						},
					},
					{
						Operations: []arv1.OperationType{arv1.Create, arv1.Update},
						Rule: arv1.Rule{
							APIGroups:   []string{"apps"},
							APIVersions: []string{"v1"},
							Resources:   []string{"daemonsets", "deployments", "replicasets", "statefulsets"},
							Scope:       &scope,
						},
					},
					{
						Operations: []arv1.OperationType{arv1.Create, arv1.Update},
						Rule: arv1.Rule{
							APIGroups:   []string{"batch"},
							APIVersions: []string{"v1"},
							Resources:   []string{"cronjobs", "jobs"},
							Scope:       &scope,
						},
					},
				},
			},
			{
				Name:                    "test." + webhookName,
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             &sideEffects,
				FailurePolicy:           &failurePolicy,
				MatchPolicy:             &matchPolicy,
				TimeoutSeconds:          &timeoutSeconds,
				ClientConfig: arv1.WebhookClientConfig{
					CABundle: caBundle,
					Service: &arv1.ServiceReference{
						Name:      pkgcommon.ClusterGuardWebhookServiceName,
						Namespace: namespace,
						Path:      &path,
						Port:      &port,
					},
				},
				NamespaceSelector: testNamespaceSelector,
				Rules: []arv1.RuleWithOperations{
					{
						Operations: []arv1.OperationType{arv1.Delete},
						Rule: arv1.Rule{
							APIGroups:   []string{"", "apps", "batch"},
							APIVersions: []string{"v1"},
							Resources: []string{
								"pods", "replicationcontrollers", "services",
								"deployments", "daemonsets", "replicasets", "statefulsets",
								"cronjobs", "jobs",
							},
							Scope: &scope,
						},
					},
				},
			},
		},
	}
}

// reconcileValidatingWebhook returns true if the webhook configuration was updated, which requires a pod restart.
func (a *Admission) reconcileValidatingWebhook(ctx context.Context, caBundle []byte) (bool, error) {
	webhook := a.ValidatingWebhook(caBundle)
	existing := &arv1.ValidatingWebhookConfiguration{}
	found, err := k8sutils.GetOrCreate(ctx, a.r, a.cfg.Request, a.cfg.Owner, a.cfg.Status, webhook, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardValidatingWebhookName},
		"Failed to get FalconClusterGuard ValidatingWebhookConfiguration")
	if !found || err != nil {
		return false, err
	}

	needsUpdate := len(webhook.Webhooks) != len(existing.Webhooks)
	if !needsUpdate && len(webhook.Webhooks) > 0 {
		if !reflect.DeepEqual(webhook.Webhooks[0].FailurePolicy, existing.Webhooks[0].FailurePolicy) {
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard ValidatingWebhookConfiguration: FailurePolicy changed",
				"old", existing.Webhooks[0].FailurePolicy,
				"new", webhook.Webhooks[0].FailurePolicy)
			needsUpdate = true
		}
		if !reflect.DeepEqual(webhook.Webhooks[0].ClientConfig, existing.Webhooks[0].ClientConfig) {
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard ValidatingWebhookConfiguration: ClientConfig changed")
			needsUpdate = true
		}
		if !reflect.DeepEqual(webhook.Webhooks[0].NamespaceSelector, existing.Webhooks[0].NamespaceSelector) {
			a.r.GetLog().V(1).Info("Updating FalconClusterGuard ValidatingWebhookConfiguration: NamespaceSelector changed")
			needsUpdate = true
		}
	}

	if needsUpdate {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(),
				types.NamespacedName{Name: pkgcommon.ClusterGuardValidatingWebhookName},
				existing); err != nil {
				return err
			}
			existing.Webhooks = webhook.Webhooks
			existing.SetGroupVersionKind(arv1.SchemeGroupVersion.WithKind("ValidatingWebhookConfiguration"))
			return k8sutils.Update(a.r, ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, existing)
		})
		return err == nil, err
	}
	return false, nil
}
