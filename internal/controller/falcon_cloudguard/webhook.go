package controllers

import (
	"context"
	"reflect"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	"github.com/go-logr/logr"
	arv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

func (r *FalconCloudGuardReconciler) reconcileValidatingWebhook(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard, caBundle []byte) error {
	webhook := cloudGuardValidatingWebhook(fcg.Spec.InstallNamespace, caBundle, fcg.Spec.CloudGuardConfig.DisabledNamespaces)
	existing := &arv1.ValidatingWebhookConfiguration{}

	err := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardValidatingWebhookName}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		return k8sutils.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, webhook)
	} else if err != nil {
		log.Error(err, "Failed to get FalconCloudGuard ValidatingWebhookConfiguration")
		return err
	}

	if !reflect.DeepEqual(webhook.Webhooks, existing.Webhooks) {
		existing.Webhooks = webhook.Webhooks
		existing.SetGroupVersionKind(arv1.SchemeGroupVersion.WithKind("ValidatingWebhookConfiguration"))
		return k8sutils.Update(r.Client, ctx, req, log, fcg, &fcg.Status, existing)
	}

	return nil
}

// cloudGuardValidatingWebhook builds the ValidatingWebhookConfiguration for FalconCloudGuard
// with three webhooks: pod admission, workload admission, and a test webhook.
func cloudGuardValidatingWebhook(namespace string, caBundle []byte, extraDisabledNamespaces []string) *arv1.ValidatingWebhookConfiguration {
	failurePolicy := arv1.Ignore
	matchPolicy := arv1.Equivalent
	sideEffects := arv1.SideEffectClassNone
	timeoutSeconds := int32(10)
	excludeOp := metav1.LabelSelectorOpNotIn
	scope := arv1.AllScopes
	webhookName := common.CloudGuardValidatingWebhookName
	path := "/validate"
	port := int32(443)

	excludedNamespaces := append(common.DefaultDisabledNamespaces,
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
				"app":                         common.CloudGuardDeploymentName,
				common.KubernetesNameKey:      common.CloudGuardDeploymentName,
				common.KubernetesComponentKey: common.CloudGuardComponentName,
				common.FalconProviderKey:      common.FalconProviderValue,
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
						Name:      common.CloudGuardWebhookServiceName,
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
						Name:      common.CloudGuardWebhookServiceName,
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
						Name:      common.CloudGuardWebhookServiceName,
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
