package falcon

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	internalErrors "github.com/crowdstrike/falcon-operator/internal/errors"
	"github.com/crowdstrike/falcon-operator/pkg/falcon_secret"
	"github.com/crowdstrike/falcon-operator/version"
)

// FalconSensorUpdatePolicyReconciler reconciles a FalconSensorUpdatePolicy object
type FalconSensorUpdatePolicyReconciler struct {
	client.Client
	Reader client.Reader
	Scheme *runtime.Scheme
}

func (r *FalconSensorUpdatePolicyReconciler) GetK8sClient() client.Client {
	return r.Client
}

func (r *FalconSensorUpdatePolicyReconciler) GetK8sReader() client.Reader {
	return r.Reader
}

// +kubebuilder:rbac:groups=falcon.crowdstrike.com,resources=falconsensorupdatepolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=falcon.crowdstrike.com,resources=falconsensorupdatepolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=falcon.crowdstrike.com,resources=falconsensorupdatepolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

func (r *FalconSensorUpdatePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	instance := &falconv1alpha1.FalconSensorUpdatePolicy{}
	if err := r.Get(ctx, req.NamespacedName, instance); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	apiConfig, err := r.falconApiConfig(ctx, instance)
	if err != nil {
		logger.Error(err, "failed to build Falcon API config")
		return ctrl.Result{}, err
	}

	info, err := getPolicyInfo(apiConfig, instance.Spec.SensorUpdatePolicy)
	if err != nil {
		logger.Error(err, "failed to get policy info", "policy", instance.Spec.SensorUpdatePolicy)
		return ctrl.Result{}, err
	}

	instance.Status.SensorVersion = info.sensorVersion
	instance.Status.UninstallProtection = info.uninstallProtection
	if err := r.Status().Update(ctx, instance); err != nil {
		logger.Error(err, "failed to update status")
		return ctrl.Result{}, err
	}

	logger.Info("updated status from policy", "policy", instance.Spec.SensorUpdatePolicy, "sensorVersion", info.sensorVersion, "uninstallProtection", info.uninstallProtection)

	interval := 10 * time.Minute
	if instance.Spec.PollingInterval != nil {
		interval = instance.Spec.PollingInterval.Duration
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

func (r *FalconSensorUpdatePolicyReconciler) falconApiConfig(ctx context.Context, instance *falconv1alpha1.FalconSensorUpdatePolicy) (*falcon.ApiConfig, error) {
	secret := &corev1.Secret{}
	falconSecret := instance.Spec.FalconSecret
	if err := r.Reader.Get(ctx, types.NamespacedName{Name: falconSecret.SecretName, Namespace: falconSecret.Namespace}, secret); err != nil {
		return nil, err
	}

	clientId, clientSecret := falcon_secret.GetFalconCredsFromSecret(secret)
	if strings.TrimSpace(clientId) == "" || strings.TrimSpace(clientSecret) == "" {
		return nil, internalErrors.ErrMissingFalconAPICredentialsInSecret
	}

	return &falcon.ApiConfig{
		ClientId:          clientId,
		ClientSecret:      clientSecret,
		Context:           ctx,
		HostOverride:      instance.Spec.HostOverride,
		UserAgentOverride: fmt.Sprintf("falcon-operator/%s", version.Version),
	}, nil
}

type policyInfo struct {
	sensorVersion       string
	uninstallProtection string
}

func getPolicyInfo(apiConfig *falcon.ApiConfig, policyName string) (policyInfo, error) {
	apiClient, err := falcon.NewClient(apiConfig)
	if err != nil {
		return policyInfo{}, err
	}

	filter := fmt.Sprintf(`platform_name:"Linux"+name.raw:"%s"`, policyName)
	queryResp, err := apiClient.SensorUpdatePolicies.QuerySensorUpdatePolicies(
		sensor_update_policies.NewQuerySensorUpdatePoliciesParams().WithFilter(&filter),
	)
	if err != nil {
		return policyInfo{}, err
	}

	ids := make([]string, 0)
	for _, id := range queryResp.Payload.Resources {
		if id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return policyInfo{}, fmt.Errorf("sensor update policy %q not found", policyName)
	}

	getResp, err := apiClient.SensorUpdatePolicies.GetSensorUpdatePoliciesV2(
		sensor_update_policies.NewGetSensorUpdatePoliciesV2Params().WithIds([]string{ids[0]}),
	)
	if err != nil {
		return policyInfo{}, err
	}

	if len(getResp.Payload.Resources) == 0 {
		return policyInfo{}, fmt.Errorf("sensor update policy %q not found", policyName)
	}

	policy := getResp.Payload.Resources[0]
	if policy.Settings == nil {
		return policyInfo{}, fmt.Errorf("sensor update policy %q has no settings", policyName)
	}

	var sensorVersion, uninstallProtection string
	if policy.Settings.SensorVersion != nil {
		sensorVersion = *policy.Settings.SensorVersion
	}
	if policy.Settings.UninstallProtection != nil {
		uninstallProtection = *policy.Settings.UninstallProtection
	}

	return policyInfo{
		sensorVersion:       sensorVersion,
		uninstallProtection: uninstallProtection,
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *FalconSensorUpdatePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&falconv1alpha1.FalconSensorUpdatePolicy{}).
		Named("falconsensorupdatepolicy").
		Complete(r)
}
