package controllers

import (
	"context"
	"fmt"
	"reflect"
	"slices"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	commonctrl "github.com/crowdstrike/falcon-operator/internal/controller/common"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/labels"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *FalconCloudGuardReconciler) reconcileSensorServiceAccount(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) error {
	sa := assets.ServiceAccount(common.CloudGuardSensorServiceAccountName, fcg.Spec.InstallNamespace, common.CloudGuardComponentName, nil, nil)
	existing := &corev1.ServiceAccount{}

	err := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardSensorServiceAccountName, Namespace: fcg.Spec.InstallNamespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		return commonctrl.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, sa)
	} else if err != nil {
		log.Error(err, "Failed to get FalconCloudGuard sensor ServiceAccount")
		return err
	}

	return nil
}

func (r *FalconCloudGuardReconciler) reconcileSensorConfigMap(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) error {
	namespace := fcg.Spec.InstallNamespace
	apiServiceName := common.CloudGuardAPIServiceName + "." + namespace + ".svc"

	data := map[string]string{
		"FALCONCTL_OPT_TRACE":               "warn",
		"FALCONCTL_OPT_BACKEND":             "bpf",
		"FLOW_ENABLED":                      "false",
		"FALCON_MODE":                       "daemonset",
		"__CS_ENABLE_K8S_METADATA_SERVICE":  "true",
		"API_SERVICE_NAME":                  apiServiceName,
	}

	if fcg.Spec.FalconAPI != nil && fcg.Spec.FalconAPI.CID != nil {
		data["FALCONCTL_OPT_CID"] = *fcg.Spec.FalconAPI.CID
	}

	cm := assets.SensorConfigMap(common.CloudGuardSensorConfigMapName, namespace, common.CloudGuardComponentName, data)
	existing := &corev1.ConfigMap{}

	err := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardSensorConfigMapName, Namespace: namespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		return commonctrl.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, cm)
	} else if err != nil {
		log.Error(err, "Failed to get FalconCloudGuard sensor ConfigMap")
		return err
	}

	if !reflect.DeepEqual(cm.Data, existing.Data) {
		for k, v := range cm.Data {
			if existing.Data[k] != v {
				log.V(1).Info("Updating FalconCloudGuard sensor ConfigMap: value changed", "key", k, "old", existing.Data[k], "new", v)
			}
		}
		existing.Data = cm.Data
		existing.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
		return commonctrl.Update(r.Client, ctx, req, log, fcg, &fcg.Status, existing)
	}

	return nil
}

func (r *FalconCloudGuardReconciler) reconcileSensorClusterRoleBinding(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) error {
	crb := assets.ClusterRoleBinding(
		common.CloudGuardSensorClusterRoleBindingName,
		fcg.Spec.InstallNamespace,
		common.CloudGuardSensorClusterRoleName,
		common.CloudGuardSensorServiceAccountName,
		common.CloudGuardComponentName,
		[]rbacv1.Subject{},
	)
	existing := &rbacv1.ClusterRoleBinding{}

	err := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardSensorClusterRoleBindingName}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		return commonctrl.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, crb)
	} else if err != nil {
		log.Error(err, "Failed to get FalconCloudGuard sensor ClusterRoleBinding")
		return err
	}

	if !reflect.DeepEqual(crb.RoleRef, existing.RoleRef) {
		if err := commonctrl.Delete(r.Client, ctx, req, log, fcg, &fcg.Status, existing); err != nil {
			return err
		}
		return commonctrl.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, crb)
	} else if !reflect.DeepEqual(crb.Subjects, existing.Subjects) {
		existing.Subjects = crb.Subjects
		existing.SetGroupVersionKind(rbacv1.SchemeGroupVersion.WithKind("ClusterRoleBinding"))
		return commonctrl.Update(r.Client, ctx, req, log, fcg, &fcg.Status, existing)
	}

	return nil
}

func (r *FalconCloudGuardReconciler) reconcileSensorDaemonSet(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) error {
	ds := cloudGuardSensorDaemonSet(fcg)
	existing := &appsv1.DaemonSet{}

	err := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardSensorDaemonSetName, Namespace: fcg.Spec.InstallNamespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		return commonctrl.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, ds)
	} else if err != nil {
		log.Error(err, "Failed to get FalconCloudGuard sensor DaemonSet")
		return err
	}

	if !reflect.DeepEqual(ds.Spec.Template.Spec.Containers, existing.Spec.Template.Spec.Containers) ||
		!reflect.DeepEqual(ds.Spec.Template.Spec.InitContainers, existing.Spec.Template.Spec.InitContainers) ||
		!reflect.DeepEqual(ds.Spec.Template.Spec.Volumes, existing.Spec.Template.Spec.Volumes) {
		existing.Spec.Template.Spec.Containers = ds.Spec.Template.Spec.Containers
		existing.Spec.Template.Spec.InitContainers = ds.Spec.Template.Spec.InitContainers
		existing.Spec.Template.Spec.Volumes = ds.Spec.Template.Spec.Volumes
		existing.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("DaemonSet"))
		return commonctrl.Update(r.Client, ctx, req, log, fcg, &fcg.Status, existing)
	}

	return nil
}

func cloudGuardSensorDaemonSet(fcg *falconv1alpha1.FalconCloudGuard) *appsv1.DaemonSet {
	namespace := fcg.Spec.InstallNamespace
	nodeSpec := fcg.Spec.NodeSensor

	dsLabels := common.CRLabels("daemonset", common.CloudGuardSensorDaemonSetName, common.CloudGuardComponentName)
	privileged := true
	runAsUser := int64(0)
	hostPathType := corev1.HostPathFile

	imageUri := fcg.Spec.Image
	if imageUri == "" && fcg.Spec.FalconAPI != nil && fcg.Spec.FalconAPI.CID != nil {
		imageUri = *fcg.Spec.FalconAPI.CID
	}

	imagePullPolicy := fcg.Spec.ImagePullPolicy
	if imagePullPolicy == "" {
		imagePullPolicy = corev1.PullIfNotPresent
	}

	terminationGracePeriod := nodeSpec.TerminationGracePeriod
	if terminationGracePeriod == 0 {
		terminationGracePeriod = 60
	}

	tolerations := []corev1.Toleration{
		{Key: "node-role.kubernetes.io/master", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
		{Key: "node-role.kubernetes.io/control-plane", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
		{Key: "kubernetes.azure.com/scalesetpriority", Operator: corev1.TolerationOpEqual, Value: "spot", Effect: corev1.TaintEffectNoSchedule},
	}
	if nodeSpec.Tolerations != nil {
		tolerations = *nodeSpec.Tolerations
	}

	updateStrategy := appsv1.DaemonSetUpdateStrategy{Type: appsv1.RollingUpdateDaemonSetStrategyType}
	if nodeSpec.DSUpdateStrategy.Type != "" {
		updateStrategy.Type = nodeSpec.DSUpdateStrategy.Type
		ru := nodeSpec.DSUpdateStrategy.RollingUpdate
		updateStrategy.RollingUpdate = &ru
	}

	containerResources := corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("300m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}
	if nodeSpec.SensorResources.Limits.Memory != "" || nodeSpec.SensorResources.Requests.CPU != "" {
		containerResources = buildResourceRequirements(nodeSpec.SensorResources)
	}

	initArgs := []string{
		"-c",
		`set -e;
if [ ! -f /opt/CrowdStrike/falcon-daemonset-init ]; then
echo "Error: This is not a falcon node sensor(DaemonSet) image";
exit 1;
fi;
echo "Running /opt/CrowdStrike/falcon-daemonset-init -i";
/opt/CrowdStrike/falcon-daemonset-init -i;
if [ ! -f /opt/CrowdStrike/configure-cluster-id ]; then
echo "/opt/CrowdStrike/configure-cluster-id not found. Skipping.";
else
echo "Running /opt/CrowdStrike/configure-cluster-id";
/opt/CrowdStrike/configure-cluster-id;
fi`,
	}

	apiServiceName := common.CloudGuardAPIServiceName + "." + namespace + ".svc"

	podSpec := corev1.PodSpec{
		ServiceAccountName:            common.CloudGuardSensorServiceAccountName,
		TerminationGracePeriodSeconds: &terminationGracePeriod,
		HostNetwork:                   true,
		DNSPolicy:                     corev1.DNSClusterFirstWithHostNet,
		HostPID:                       true,
		HostIPC:                       true,
		ImagePullSecrets:              fcg.Spec.ImagePullSecrets,
		NodeSelector: map[string]string{
			"kubernetes.io/os": "linux",
		},
		SecurityContext: &corev1.PodSecurityContext{
			FSGroup: func() *int64 { g := int64(65534); return &g }(),
		},
		Tolerations: tolerations,
		InitContainers: []corev1.Container{
			{
				Name:            "init-falconstore",
				Image:           imageUri,
				ImagePullPolicy: imagePullPolicy,
				Command:         []string{"/bin/bash"},
				Args:            initArgs,
				SecurityContext: &corev1.SecurityContext{
					RunAsUser:                &runAsUser,
					Privileged:               &privileged,
					AllowPrivilegeEscalation: &privileged,
					ReadOnlyRootFilesystem:   func() *bool { b := false; return &b }(),
				},
				Env: []corev1.EnvVar{
					{Name: "POD_NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
					{Name: "API_SERVICE_NAME", Value: apiServiceName},
				},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "falcon-sensor-tls-certs", MountPath: "/run/secrets/tls", ReadOnly: true},
					{Name: "falcon-api-ca", MountPath: "/run/secrets/ca", ReadOnly: true},
				},
			},
		},
		Containers: []corev1.Container{
			{
				Name:            "falcon-node-sensor",
				Image:           imageUri,
				ImagePullPolicy: imagePullPolicy,
				SecurityContext: &corev1.SecurityContext{
					RunAsUser:                &runAsUser,
					Privileged:               &privileged,
					ReadOnlyRootFilesystem:   func() *bool { b := false; return &b }(),
					AllowPrivilegeEscalation: &privileged,
				},
				Resources: containerResources,
				Env: []corev1.EnvVar{
					{Name: "POD_NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
					{Name: "API_SERVICE_NAME", Value: apiServiceName},
				},
				EnvFrom: []corev1.EnvFromSource{
					{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: common.CloudGuardSensorConfigMapName}}},
				},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "falconstore", MountPath: "/opt/CrowdStrike/falconstore"},
					{Name: "falcon-sensor-tls-certs", MountPath: "/run/secrets/tls", ReadOnly: true},
					{Name: "falcon-api-ca", MountPath: "/run/secrets/ca", ReadOnly: true},
				},
			},
		},
		Volumes: []corev1.Volume{
			{Name: "falconstore", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/CrowdStrike/falconstore", Type: &hostPathType}}},
			{Name: "falcon-sensor-tls-certs", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: common.CloudGuardSensorTLSSecretName}}},
			{Name: "falcon-api-ca", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: common.CloudGuardAPICASecretName}}},
		},
	}

	if nodeSpec.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil ||
		len(nodeSpec.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution) > 0 {
		podSpec.Affinity = &corev1.Affinity{NodeAffinity: &nodeSpec.NodeAffinity}
	}

	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: appsv1.SchemeGroupVersion.String(),
			Kind:       "DaemonSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.CloudGuardSensorDaemonSetName,
			Namespace: namespace,
			Labels:    dsLabels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": common.CloudGuardSensorDaemonSetName}},
			UpdateStrategy: updateStrategy,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      map[string]string{"app": common.CloudGuardSensorDaemonSetName},
					Annotations: map[string]string{common.FalconContainerInjection: "disabled"},
				},
				Spec: podSpec,
			},
		},
	}
}

func buildResourceRequirements(res falconv1alpha1.Resources) corev1.ResourceRequirements {
	reqs := corev1.ResourceRequirements{
		Limits:   corev1.ResourceList{},
		Requests: corev1.ResourceList{},
	}
	if res.Limits.Memory != "" {
		reqs.Limits[corev1.ResourceMemory] = resource.MustParse(res.Limits.Memory)
	}
	if res.Limits.CPU != "" {
		reqs.Limits[corev1.ResourceCPU] = resource.MustParse(res.Limits.CPU)
	}
	if res.Requests.Memory != "" {
		reqs.Requests[corev1.ResourceMemory] = resource.MustParse(res.Requests.Memory)
	}
	if res.Requests.CPU != "" {
		reqs.Requests[corev1.ResourceCPU] = resource.MustParse(res.Requests.CPU)
	}
	return reqs
}

func (r *FalconCloudGuardReconciler) reconcileSensorCleanupServiceAccount(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) error {
	sa := assets.ServiceAccount(common.CloudGuardSensorCleanupServiceAccountName, fcg.Spec.InstallNamespace, common.CloudGuardComponentName, nil, nil)
	existing := &corev1.ServiceAccount{}

	err := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardSensorCleanupServiceAccountName, Namespace: fcg.Spec.InstallNamespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		return commonctrl.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, sa)
	} else if err != nil {
		log.Error(err, "Failed to get FalconCloudGuard sensor cleanup ServiceAccount")
		return err
	}

	return nil
}

func (r *FalconCloudGuardReconciler) reconcileSensorCleanupDaemonSet(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) error {
	imageUri := fcg.Spec.Image
	if imageUri == "" && fcg.Spec.FalconAPI != nil && fcg.Spec.FalconAPI.CID != nil && *fcg.Spec.FalconAPI.CID != "" {
		imageUri = *fcg.Spec.FalconAPI.CID
	}

	ds := cloudGuardSensorCleanupDaemonSet(fcg.Spec.InstallNamespace, imageUri, fcg.Spec.ImagePullPolicy, fcg.Spec.ImagePullSecrets)
	existing := &appsv1.DaemonSet{}

	err := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardSensorCleanupDaemonSetName, Namespace: fcg.Spec.InstallNamespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		return commonctrl.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, ds)
	} else if err != nil {
		log.Error(err, "Failed to get FalconCloudGuard sensor cleanup DaemonSet")
		return err
	}

	if !reflect.DeepEqual(ds.Spec.Template.Spec.Containers, existing.Spec.Template.Spec.Containers) ||
		!reflect.DeepEqual(ds.Spec.Template.Spec.InitContainers, existing.Spec.Template.Spec.InitContainers) {
		existing.Spec.Template.Spec.Containers = ds.Spec.Template.Spec.Containers
		existing.Spec.Template.Spec.InitContainers = ds.Spec.Template.Spec.InitContainers
		existing.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("DaemonSet"))
		return commonctrl.Update(r.Client, ctx, req, log, fcg, &fcg.Status, existing)
	}

	return nil
}

func cloudGuardSensorCleanupDaemonSet(namespace string, imageUri string, imagePullPolicy corev1.PullPolicy, imagePullSecrets []corev1.LocalObjectReference) *appsv1.DaemonSet {
	dsLabels := common.CRLabels("daemonset", common.CloudGuardSensorCleanupDaemonSetName, common.CloudGuardComponentName)

	if imagePullPolicy == "" {
		imagePullPolicy = corev1.PullIfNotPresent
	}
	privileged := true
	runAsUser := int64(0)
	terminationGracePeriod := int64(60)
	readOnlyRootFilesystem := true
	allowPrivilegeEscalation := true
	disallowPrivilegeEscalation := false

	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: appsv1.SchemeGroupVersion.String(),
			Kind:       "DaemonSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.CloudGuardSensorCleanupDaemonSetName,
			Namespace: namespace,
			Labels:    dsLabels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": common.CloudGuardSensorCleanupDaemonSetName},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": common.CloudGuardSensorCleanupDaemonSetName},
					Annotations: map[string]string{
						common.FalconContainerInjection: "disabled",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName:            common.CloudGuardSensorCleanupServiceAccountName,
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostPID:                       true,
					ImagePullSecrets:              imagePullSecrets,
					NodeSelector: map[string]string{
						"kubernetes.io/os": "linux",
					},
					InitContainers: []corev1.Container{
						{
							Name:            "cleanup-opt-crowdstrike",
							Image:           imageUri,
							ImagePullPolicy: imagePullPolicy,
							Command:         []string{"/bin/bash"},
							Args: []string{
								"-c",
								`echo "Running /opt/CrowdStrike/falcon-daemonset-init -u"; /opt/CrowdStrike/falcon-daemonset-init -u`,
							},
							SecurityContext: &corev1.SecurityContext{
								RunAsUser:                &runAsUser,
								Privileged:               &privileged,
								AllowPrivilegeEscalation: &allowPrivilegeEscalation,
								ReadOnlyRootFilesystem:   func() *bool { b := false; return &b }(),
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:            "cleanup-sleep",
							Image:           imageUri,
							ImagePullPolicy: imagePullPolicy,
							Command:         []string{"/bin/bash"},
							Args:            []string{"-c", "sleep infinity"},
							SecurityContext: &corev1.SecurityContext{
								Privileged:               &disallowPrivilegeEscalation,
								ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
								AllowPrivilegeEscalation: &allowPrivilegeEscalation,
							},
						},
					},
				},
			},
		},
	}
}

// finalizeSensorDaemonSet deletes the main sensor DaemonSet, runs the cleanup DaemonSet to
// remove /opt/CrowdStrike on each node, waits for it to complete, then deletes it.
func (r *FalconCloudGuardReconciler) finalizeSensorDaemonSet(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) error {
	dsCleanupName := common.CloudGuardSensorCleanupDaemonSetName
	daemonset := &appsv1.DaemonSet{}
	pods := corev1.PodList{}
	dsList := &appsv1.DaemonSetList{}
	var nodeCount int32 = 0

	// Get a list of DS in the namespace to determine desired node count
	listOptions := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{common.FalconComponentKey: common.CloudGuardComponentName}),
		Namespace:     fcg.Spec.InstallNamespace,
	}

	if err := r.List(ctx, dsList, listOptions); err != nil {
		if err = r.Reader.List(ctx, dsList, listOptions); err != nil {
			return err
		}
	}

	// Delete the main sensor DaemonSet
	log.Info("Deleting main sensor DaemonSet")
	if err := r.Delete(ctx,
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      common.CloudGuardSensorDaemonSetName,
				Namespace: fcg.Spec.InstallNamespace,
			},
		}); err != nil && !apierrors.IsNotFound(err) {
		log.Error(err, "Failed to delete main sensor DaemonSet")
		return err
	}

	// Create or ensure the cleanup DaemonSet exists
	log.Info("Creating cleanup DaemonSet")
	if err := r.reconcileSensorCleanupDaemonSet(ctx, req, log, fcg); err != nil {
		return err
	}

	var lastCompletedCount int32
	var lastNodeCount int32
	var crashloopingPodNodes []string

	// Wait for all cleanup pods to be running or completed
	log.Info("Waiting for cleanup pods to complete")
	for {
		// List all pods with the cleanup label in the appropriate NS
		cleanupListOptions := &client.ListOptions{
			LabelSelector: labels.SelectorFromSet(labels.Set{"app": common.CloudGuardSensorCleanupDaemonSetName}),
			Namespace:     fcg.Spec.InstallNamespace,
		}
		if err := r.List(ctx, &pods, cleanupListOptions); err != nil {
			if err = r.Reader.List(ctx, &pods, cleanupListOptions); err != nil {
				return err
			}
		}

		// Reset completedCount each loop to ensure we don't count the same node(s) multiple times
		var completedCount int32 = 0
		// Reset the nodeCount each loop in case the cluster has scaled down
		for _, dSet := range dsList.Items {
			nodeCount = dSet.Status.DesiredNumberScheduled
			if lastNodeCount != nodeCount {
				log.Info("Setting DaemonSet node count", "Number of nodes", nodeCount)
			}
			lastNodeCount = nodeCount
		}

		// Running is acceptable because the pods should be running the sleep command and have already cleaned up /opt/CrowdStrike
		for _, pod := range pods.Items {
			switch pod.Status.Phase {
			case "Running", "Succeeded":
				completedCount++
			case "Pending":
				if commonctrl.IsInitPodCrashLooping(&pod) {
					if !slices.Contains(crashloopingPodNodes, pod.Spec.NodeName) {
						log.Info(fmt.Sprintf("/opt/CrowdStrike may have not been removed on node %s due to the cleanup pod crashlooping. See the troubleshooting section of the documentation for more information.", pod.Spec.NodeName))
						crashloopingPodNodes = append(crashloopingPodNodes, pod.Spec.NodeName)
					}
					completedCount++
				}
			}
		}

		// Break when all nodes have a running or completed cleanup pod
		if completedCount == nodeCount {
			log.Info("Cleanup pods are done")
			break
		} else if completedCount < nodeCount && completedCount > 0 {
			if completedCount != lastCompletedCount {
				log.Info("Waiting for cleanup pods to complete", "Pods still processing", completedCount, "Total nodes", nodeCount)
			}
			lastCompletedCount = completedCount
		}

		// Check if cleanup daemonset has been manually removed
		err := r.Get(ctx, types.NamespacedName{Name: dsCleanupName, Namespace: fcg.Spec.InstallNamespace}, daemonset)
		if err != nil && apierrors.IsNotFound(err) {
			log.Info("Cleanup daemonset has been removed")
			break
		}
	}

	// The cleanup DS is done, delete it
	log.Info("Deleting cleanup DaemonSet")
	if err := r.Delete(ctx,
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      dsCleanupName,
				Namespace: fcg.Spec.InstallNamespace,
			},
		}); err != nil && !apierrors.IsNotFound(err) {
		log.Error(err, "Failed to delete cleanup DaemonSet")
		return err
	}

	log.Info("Successfully finalized sensor daemonset", "Path", common.FalconDataDir)
	return nil
}
