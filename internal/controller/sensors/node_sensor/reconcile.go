package node_sensor

import (
	"context"
	"fmt"
	"reflect"
	"slices"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	pkgcommon "github.com/crowdstrike/falcon-operator/pkg/common"
	"github.com/operator-framework/operator-lib/proxy"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// Reconciler is the interface the sensor component requires from the controller.
type Reconciler = k8sutils.Reconciler

// Config holds the inputs needed to reconcile the node sensor component.
type Config struct {
	Request          ctrl.Request
	Owner            client.Object
	Status           *falconv1alpha1.FalconCRStatus
	InstallNamespace string
	Image            string
	ImagePullPolicy  corev1.PullPolicy
	ImagePullSecrets []corev1.LocalObjectReference
	Falcon           falconv1alpha1.FalconSensor
	FalconAPI        *falconv1alpha1.FalconAPI
	NodeSensor       falconv1alpha1.FalconNodeSensorConfig
	Cid              string
}

// NodeSensor owns the reconciliation of all node sensor sub-resources.
type NodeSensor struct {
	r   Reconciler
	cfg Config
}

// New returns a NodeSensor ready to reconcile.
func New(r Reconciler, cfg Config) *NodeSensor {
	return &NodeSensor{r: r, cfg: cfg}
}

// Reconcile manages the full sensor lifecycle: finalizer registration, normal
// reconciliation of sensor resources, and cleanup on deletion.
func (n *NodeSensor) Reconcile(ctx context.Context) (ctrl.Result, error) {
	log := n.r.GetLog()

	if n.cfg.Owner.GetDeletionTimestamp() != nil {
		if controllerutil.ContainsFinalizer(n.cfg.Owner, pkgcommon.FalconFinalizer) {
			log.Info("FalconClusterGuard is being deleted, running finalization logic")
			if err := n.finalize(ctx); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(n.cfg.Owner, pkgcommon.FalconFinalizer)
			if err := n.r.Update(ctx, n.cfg.Owner); err != nil {
				return ctrl.Result{}, err
			}
			log.Info("Successfully finalized FalconClusterGuard")
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(n.cfg.Owner, pkgcommon.FalconFinalizer) {
		controllerutil.AddFinalizer(n.cfg.Owner, pkgcommon.FalconFinalizer)
		if err := n.r.Update(ctx, n.cfg.Owner); err != nil {
			log.Error(err, "Unable to add finalizer to FalconClusterGuard")
			return ctrl.Result{}, err
		}
		log.Info("Added finalizer to FalconClusterGuard")
	}

	if err := n.reconcileServiceAccount(ctx); err != nil {
		return ctrl.Result{}, err
	}
	if err := n.reconcileConfigMap(ctx); err != nil {
		return ctrl.Result{}, err
	}
	if err := n.reconcileClusterRoleBinding(ctx); err != nil {
		return ctrl.Result{}, err
	}
	if err := n.reconcileDaemonSet(ctx); err != nil {
		return ctrl.Result{}, err
	}
	if err := n.reconcileCleanupServiceAccount(ctx); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// finalize deletes the sensor DaemonSet, runs the cleanup DaemonSet on each node,
// waits for completion, then removes the cleanup DaemonSet.
func (n *NodeSensor) finalize(ctx context.Context) error {
	dsCleanupName := pkgcommon.ClusterGuardSensorCleanupDaemonSetName
	daemonset := &appsv1.DaemonSet{}
	pods := corev1.PodList{}
	dsList := &appsv1.DaemonSetList{}
	var nodeCount int32

	listOptions := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{pkgcommon.FalconComponentKey: pkgcommon.ClusterGuardComponentName}),
		Namespace:     n.cfg.InstallNamespace,
	}
	if err := n.r.List(ctx, dsList, listOptions); err != nil {
		if err = n.r.GetK8sReader().List(ctx, dsList, listOptions); err != nil {
			return err
		}
	}

	n.r.GetLog().Info("Deleting main sensor DaemonSet")
	if err := n.r.Delete(ctx, &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: pkgcommon.ClusterGuardSensorDaemonSetName, Namespace: n.cfg.InstallNamespace},
	}); err != nil && !apierrors.IsNotFound(err) {
		n.r.GetLog().Error(err, "Failed to delete main sensor DaemonSet")
		return err
	}

	n.r.GetLog().Info("Creating cleanup DaemonSet")
	if err := n.reconcileCleanupDaemonSet(ctx); err != nil {
		return err
	}

	var lastCompletedCount int32
	var lastNodeCount int32
	var crashloopingPodNodes []string

	n.r.GetLog().Info("Waiting for cleanup pods to complete")
	for {
		cleanupListOptions := &client.ListOptions{
			LabelSelector: labels.SelectorFromSet(labels.Set{"app": pkgcommon.ClusterGuardSensorCleanupDaemonSetName}),
			Namespace:     n.cfg.InstallNamespace,
		}
		if err := n.r.List(ctx, &pods, cleanupListOptions); err != nil {
			if err = n.r.GetK8sReader().List(ctx, &pods, cleanupListOptions); err != nil {
				return err
			}
		}

		var completedCount int32
		for _, dSet := range dsList.Items {
			nodeCount = dSet.Status.DesiredNumberScheduled
			if lastNodeCount != nodeCount {
				n.r.GetLog().Info("Setting DaemonSet node count", "Number of nodes", nodeCount)
			}
			lastNodeCount = nodeCount
		}

		for _, pod := range pods.Items {
			switch pod.Status.Phase {
			case "Running", "Succeeded":
				completedCount++
			case "Pending":
				if k8sutils.IsInitPodCrashLooping(&pod) {
					if !slices.Contains(crashloopingPodNodes, pod.Spec.NodeName) {
						n.r.GetLog().Info(fmt.Sprintf("/opt/CrowdStrike may have not been removed on node %s due to the cleanup pod crashlooping. See the troubleshooting section of the documentation for more information.", pod.Spec.NodeName))
						crashloopingPodNodes = append(crashloopingPodNodes, pod.Spec.NodeName)
					}
					completedCount++
				}
			}
		}

		if completedCount == nodeCount {
			n.r.GetLog().Info("Cleanup pods are done")
			break
		} else if completedCount < nodeCount && completedCount > 0 {
			if completedCount != lastCompletedCount {
				n.r.GetLog().Info("Waiting for cleanup pods to complete", "Pods still processing", completedCount, "Total nodes", nodeCount)
			}
			lastCompletedCount = completedCount
		}

		err := pkgcommon.GetWithFallback(ctx, n.r, n.r.GetK8sReader(), types.NamespacedName{Name: dsCleanupName, Namespace: n.cfg.InstallNamespace}, daemonset)
		if err != nil && apierrors.IsNotFound(err) {
			n.r.GetLog().Info("Cleanup daemonset has been removed")
			break
		}
	}

	n.r.GetLog().Info("Deleting cleanup DaemonSet")
	if err := n.r.Delete(ctx, &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: dsCleanupName, Namespace: n.cfg.InstallNamespace},
	}); err != nil && !apierrors.IsNotFound(err) {
		n.r.GetLog().Error(err, "Failed to delete cleanup DaemonSet")
		return err
	}

	n.r.GetLog().Info("Successfully finalized sensor daemonset", "Path", pkgcommon.FalconDataDir)
	return nil
}

func (n *NodeSensor) syncConfigMap(ctx context.Context, cm *corev1.ConfigMap, logLabel string) error {
	existing := &corev1.ConfigMap{}
	found, err := k8sutils.GetOrCreate(ctx, n.r, n.cfg.Request, n.cfg.Owner, n.cfg.Status, cm, existing,
		types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace},
		"Failed to get "+logLabel+" ConfigMap")
	if !found || err != nil {
		return err
	}
	if !reflect.DeepEqual(cm.Data, existing.Data) {
		return retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := pkgcommon.GetWithFallback(ctx, n.r, n.r.GetK8sReader(),
				types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, existing); err != nil {
				return err
			}
			for k, v := range cm.Data {
				if existing.Data[k] != v {
					n.r.GetLog().V(1).Info("Updating "+logLabel+" ConfigMap: value changed", "key", k, "old", existing.Data[k], "new", v)
				}
			}
			existing.Data = cm.Data
			existing.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
			return k8sutils.Update(n.r, ctx, n.cfg.Request, n.r.GetLog(), n.cfg.Owner, n.cfg.Status, existing)
		})
	}
	return nil
}

func (n *NodeSensor) reconcileServiceAccount(ctx context.Context) error {
	sa := n.serviceAccount()
	_, err := k8sutils.GetOrCreate(ctx, n.r, n.cfg.Request, n.cfg.Owner, n.cfg.Status, sa, &corev1.ServiceAccount{},
		types.NamespacedName{Name: pkgcommon.ClusterGuardSensorServiceAccountName, Namespace: n.cfg.InstallNamespace},
		"Failed to get FalconClusterGuard sensor ServiceAccount")
	return err
}

func (n *NodeSensor) reconcileConfigMap(ctx context.Context) error {
	cm := n.configMap()
	return n.syncConfigMap(ctx, cm, "FalconClusterGuard sensor")
}

func (n *NodeSensor) reconcileClusterRoleBinding(ctx context.Context) error {
	crb := n.clusterRoleBinding()
	existing := &rbacv1.ClusterRoleBinding{}
	found, err := k8sutils.GetOrCreate(ctx, n.r, n.cfg.Request, n.cfg.Owner, n.cfg.Status, crb, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardSensorClusterRoleBindingName},
		"Failed to get FalconClusterGuard sensor ClusterRoleBinding")
	if !found || err != nil {
		return err
	}
	if !reflect.DeepEqual(crb.RoleRef, existing.RoleRef) {
		n.r.GetLog().V(1).Info("Recreating FalconClusterGuard sensor ClusterRoleBinding: RoleRef changed")
		if err := k8sutils.Delete(n.r, ctx, n.cfg.Request, n.r.GetLog(), n.cfg.Owner, n.cfg.Status, existing); err != nil {
			return err
		}
		return k8sutils.Create(n.r, n.r.GetScheme(), ctx, n.cfg.Request, n.r.GetLog(), n.cfg.Owner, n.cfg.Status, crb)
	} else if !reflect.DeepEqual(crb.Subjects, existing.Subjects) {
		n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor ClusterRoleBinding: subjects changed")
		existing.Subjects = crb.Subjects
		existing.SetGroupVersionKind(rbacv1.SchemeGroupVersion.WithKind("ClusterRoleBinding"))
		return k8sutils.Update(n.r, ctx, n.cfg.Request, n.r.GetLog(), n.cfg.Owner, n.cfg.Status, existing)
	}
	return nil
}

func (n *NodeSensor) reconcileDaemonSet(ctx context.Context) error {
	ds := n.daemonSet()

	// Inject operator proxy env vars into the desired spec containers before create/update.
	if len(proxy.ReadProxyVarsFromEnv()) > 0 {
		for i, container := range ds.Spec.Template.Spec.Containers {
			ds.Spec.Template.Spec.Containers[i].Env = append(container.Env, proxy.ReadProxyVarsFromEnv()...)
		}
	}

	existing := &appsv1.DaemonSet{}
	found, err := k8sutils.GetOrCreate(ctx, n.r, n.cfg.Request, n.cfg.Owner, n.cfg.Status, ds, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardSensorDaemonSetName, Namespace: n.cfg.InstallNamespace},
		"Failed to get FalconClusterGuard sensor DaemonSet")
	if !found || err != nil {
		return err
	}

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := pkgcommon.GetWithFallback(ctx, n.r, n.r.GetK8sReader(),
			types.NamespacedName{Name: pkgcommon.ClusterGuardSensorDaemonSetName, Namespace: n.cfg.InstallNamespace},
			existing); err != nil {
			return err
		}

		updated := false

		// ImagePullSecrets
		if !equality.Semantic.DeepEqual(ds.Spec.Template.Spec.ImagePullSecrets, existing.Spec.Template.Spec.ImagePullSecrets) {
			n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: ImagePullSecrets changed",
				"old", existing.Spec.Template.Spec.ImagePullSecrets,
				"new", ds.Spec.Template.Spec.ImagePullSecrets)
			existing.Spec.Template.Spec.ImagePullSecrets = ds.Spec.Template.Spec.ImagePullSecrets
			updated = true
		}

		// UpdateStrategy
		if !equality.Semantic.DeepEqual(ds.Spec.UpdateStrategy, existing.Spec.UpdateStrategy) {
			n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: UpdateStrategy changed",
				"old", existing.Spec.UpdateStrategy,
				"new", ds.Spec.UpdateStrategy)
			existing.Spec.UpdateStrategy = ds.Spec.UpdateStrategy
			updated = true
		}

		// Volumes
		if !equality.Semantic.DeepEqual(ds.Spec.Template.Spec.Volumes, existing.Spec.Template.Spec.Volumes) {
			n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: Volumes changed")
			existing.Spec.Template.Spec.Volumes = ds.Spec.Template.Spec.Volumes
			updated = true
		}

		// NodeAffinity
		if ds.Spec.Template.Spec.Affinity != nil {
			if existing.Spec.Template.Spec.Affinity == nil {
				existing.Spec.Template.Spec.Affinity = &corev1.Affinity{}
			}
			if !equality.Semantic.DeepEqual(ds.Spec.Template.Spec.Affinity.NodeAffinity, existing.Spec.Template.Spec.Affinity.NodeAffinity) {
				n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: NodeAffinity changed",
					"old", existing.Spec.Template.Spec.Affinity.NodeAffinity,
					"new", ds.Spec.Template.Spec.Affinity.NodeAffinity)
				existing.Spec.Template.Spec.Affinity.NodeAffinity = ds.Spec.Template.Spec.Affinity.NodeAffinity
				updated = true
			}
		}

		// Tolerations (merge: spec is authoritative; preserve existing tolerations not in spec)
		mergedTolerations := ds.Spec.Template.Spec.Tolerations
		for _, existingTol := range existing.Spec.Template.Spec.Tolerations {
			found := false
			for _, specTol := range ds.Spec.Template.Spec.Tolerations {
				if existingTol.Key == specTol.Key && existingTol.Effect == specTol.Effect {
					found = true
					break
				}
			}
			if !found {
				mergedTolerations = append(mergedTolerations, existingTol)
			}
		}
		if !equality.Semantic.DeepEqual(existing.Spec.Template.Spec.Tolerations, mergedTolerations) {
			n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: Tolerations changed",
				"old", existing.Spec.Template.Spec.Tolerations,
				"new", mergedTolerations)
			existing.Spec.Template.Spec.Tolerations = mergedTolerations
			updated = true
		}

		// InitContainers: per-field checks
		if len(ds.Spec.Template.Spec.InitContainers) > 0 && len(existing.Spec.Template.Spec.InitContainers) > 0 {
			specInit := ds.Spec.Template.Spec.InitContainers[0]
			existingInit := &existing.Spec.Template.Spec.InitContainers[0]
			if existingInit.Image != specInit.Image {
				n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: InitContainer image changed",
					"old", existingInit.Image, "new", specInit.Image)
				existingInit.Image = specInit.Image
				updated = true
			}
			if !equality.Semantic.DeepEqual(existingInit.VolumeMounts, specInit.VolumeMounts) {
				n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: InitContainer VolumeMounts changed")
				existingInit.VolumeMounts = specInit.VolumeMounts
				updated = true
			}
			if !equality.Semantic.DeepEqual(existingInit.Env, specInit.Env) {
				n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: InitContainer Env changed")
				existingInit.Env = specInit.Env
				updated = true
			}
			if !equality.Semantic.DeepEqual(existingInit.Args, specInit.Args) {
				n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: InitContainer Args changed")
				existingInit.Args = specInit.Args
				updated = true
			}
			if existingInit.SecurityContext != nil && specInit.SecurityContext != nil &&
				!equality.Semantic.DeepEqual(existingInit.SecurityContext.Capabilities, specInit.SecurityContext.Capabilities) {
				n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: InitContainer Capabilities changed")
				existingInit.SecurityContext.Capabilities = specInit.SecurityContext.Capabilities
				updated = true
			}
		} else if !equality.Semantic.DeepEqual(ds.Spec.Template.Spec.InitContainers, existing.Spec.Template.Spec.InitContainers) {
			n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: InitContainers changed")
			existing.Spec.Template.Spec.InitContainers = ds.Spec.Template.Spec.InitContainers
			updated = true
		}

		// Containers: per-field checks
		if len(ds.Spec.Template.Spec.Containers) > 0 && len(existing.Spec.Template.Spec.Containers) > 0 {
			specC := ds.Spec.Template.Spec.Containers[0]
			existingC := &existing.Spec.Template.Spec.Containers[0]
			if existingC.Image != specC.Image {
				n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: Container image changed",
					"old", existingC.Image, "new", specC.Image)
				existingC.Image = specC.Image
				updated = true
			}
			if !equality.Semantic.DeepEqual(existingC.VolumeMounts, specC.VolumeMounts) {
				n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: Container VolumeMounts changed")
				existingC.VolumeMounts = specC.VolumeMounts
				updated = true
			}
			if !equality.Semantic.DeepEqual(existingC.Resources, specC.Resources) {
				n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: Container Resources changed",
					"old", existingC.Resources, "new", specC.Resources)
				existingC.Resources = specC.Resources
				updated = true
			}
			if !equality.Semantic.DeepEqual(existingC.Env, specC.Env) {
				// Merge existing proxy env vars from the cluster into the spec env before comparing,
				// to avoid overwriting proxy vars that were injected by the operator environment.
				mergedEnv := pkgcommon.MergeEnvVars(specC.Env, existingC.Env, pkgcommon.ProxyEnvNamesWithLowerCase())
				if !equality.Semantic.DeepEqual(existingC.Env, mergedEnv) {
					n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: Container Env changed")
					existingC.Env = mergedEnv
					updated = true
				}
			}
			if existingC.SecurityContext != nil && specC.SecurityContext != nil &&
				!equality.Semantic.DeepEqual(existingC.SecurityContext.Capabilities, specC.SecurityContext.Capabilities) {
				n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: Container Capabilities changed")
				existingC.SecurityContext.Capabilities = specC.SecurityContext.Capabilities
				updated = true
			}
		} else if !equality.Semantic.DeepEqual(ds.Spec.Template.Spec.Containers, existing.Spec.Template.Spec.Containers) {
			n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: Containers changed")
			existing.Spec.Template.Spec.Containers = ds.Spec.Template.Spec.Containers
			updated = true
		}

		// Reconcile proxy env vars: append any new proxy vars from the operator environment,
		// and update the values of any existing proxy vars that have changed.
		if len(proxy.ReadProxyVarsFromEnv()) > 0 {
			for i, container := range existing.Spec.Template.Spec.Containers {
				newEnv := pkgcommon.AppendUniqueEnvVars(container.Env, proxy.ReadProxyVarsFromEnv())
				updatedEnv := pkgcommon.UpdateEnvVars(container.Env, proxy.ReadProxyVarsFromEnv())
				if !equality.Semantic.DeepEqual(existing.Spec.Template.Spec.Containers[i].Env, newEnv) {
					existing.Spec.Template.Spec.Containers[i].Env = newEnv
					updated = true
				}
				if !equality.Semantic.DeepEqual(existing.Spec.Template.Spec.Containers[i].Env, updatedEnv) {
					existing.Spec.Template.Spec.Containers[i].Env = updatedEnv
					updated = true
				}
			}
			if updated {
				n.r.GetLog().V(1).Info("Updating FalconClusterGuard sensor DaemonSet: Proxy env vars changed")
			}
		}

		if updated {
			existing.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("DaemonSet"))
			return k8sutils.Update(n.r, ctx, n.cfg.Request, n.r.GetLog(), n.cfg.Owner, n.cfg.Status, existing)
		}
		return nil
	})
	if err != nil {
		n.r.GetLog().Error(err, "Failed to update FalconClusterGuard sensor DaemonSet after retries")
		return err
	}
	return nil
}

func (n *NodeSensor) reconcileCleanupServiceAccount(ctx context.Context) error {
	sa := n.cleanupServiceAccount()
	_, err := k8sutils.GetOrCreate(ctx, n.r, n.cfg.Request, n.cfg.Owner, n.cfg.Status, sa, &corev1.ServiceAccount{},
		types.NamespacedName{Name: pkgcommon.ClusterGuardSensorCleanupServiceAccountName, Namespace: n.cfg.InstallNamespace},
		"Failed to get FalconClusterGuard sensor cleanup ServiceAccount")
	return err
}

func (n *NodeSensor) reconcileCleanupDaemonSet(ctx context.Context) error {
	ds := n.cleanupDaemonSet()
	existing := &appsv1.DaemonSet{}
	found, err := k8sutils.GetOrCreate(ctx, n.r, n.cfg.Request, n.cfg.Owner, n.cfg.Status, ds, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardSensorCleanupDaemonSetName, Namespace: n.cfg.InstallNamespace},
		"Failed to get FalconClusterGuard sensor cleanup DaemonSet")
	if !found || err != nil {
		return err
	}

	updated := false

	// InitContainers: per-field checks
	if len(ds.Spec.Template.Spec.InitContainers) > 0 && len(existing.Spec.Template.Spec.InitContainers) > 0 {
		specInit := ds.Spec.Template.Spec.InitContainers[0]
		existingInit := &existing.Spec.Template.Spec.InitContainers[0]
		if existingInit.Image != specInit.Image {
			n.r.GetLog().V(1).Info("Updating FalconClusterGuard cleanup DaemonSet: InitContainer image changed",
				"old", existingInit.Image, "new", specInit.Image)
			existingInit.Image = specInit.Image
			updated = true
		}
		if !equality.Semantic.DeepEqual(existingInit.Args, specInit.Args) {
			n.r.GetLog().V(1).Info("Updating FalconClusterGuard cleanup DaemonSet: InitContainer Args changed")
			existingInit.Args = specInit.Args
			updated = true
		}
		if existingInit.SecurityContext != nil && specInit.SecurityContext != nil &&
			!equality.Semantic.DeepEqual(existingInit.SecurityContext.Capabilities, specInit.SecurityContext.Capabilities) {
			n.r.GetLog().V(1).Info("Updating FalconClusterGuard cleanup DaemonSet: InitContainer Capabilities changed")
			existingInit.SecurityContext.Capabilities = specInit.SecurityContext.Capabilities
			updated = true
		}
	} else if !equality.Semantic.DeepEqual(ds.Spec.Template.Spec.InitContainers, existing.Spec.Template.Spec.InitContainers) {
		n.r.GetLog().V(1).Info("Updating FalconClusterGuard cleanup DaemonSet: InitContainers changed")
		existing.Spec.Template.Spec.InitContainers = ds.Spec.Template.Spec.InitContainers
		updated = true
	}

	// Containers: per-field checks
	if len(ds.Spec.Template.Spec.Containers) > 0 && len(existing.Spec.Template.Spec.Containers) > 0 {
		specC := ds.Spec.Template.Spec.Containers[0]
		existingC := &existing.Spec.Template.Spec.Containers[0]
		if existingC.Image != specC.Image {
			n.r.GetLog().V(1).Info("Updating FalconClusterGuard cleanup DaemonSet: Container image changed",
				"old", existingC.Image, "new", specC.Image)
			existingC.Image = specC.Image
			updated = true
		}
		if existingC.SecurityContext != nil && specC.SecurityContext != nil &&
			!equality.Semantic.DeepEqual(existingC.SecurityContext.Capabilities, specC.SecurityContext.Capabilities) {
			n.r.GetLog().V(1).Info("Updating FalconClusterGuard cleanup DaemonSet: Container Capabilities changed")
			existingC.SecurityContext.Capabilities = specC.SecurityContext.Capabilities
			updated = true
		}
	} else if !equality.Semantic.DeepEqual(ds.Spec.Template.Spec.Containers, existing.Spec.Template.Spec.Containers) {
		n.r.GetLog().V(1).Info("Updating FalconClusterGuard cleanup DaemonSet: Containers changed")
		existing.Spec.Template.Spec.Containers = ds.Spec.Template.Spec.Containers
		updated = true
	}

	if updated {
		existing.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("DaemonSet"))
		return k8sutils.Update(n.r, ctx, n.cfg.Request, n.r.GetLog(), n.cfg.Owner, n.cfg.Status, existing)
	}
	return nil
}
