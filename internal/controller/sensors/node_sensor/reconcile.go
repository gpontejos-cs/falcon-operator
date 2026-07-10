package node_sensor

import (
	"context"
	"fmt"
	"reflect"
	"slices"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	pkgcommon "github.com/crowdstrike/falcon-operator/pkg/common"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// Reconciler is the interface the sensor component requires from the controller.
type Reconciler interface {
	client.Client
	GetK8sReader() client.Reader
	GetScheme()    *runtime.Scheme
	GetLog()       logr.Logger
}

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
}

// Reconcile manages the full sensor lifecycle: finalizer registration, normal
// reconciliation of sensor resources, and cleanup on deletion.
func Reconcile(ctx context.Context, r Reconciler, cfg Config) (ctrl.Result, error) {
	log := r.GetLog()

	if cfg.Owner.GetDeletionTimestamp() != nil {
		if controllerutil.ContainsFinalizer(cfg.Owner, pkgcommon.FalconFinalizer) {
			log.Info("FalconClusterGuard is being deleted, running finalization logic")
			if err := finalize(ctx, r, cfg); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(cfg.Owner, pkgcommon.FalconFinalizer)
			if err := r.Update(ctx, cfg.Owner); err != nil {
				return ctrl.Result{}, err
			}
			log.Info("Successfully finalized FalconClusterGuard")
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(cfg.Owner, pkgcommon.FalconFinalizer) {
		controllerutil.AddFinalizer(cfg.Owner, pkgcommon.FalconFinalizer)
		if err := r.Update(ctx, cfg.Owner); err != nil {
			log.Error(err, "Unable to add finalizer to FalconClusterGuard")
			return ctrl.Result{}, err
		}
		log.Info("Added finalizer to FalconClusterGuard")
	}

	if err := reconcileServiceAccount(ctx, r, cfg); err != nil {
		return ctrl.Result{}, err
	}
	if err := reconcileConfigMap(ctx, r, cfg); err != nil {
		return ctrl.Result{}, err
	}
	if err := reconcileClusterRoleBinding(ctx, r, cfg); err != nil {
		return ctrl.Result{}, err
	}
	if err := reconcileDaemonSet(ctx, r, cfg); err != nil {
		return ctrl.Result{}, err
	}
	if err := reconcileCleanupServiceAccount(ctx, r, cfg); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// finalize deletes the sensor DaemonSet, runs the cleanup DaemonSet on each node,
// waits for completion, then removes the cleanup DaemonSet.
func finalize(ctx context.Context, r Reconciler, cfg Config) error {
	dsCleanupName := pkgcommon.ClusterGuardSensorCleanupDaemonSetName
	daemonset := &appsv1.DaemonSet{}
	pods := corev1.PodList{}
	dsList := &appsv1.DaemonSetList{}
	var nodeCount int32

	listOptions := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{pkgcommon.FalconComponentKey: pkgcommon.ClusterGuardComponentName}),
		Namespace:     cfg.InstallNamespace,
	}
	if err := r.List(ctx, dsList, listOptions); err != nil {
		if err = r.GetK8sReader().List(ctx, dsList, listOptions); err != nil {
			return err
		}
	}

	r.GetLog().Info("Deleting main sensor DaemonSet")
	if err := r.Delete(ctx, &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: pkgcommon.ClusterGuardSensorDaemonSetName, Namespace: cfg.InstallNamespace},
	}); err != nil && !apierrors.IsNotFound(err) {
		r.GetLog().Error(err, "Failed to delete main sensor DaemonSet")
		return err
	}

	r.GetLog().Info("Creating cleanup DaemonSet")
	if err := reconcileCleanupDaemonSet(ctx, r, cfg); err != nil {
		return err
	}

	var lastCompletedCount int32
	var lastNodeCount int32
	var crashloopingPodNodes []string

	r.GetLog().Info("Waiting for cleanup pods to complete")
	for {
		cleanupListOptions := &client.ListOptions{
			LabelSelector: labels.SelectorFromSet(labels.Set{"app": pkgcommon.ClusterGuardSensorCleanupDaemonSetName}),
			Namespace:     cfg.InstallNamespace,
		}
		if err := r.List(ctx, &pods, cleanupListOptions); err != nil {
			if err = r.GetK8sReader().List(ctx, &pods, cleanupListOptions); err != nil {
				return err
			}
		}

		var completedCount int32
		for _, dSet := range dsList.Items {
			nodeCount = dSet.Status.DesiredNumberScheduled
			if lastNodeCount != nodeCount {
				r.GetLog().Info("Setting DaemonSet node count", "Number of nodes", nodeCount)
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
						r.GetLog().Info(fmt.Sprintf("/opt/CrowdStrike may have not been removed on node %s due to the cleanup pod crashlooping. See the troubleshooting section of the documentation for more information.", pod.Spec.NodeName))
						crashloopingPodNodes = append(crashloopingPodNodes, pod.Spec.NodeName)
					}
					completedCount++
				}
			}
		}

		if completedCount == nodeCount {
			r.GetLog().Info("Cleanup pods are done")
			break
		} else if completedCount < nodeCount && completedCount > 0 {
			if completedCount != lastCompletedCount {
				r.GetLog().Info("Waiting for cleanup pods to complete", "Pods still processing", completedCount, "Total nodes", nodeCount)
			}
			lastCompletedCount = completedCount
		}

		err := pkgcommon.GetWithFallback(ctx, r, r.GetK8sReader(), types.NamespacedName{Name: dsCleanupName, Namespace: cfg.InstallNamespace}, daemonset)
		if err != nil && apierrors.IsNotFound(err) {
			r.GetLog().Info("Cleanup daemonset has been removed")
			break
		}
	}

	r.GetLog().Info("Deleting cleanup DaemonSet")
	if err := r.Delete(ctx, &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: dsCleanupName, Namespace: cfg.InstallNamespace},
	}); err != nil && !apierrors.IsNotFound(err) {
		r.GetLog().Error(err, "Failed to delete cleanup DaemonSet")
		return err
	}

	r.GetLog().Info("Successfully finalized sensor daemonset", "Path", pkgcommon.FalconDataDir)
	return nil
}

func getOrCreate(ctx context.Context, r Reconciler, cfg Config, desired, existing client.Object, key types.NamespacedName, errMsg string) (bool, error) {
	if err := pkgcommon.GetWithFallback(ctx, r, r.GetK8sReader(), key, existing); err != nil {
		if apierrors.IsNotFound(err) {
			return false, k8sutils.Create(r, r.GetScheme(), ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, desired)
		}
		r.GetLog().Error(err, errMsg)
		return false, err
	}
	return true, nil
}

func syncConfigMap(ctx context.Context, r Reconciler, cfg Config, cm *corev1.ConfigMap, logLabel string) error {
	existing := &corev1.ConfigMap{}
	found, err := getOrCreate(ctx, r, cfg, cm, existing,
		types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace},
		"Failed to get "+logLabel+" ConfigMap")
	if !found || err != nil {
		return err
	}
	if !reflect.DeepEqual(cm.Data, existing.Data) {
		for k, v := range cm.Data {
			if existing.Data[k] != v {
				r.GetLog().V(1).Info("Updating "+logLabel+" ConfigMap: value changed", "key", k, "old", existing.Data[k], "new", v)
			}
		}
		existing.Data = cm.Data
		existing.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
		return k8sutils.Update(r, ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, existing)
	}
	return nil
}

func reconcileServiceAccount(ctx context.Context, r Reconciler, cfg Config) error {
	sa := ClusterGuardSensorServiceAccount(cfg.InstallNamespace)
	_, err := getOrCreate(ctx, r, cfg, sa, &corev1.ServiceAccount{},
		types.NamespacedName{Name: pkgcommon.ClusterGuardSensorServiceAccountName, Namespace: cfg.InstallNamespace},
		"Failed to get FalconClusterGuard sensor ServiceAccount")
	return err
}

func reconcileConfigMap(ctx context.Context, r Reconciler, cfg Config) error {
	cm := ClusterGuardSensorConfigMap(cfg.InstallNamespace, cfg)
	return syncConfigMap(ctx, r, cfg, cm, "FalconClusterGuard sensor")
}

func reconcileClusterRoleBinding(ctx context.Context, r Reconciler, cfg Config) error {
	crb := ClusterGuardSensorClusterRoleBinding(cfg.InstallNamespace)
	existing := &rbacv1.ClusterRoleBinding{}
	found, err := getOrCreate(ctx, r, cfg, crb, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardSensorClusterRoleBindingName},
		"Failed to get FalconClusterGuard sensor ClusterRoleBinding")
	if !found || err != nil {
		return err
	}
	if !reflect.DeepEqual(crb.RoleRef, existing.RoleRef) {
		if err := k8sutils.Delete(r, ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, existing); err != nil {
			return err
		}
		return k8sutils.Create(r, r.GetScheme(), ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, crb)
	} else if !reflect.DeepEqual(crb.Subjects, existing.Subjects) {
		r.GetLog().V(1).Info("Updating FalconClusterGuard sensor ClusterRoleBinding: subjects changed")
		existing.Subjects = crb.Subjects
		existing.SetGroupVersionKind(rbacv1.SchemeGroupVersion.WithKind("ClusterRoleBinding"))
		return k8sutils.Update(r, ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, existing)
	}
	return nil
}

func reconcileDaemonSet(ctx context.Context, r Reconciler, cfg Config) error {
	ds := ClusterGuardSensorDaemonSet(cfg)
	existing := &appsv1.DaemonSet{}
	found, err := getOrCreate(ctx, r, cfg, ds, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardSensorDaemonSetName, Namespace: cfg.InstallNamespace},
		"Failed to get FalconClusterGuard sensor DaemonSet")
	if !found || err != nil {
		return err
	}
	if !equality.Semantic.DeepEqual(ds.Spec.Template.Spec.Containers, existing.Spec.Template.Spec.Containers) ||
		!equality.Semantic.DeepEqual(ds.Spec.Template.Spec.InitContainers, existing.Spec.Template.Spec.InitContainers) ||
		!equality.Semantic.DeepEqual(ds.Spec.Template.Spec.Volumes, existing.Spec.Template.Spec.Volumes) {
		r.GetLog().V(1).Info("Updating FalconClusterGuard DaemonSet: containers, initContainers, or volumes changed")
		existing.Spec.Template.Spec.Containers = ds.Spec.Template.Spec.Containers
		existing.Spec.Template.Spec.InitContainers = ds.Spec.Template.Spec.InitContainers
		existing.Spec.Template.Spec.Volumes = ds.Spec.Template.Spec.Volumes
		existing.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("DaemonSet"))
		return k8sutils.Update(r, ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, existing)
	}
	return nil
}

func reconcileCleanupServiceAccount(ctx context.Context, r Reconciler, cfg Config) error {
	sa := ClusterGuardSensorCleanupServiceAccount(cfg.InstallNamespace)
	_, err := getOrCreate(ctx, r, cfg, sa, &corev1.ServiceAccount{},
		types.NamespacedName{Name: pkgcommon.ClusterGuardSensorCleanupServiceAccountName, Namespace: cfg.InstallNamespace},
		"Failed to get FalconClusterGuard sensor cleanup ServiceAccount")
	return err
}

func reconcileCleanupDaemonSet(ctx context.Context, r Reconciler, cfg Config) error {
	ds := ClusterGuardSensorCleanupDaemonSet(cfg.InstallNamespace, cfg.Image, cfg.ImagePullPolicy, cfg.ImagePullSecrets)
	existing := &appsv1.DaemonSet{}
	found, err := getOrCreate(ctx, r, cfg, ds, existing,
		types.NamespacedName{Name: pkgcommon.ClusterGuardSensorCleanupDaemonSetName, Namespace: cfg.InstallNamespace},
		"Failed to get FalconClusterGuard sensor cleanup DaemonSet")
	if !found || err != nil {
		return err
	}
	if !equality.Semantic.DeepEqual(ds.Spec.Template.Spec.Containers, existing.Spec.Template.Spec.Containers) ||
		!equality.Semantic.DeepEqual(ds.Spec.Template.Spec.InitContainers, existing.Spec.Template.Spec.InitContainers) {
		r.GetLog().V(1).Info("Updating FalconClusterGuard cleanup DaemonSet: containers or initContainers changed")
		existing.Spec.Template.Spec.Containers = ds.Spec.Template.Spec.Containers
		existing.Spec.Template.Spec.InitContainers = ds.Spec.Template.Spec.InitContainers
		existing.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("DaemonSet"))
		return k8sutils.Update(r, ctx, cfg.Request, r.GetLog(), cfg.Owner, cfg.Status, existing)
	}
	return nil
}
