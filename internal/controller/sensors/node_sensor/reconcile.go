package node_sensor

import (
	"context"
	"fmt"
	"slices"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	pkgcommon "github.com/crowdstrike/falcon-operator/pkg/common"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
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

		if len(pods.Items) == 0 {
			n.r.GetLog().Info("No cleanup pods found yet, waiting...")
			continue
		}

		if err := pkgcommon.GetWithFallback(ctx, n.r, n.r.GetK8sReader(),
			types.NamespacedName{Name: dsCleanupName, Namespace: n.cfg.InstallNamespace}, daemonset); err != nil {
			if apierrors.IsNotFound(err) {
				n.r.GetLog().Info("Cleanup DaemonSet not found, waiting for it to be created...")
				continue
			}
			return err
		}
		nodeCount = daemonset.Status.DesiredNumberScheduled
		readyCount := daemonset.Status.NumberReady

		if readyCount != lastCompletedCount || nodeCount != lastNodeCount {
			n.r.GetLog().Info(fmt.Sprintf("Cleanup progress: %d/%d pods ready", readyCount, nodeCount))
			lastCompletedCount = readyCount
			lastNodeCount = nodeCount
		}

		if readyCount == nodeCount && nodeCount > 0 {
			n.r.GetLog().Info("All cleanup pods completed successfully")
			break
		}

		// Check for failed/crashlooping pods
		for _, pod := range pods.Items {
			if pod.Status.Phase == corev1.PodFailed {
				for _, status := range pod.Status.ContainerStatuses {
					if status.State.Waiting != nil && status.State.Waiting.Reason == "CrashLoopBackOff" {
						crashloopingPodNodes = append(crashloopingPodNodes, pod.Spec.NodeName)
					}
				}
			}
		}

		if len(crashloopingPodNodes) > 0 {
			slices.Sort(crashloopingPodNodes)
			crashloopingPodNodes = slices.Compact(crashloopingPodNodes)
			n.r.GetLog().Info(fmt.Sprintf("Some cleanup pods are in CrashLoopBackOff on nodes: %v", crashloopingPodNodes))
		}
	}

	n.r.GetLog().Info("Deleting cleanup DaemonSet")
	if err := n.r.Delete(ctx, &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: dsCleanupName, Namespace: n.cfg.InstallNamespace},
	}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	return nil
}
