package node_sensor

import (
	"context"
	"fmt"
	"slices"
	"time"

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
	NodeSensor       falconv1alpha1.FalconNodeBaseConfig
	NamePrefix       string
	Cid              string
}

const nodeSensorDefaultPrefix = "falcon-clusterguard"

// prefix returns the name prefix to use for owned resources.
// If NamePrefix is set in config, it is used; otherwise the default is returned.
func (n *NodeSensor) prefix() string {
	if n.cfg.NamePrefix != "" {
		return n.cfg.NamePrefix
	}
	return nodeSensorDefaultPrefix
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
			done, err := n.finalize(ctx)
			if err != nil {
				return ctrl.Result{}, err
			}
			if !done {
				return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
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

// finalize ensures the cleanup DaemonSet is running and all cleanup pods have completed
// (reached Running phase, meaning init containers finished). Returns true when done.
// It is safe to call on every reconcile — the delete and DaemonSet creation are idempotent.
func (n *NodeSensor) finalize(ctx context.Context) (bool, error) {
	dsCleanupName := n.prefix() + "-sensor-cleanup"

	n.r.GetLog().Info("Deleting main sensor DaemonSet")
	if err := n.r.Delete(ctx, &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: n.prefix() + "-sensor", Namespace: n.cfg.InstallNamespace},
	}); err != nil && !apierrors.IsNotFound(err) {
		n.r.GetLog().Error(err, "Failed to delete main sensor DaemonSet")
		return false, err
	}

	if err := n.reconcileCleanupDaemonSet(ctx); err != nil {
		return false, err
	}

	daemonset := &appsv1.DaemonSet{}
	if err := pkgcommon.GetWithFallback(ctx, n.r, n.r.GetK8sReader(),
		types.NamespacedName{Name: dsCleanupName, Namespace: n.cfg.InstallNamespace}, daemonset); err != nil {
		if apierrors.IsNotFound(err) {
			n.r.GetLog().Info("Cleanup DaemonSet not found yet, requeueing...")
			return false, nil
		}
		return false, err
	}

	pods := corev1.PodList{}
	cleanupListOptions := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{"app": dsCleanupName}),
		Namespace:     n.cfg.InstallNamespace,
	}
	if err := n.r.List(ctx, &pods, cleanupListOptions); err != nil {
		if err = n.r.GetK8sReader().List(ctx, &pods, cleanupListOptions); err != nil {
			return false, err
		}
	}

	nodeCount := daemonset.Status.DesiredNumberScheduled
	if nodeCount == 0 || len(pods.Items) == 0 {
		n.r.GetLog().Info("Waiting for cleanup pods to be scheduled...")
		return false, nil
	}

	var runningCount int32
	var crashloopingPodNodes []string
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning {
			runningCount++
		}
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

	n.r.GetLog().Info(fmt.Sprintf("Cleanup progress: %d/%d pods running", runningCount, nodeCount))

	if runningCount < nodeCount {
		return false, nil
	}

	n.r.GetLog().Info("All cleanup pods completed, deleting cleanup DaemonSet")
	if err := n.r.Delete(ctx, &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: dsCleanupName, Namespace: n.cfg.InstallNamespace},
	}); err != nil && !apierrors.IsNotFound(err) {
		return false, err
	}

	return true, nil
}
