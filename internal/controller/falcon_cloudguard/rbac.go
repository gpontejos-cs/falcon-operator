package controllers

import (
	"context"
	"reflect"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

func (r *FalconCloudGuardReconciler) reconcileServiceAccount(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) error {
	sa := assets.ServiceAccount(common.CloudGuardServiceAccountName, fcg.Spec.InstallNamespace, common.CloudGuardComponentName, nil, nil)
	existing := &corev1.ServiceAccount{}

	err := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardServiceAccountName, Namespace: fcg.Spec.InstallNamespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		return k8sutils.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, sa)
	} else if err != nil {
		log.Error(err, "Failed to get FalconCloudGuard ServiceAccount")
		return err
	}

	return nil
}

func (r *FalconCloudGuardReconciler) reconcileClusterRoleBinding(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) error {
	crb := assets.ClusterRoleBinding(
		common.CloudGuardClusterRoleBindingName,
		fcg.Spec.InstallNamespace,
		common.CloudGuardClusterRoleName,
		common.CloudGuardServiceAccountName,
		common.CloudGuardComponentName,
		[]rbacv1.Subject{},
	)
	existing := &rbacv1.ClusterRoleBinding{}

	err := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardClusterRoleBindingName}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		return k8sutils.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, crb)
	} else if err != nil {
		log.Error(err, "Failed to get FalconCloudGuard ClusterRoleBinding")
		return err
	}

	if !reflect.DeepEqual(crb.RoleRef, existing.RoleRef) {
		if err := k8sutils.Delete(r.Client, ctx, req, log, fcg, &fcg.Status, existing); err != nil {
			return err
		}
		return k8sutils.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, crb)
	} else if !reflect.DeepEqual(crb.Subjects, existing.Subjects) {
		existing.Subjects = crb.Subjects
		existing.SetGroupVersionKind(rbacv1.SchemeGroupVersion.WithKind("ClusterRoleBinding"))
		return k8sutils.Update(r.Client, ctx, req, log, fcg, &fcg.Status, existing)
	}

	return nil
}

func (r *FalconCloudGuardReconciler) reconcileRoleBinding(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) error {
	rb := assets.RoleBinding(common.CloudGuardRoleBindingName, fcg.Spec.InstallNamespace, common.CloudGuardRoleName, common.CloudGuardServiceAccountName)
	existing := &rbacv1.RoleBinding{}

	err := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardRoleBindingName, Namespace: fcg.Spec.InstallNamespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		return k8sutils.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, rb)
	} else if err != nil {
		log.Error(err, "Failed to get FalconCloudGuard RoleBinding")
		return err
	}

	if !reflect.DeepEqual(rb.RoleRef, existing.RoleRef) {
		if err := k8sutils.Delete(r.Client, ctx, req, log, fcg, &fcg.Status, existing); err != nil {
			return err
		}
		return k8sutils.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, rb)
	} else if !reflect.DeepEqual(rb.Subjects, existing.Subjects) {
		existing.Subjects = rb.Subjects
		existing.SetGroupVersionKind(rbacv1.SchemeGroupVersion.WithKind("RoleBinding"))
		return k8sutils.Update(r.Client, ctx, req, log, fcg, &fcg.Status, existing)
	}

	return nil
}
