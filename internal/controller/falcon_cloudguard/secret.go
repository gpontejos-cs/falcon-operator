package controllers

import (
	"context"
	"fmt"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	"github.com/crowdstrike/falcon-operator/pkg/tls"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

func (r *FalconCloudGuardReconciler) reconcileTLSSecret(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) (*corev1.Secret, error) {
	existing := &corev1.Secret{}
	namespace := fcg.Spec.InstallNamespace

	err := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardTLSSecretName, Namespace: namespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		svcName := fmt.Sprintf("%s.%s.svc", common.CloudGuardWebhookServiceName, namespace)
		altDNSNames := []string{
			svcName,
			fmt.Sprintf("%s.cluster.local", svcName),
			fmt.Sprintf("%s.%s", svcName, namespace),
		}

		certInfo := tls.CertInfo{
			CommonName: svcName,
			DNSNames:   altDNSNames,
		}

		cert, key, ca, err := tls.CertSetup(namespace, 3650, certInfo)
		if err != nil {
			log.Error(err, "Failed to generate FalconCloudGuard TLS certificates")
			return &corev1.Secret{}, err
		}

		secretData := map[string][]byte{
			"tls.crt": cert,
			"tls.key": key,
			"ca.crt":  ca,
		}

		tlsSecret := assets.Secret(common.CloudGuardTLSSecretName, namespace, common.CloudGuardComponentName, secretData, corev1.SecretTypeTLS)
		if err := k8sutils.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, tlsSecret); err != nil {
			return &corev1.Secret{}, err
		}
		return tlsSecret, nil
	} else if err != nil {
		log.Error(err, "Failed to get FalconCloudGuard TLS Secret")
		return &corev1.Secret{}, err
	}

	return existing, nil
}

// reconcileAPITLSSecrets reconciles the three PKI secrets for the gRPC API:
//   - falcon-api-tls:    server TLS cert/key for the API service
//   - falcon-api-ca:     CA cert for clients to verify the API server
//   - falcon-sensor-tls: client TLS cert/key for the node sensor
func (r *FalconCloudGuardReconciler) reconcileAPITLSSecrets(ctx context.Context, req ctrl.Request, log logr.Logger, fcg *falconv1alpha1.FalconCloudGuard) error {
	namespace := fcg.Spec.InstallNamespace

	// If all three already exist, nothing to do.
	existingAPI := &corev1.Secret{}
	errAPI := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardAPITLSSecretName, Namespace: namespace}, existingAPI)
	existingCA := &corev1.Secret{}
	errCA := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardAPICASecretName, Namespace: namespace}, existingCA)
	existingSensor := &corev1.Secret{}
	errSensor := r.Get(ctx, types.NamespacedName{Name: common.CloudGuardSensorTLSSecretName, Namespace: namespace}, existingSensor)

	if errAPI == nil && errCA == nil && errSensor == nil {
		return nil
	}

	// Generate a shared CA + server cert + client cert.
	apiSvcName := fmt.Sprintf("%s.%s.svc", common.CloudGuardAPIServiceName, namespace)
	serverCertInfo := tls.CertInfo{
		CommonName: apiSvcName,
		DNSNames: []string{
			apiSvcName,
			fmt.Sprintf("%s.cluster.local", apiSvcName),
		},
	}
	serverCert, serverKey, ca, err := tls.CertSetup(namespace, 3650, serverCertInfo)
	if err != nil {
		log.Error(err, "Failed to generate FalconCloudGuard API TLS certificates")
		return err
	}

	sensorSvcName := fmt.Sprintf("%s.%s.svc", common.CloudGuardSensorServiceAccountName, namespace)
	clientCertInfo := tls.CertInfo{
		CommonName: "falcon-sensor-client",
		DNSNames:   []string{sensorSvcName},
	}
	clientCert, clientKey, _, err := tls.CertSetup(namespace, 3650, clientCertInfo)
	if err != nil {
		log.Error(err, "Failed to generate FalconCloudGuard sensor client TLS certificates")
		return err
	}

	if apierrors.IsNotFound(errAPI) {
		apiSecret := assets.Secret(
			common.CloudGuardAPITLSSecretName, namespace, common.CloudGuardComponentName,
			map[string][]byte{"tls.crt": serverCert, "tls.key": serverKey},
			corev1.SecretTypeTLS,
		)
		if err := k8sutils.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, apiSecret); err != nil {
			return err
		}
	} else if errAPI != nil {
		log.Error(errAPI, "Failed to get FalconCloudGuard API TLS Secret")
		return errAPI
	}

	if apierrors.IsNotFound(errCA) {
		caSecret := assets.Secret(
			common.CloudGuardAPICASecretName, namespace, common.CloudGuardComponentName,
			map[string][]byte{"ca.crt": ca},
			corev1.SecretTypeOpaque,
		)
		if err := k8sutils.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, caSecret); err != nil {
			return err
		}
	} else if errCA != nil {
		log.Error(errCA, "Failed to get FalconCloudGuard API CA Secret")
		return errCA
	}

	if apierrors.IsNotFound(errSensor) {
		sensorSecret := assets.Secret(
			common.CloudGuardSensorTLSSecretName, namespace, common.CloudGuardComponentName,
			map[string][]byte{"tls.crt": clientCert, "tls.key": clientKey},
			corev1.SecretTypeTLS,
		)
		if err := k8sutils.Create(r.Client, r.Scheme, ctx, req, log, fcg, &fcg.Status, sensorSecret); err != nil {
			return err
		}
	} else if errSensor != nil {
		log.Error(errSensor, "Failed to get FalconCloudGuard sensor TLS Secret")
		return errSensor
	}

	return nil
}
