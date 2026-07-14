package admission

import (
	"context"
	"fmt"

	"github.com/crowdstrike/falcon-operator/internal/controller/assets"
	k8sutils "github.com/crowdstrike/falcon-operator/internal/controller/common"
	pkgcommon "github.com/crowdstrike/falcon-operator/pkg/common"
	"github.com/crowdstrike/falcon-operator/pkg/tls"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
)

// reconcileTLSSecret reconciles the TLS secret for the admission webhook.
func (a *Admission) reconcileTLSSecret(ctx context.Context) (*corev1.Secret, error) {
	existing := &corev1.Secret{}
	namespace := a.cfg.InstallNamespace
	err := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(), types.NamespacedName{Name: pkgcommon.AdmissionTLSSecretName, Namespace: namespace}, existing)
	if err != nil && apierrors.IsNotFound(err) {
		svcName := fmt.Sprintf("%s.%s.svc", pkgcommon.AdmissionWebhookServiceName, namespace)
		altDNSNames := []string{
			svcName,
			fmt.Sprintf("%s.cluster.local", svcName),
			fmt.Sprintf("%s.%s", svcName, namespace),
		}
		cert, key, ca, err := tls.CertSetup(namespace, 3650, tls.CertInfo{CommonName: svcName, DNSNames: altDNSNames})
		if err != nil {
			a.r.GetLog().Error(err, "Failed to generate FalconClusterGuard TLS certificates")
			return &corev1.Secret{}, err
		}
		tlsSecret := assets.Secret(pkgcommon.AdmissionTLSSecretName, namespace, pkgcommon.AdmissionComponentName,
			map[string][]byte{"tls.crt": cert, "tls.key": key, "ca.crt": ca}, corev1.SecretTypeTLS)
		if err := k8sutils.Create(a.r, a.r.GetScheme(), ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, tlsSecret); err != nil {
			return &corev1.Secret{}, err
		}
		return tlsSecret, nil
	} else if err != nil {
		a.r.GetLog().Error(err, "Failed to get FalconClusterGuard TLS Secret")
		return &corev1.Secret{}, err
	}
	return existing, nil
}

// reconcileAPITLSSecrets reconciles the three PKI secrets for the gRPC API:
//   - falcon-api-tls:    server TLS cert/key for the API service
//   - falcon-api-ca:     CA cert for clients to verify the API server
//   - falcon-sensor-tls: client TLS cert/key for the node sensor
func (a *Admission) reconcileAPITLSSecrets(ctx context.Context) error {
	namespace := a.cfg.InstallNamespace
	existingAPI := &corev1.Secret{}
	errAPI := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(), types.NamespacedName{Name: pkgcommon.AdmissionAPITLSSecretName, Namespace: namespace}, existingAPI)
	existingCA := &corev1.Secret{}
	errCA := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(), types.NamespacedName{Name: pkgcommon.AdmissionAPICASecretName, Namespace: namespace}, existingCA)
	existingSensor := &corev1.Secret{}
	errSensor := pkgcommon.GetWithFallback(ctx, a.r, a.r.GetK8sReader(), types.NamespacedName{Name: pkgcommon.ClusterGuardSensorTLSSecretName, Namespace: namespace}, existingSensor)
	if errAPI == nil && errCA == nil && errSensor == nil {
		return nil
	}
	apiSvcName := fmt.Sprintf("%s.%s.svc", pkgcommon.AdmissionAPIServiceName, namespace)
	serverCert, serverKey, ca, err := tls.CertSetup(namespace, 3650, tls.CertInfo{
		CommonName: apiSvcName,
		DNSNames:   []string{apiSvcName, fmt.Sprintf("%s.cluster.local", apiSvcName)},
	})
	if err != nil {
		a.r.GetLog().Error(err, "Failed to generate FalconClusterGuard API TLS certificates")
		return err
	}
	sensorSvcName := fmt.Sprintf("%s.%s.svc", pkgcommon.ClusterGuardSensorServiceAccountName, namespace)
	clientCert, clientKey, _, err := tls.CertSetup(namespace, 3650, tls.CertInfo{
		CommonName: "falcon-sensor-client",
		DNSNames:   []string{sensorSvcName},
	})
	if err != nil {
		a.r.GetLog().Error(err, "Failed to generate FalconClusterGuard sensor client TLS certificates")
		return err
	}
	if apierrors.IsNotFound(errAPI) {
		s := assets.Secret(pkgcommon.AdmissionAPITLSSecretName, namespace, pkgcommon.AdmissionComponentName,
			map[string][]byte{"tls.crt": serverCert, "tls.key": serverKey}, corev1.SecretTypeTLS)
		if err := k8sutils.Create(a.r, a.r.GetScheme(), ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, s); err != nil {
			return err
		}
	} else if errAPI != nil {
		a.r.GetLog().Error(errAPI, "Failed to get FalconClusterGuard API TLS Secret")
		return errAPI
	}
	if apierrors.IsNotFound(errCA) {
		s := assets.Secret(pkgcommon.AdmissionAPICASecretName, namespace, pkgcommon.AdmissionComponentName,
			map[string][]byte{"ca.crt": ca}, corev1.SecretTypeOpaque)
		if err := k8sutils.Create(a.r, a.r.GetScheme(), ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, s); err != nil {
			return err
		}
	} else if errCA != nil {
		a.r.GetLog().Error(errCA, "Failed to get FalconClusterGuard API CA Secret")
		return errCA
	}
	if apierrors.IsNotFound(errSensor) {
		s := assets.Secret(pkgcommon.ClusterGuardSensorTLSSecretName, namespace, pkgcommon.AdmissionComponentName,
			map[string][]byte{"tls.crt": clientCert, "tls.key": clientKey}, corev1.SecretTypeTLS)
		if err := k8sutils.Create(a.r, a.r.GetScheme(), ctx, a.cfg.Request, a.r.GetLog(), a.cfg.Owner, a.cfg.Status, s); err != nil {
			return err
		}
	} else if errSensor != nil {
		a.r.GetLog().Error(errSensor, "Failed to get FalconClusterGuard sensor TLS Secret")
		return errSensor
	}
	return nil
}
