package node_sensor_test

import (
	"testing"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	sensor "github.com/crowdstrike/falcon-operator/internal/controller/sensors/node_sensor"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
)

func TestClusterGuardSensorDaemonSetReturnsDS(t *testing.T) {
	cfg := sensor.Config{
		InstallNamespace: "falcon-clusterguard",
		Image:            "quay.io/crowdstrike/falcon-sensor:latest",
	}

	n := sensor.New(nil, cfg)
	ds := n.DaemonSet()

	if ds == nil {
		t.Fatal("expected non-nil DaemonSet")
	}
	if ds.Name != common.ClusterGuardSensorDaemonSetName {
		t.Errorf("expected name %q, got %q", common.ClusterGuardSensorDaemonSetName, ds.Name)
	}
	if ds.Namespace != cfg.InstallNamespace {
		t.Errorf("expected namespace %q, got %q", cfg.InstallNamespace, ds.Namespace)
	}
	if len(ds.Spec.Template.Spec.Containers) != 1 {
		t.Errorf("expected 1 container, got %d", len(ds.Spec.Template.Spec.Containers))
	}
	if ds.Spec.Template.Spec.Containers[0].Image != cfg.Image {
		t.Errorf("expected image %q, got %q", cfg.Image, ds.Spec.Template.Spec.Containers[0].Image)
	}
}

func TestClusterGuardSensorDaemonSetDefaultTerminationGracePeriod(t *testing.T) {
	cfg := sensor.Config{
		InstallNamespace: "falcon-clusterguard",
		Image:            "quay.io/crowdstrike/falcon-sensor:latest",
		// NodeSensor.TerminationGracePeriod is 0 (zero value) -> should default to 60
	}

	n := sensor.New(nil, cfg)
	ds := n.DaemonSet()

	if ds.Spec.Template.Spec.TerminationGracePeriodSeconds == nil {
		t.Fatal("expected non-nil TerminationGracePeriodSeconds")
	}
	if *ds.Spec.Template.Spec.TerminationGracePeriodSeconds != 60 {
		t.Errorf("expected 60, got %d", *ds.Spec.Template.Spec.TerminationGracePeriodSeconds)
	}
}

func TestClusterGuardSensorCleanupDaemonSetReturnsDS(t *testing.T) {
	cfg := sensor.Config{
		InstallNamespace: "falcon-clusterguard",
		Image:            "quay.io/crowdstrike/falcon-sensor:latest",
		ImagePullPolicy:  corev1.PullIfNotPresent,
		ImagePullSecrets: []corev1.LocalObjectReference{{Name: "mysecret"}},
	}

	n := sensor.New(nil, cfg)
	ds := n.CleanupDaemonSet()

	if ds == nil {
		t.Fatal("expected non-nil DaemonSet")
	}
	if ds.Name != common.ClusterGuardSensorCleanupDaemonSetName {
		t.Errorf("expected name %q, got %q", common.ClusterGuardSensorCleanupDaemonSetName, ds.Name)
	}
	if ds.Namespace != cfg.InstallNamespace {
		t.Errorf("expected namespace %q, got %q", cfg.InstallNamespace, ds.Namespace)
	}
	if len(ds.Spec.Template.Spec.InitContainers) != 1 {
		t.Errorf("expected 1 init container, got %d", len(ds.Spec.Template.Spec.InitContainers))
	}
}

func TestBuildResourceRequirementsWithValues(t *testing.T) {
	res := falconv1alpha1.Resources{}
	res.Limits.Memory = "1Gi"
	res.Limits.CPU = "500m"
	res.Requests.Memory = "512Mi"
	res.Requests.CPU = "200m"

	reqs := sensor.BuildResourceRequirements(res)

	if reqs.Limits == nil {
		t.Fatal("expected non-nil Limits")
	}
	if reqs.Requests == nil {
		t.Fatal("expected non-nil Requests")
	}
	if _, ok := reqs.Limits[corev1.ResourceMemory]; !ok {
		t.Error("expected memory limit")
	}
	if _, ok := reqs.Limits[corev1.ResourceCPU]; !ok {
		t.Error("expected cpu limit")
	}
	if _, ok := reqs.Requests[corev1.ResourceMemory]; !ok {
		t.Error("expected memory request")
	}
	if _, ok := reqs.Requests[corev1.ResourceCPU]; !ok {
		t.Error("expected cpu request")
	}
}

func TestBuildResourceRequirementsWithEmptyValues(t *testing.T) {
	res := falconv1alpha1.Resources{}

	reqs := sensor.BuildResourceRequirements(res)

	if len(reqs.Limits) != 0 {
		t.Errorf("expected empty Limits, got %v", reqs.Limits)
	}
	if len(reqs.Requests) != 0 {
		t.Errorf("expected empty Requests, got %v", reqs.Requests)
	}
}
