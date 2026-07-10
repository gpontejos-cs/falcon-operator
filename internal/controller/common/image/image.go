package image

import (
	"context"
	"fmt"
	"os"
	"strings"

	falconv1alpha1 "github.com/crowdstrike/falcon-operator/api/falcon/v1alpha1"
	"github.com/crowdstrike/falcon-operator/pkg/common"
	"github.com/crowdstrike/falcon-operator/pkg/registry/falcon_registry"
	"github.com/crowdstrike/gofalcon/falcon"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Resolver is the minimal interface required to resolve and store the sensor image.
type Resolver interface {
	GetK8sReader() client.Reader
	Status() client.StatusWriter
}

// Config holds the spec fields needed to resolve the sensor image URI.
type Config struct {
	Image               string
	FalconAPI           *falconv1alpha1.FalconAPI
	FalconSecret        falconv1alpha1.FalconSecret
	Version             *string
	RelatedImageEnvVar  string
}

// URI resolves the full image URI for the sensor image.
func URI(ctx context.Context, r Resolver, cfg Config, status *falconv1alpha1.FalconCRStatus, obj client.Object) (string, error) {
	if cfg.Image != "" {
		return cfg.Image, nil
	}

	clusterGuardImage := os.Getenv(cfg.RelatedImageEnvVar)
	if clusterGuardImage != "" && (cfg.FalconAPI == nil || !cfg.FalconSecret.Enabled) {
		return clusterGuardImage, nil
	}

	imageTag, err := SetTag(ctx, r, cfg, status, obj)
	if err != nil {
		return "", fmt.Errorf("failed to set Falcon Cloud Guard Image version: %v", err)
	}

	cloud, err := cfg.FalconAPI.FalconCloudWithSecret(ctx, r.GetK8sReader(), cfg.FalconSecret)
	if err != nil {
		return "", err
	}

	registryURI := falcon.FalconContainerSensorImageURI(cloud, falcon.KacSensor)

	semver := strings.Split(imageTag, "-")[0]
	if !falcon_registry.IsMinimumUnifiedSensorVersion(semver, falcon.KacSensor) {
		registryURI = falcon.FalconContainerSensorImageURI(cloud, falcon.RegionedKacSensor)
	}

	return fmt.Sprintf("%s:%s", registryURI, imageTag), nil
}

// SetTag resolves and stores the sensor image tag in status, returning the tag.
func SetTag(ctx context.Context, r Resolver, cfg Config, status *falconv1alpha1.FalconCRStatus, obj client.Object) (string, error) {
	if versionLock(cfg, status) {
		if tag, err := getTag(status); err == nil {
			return tag, err
		}
	}

	if cfg.Image != "" {
		status.Sensor = common.ImageVersion(cfg.Image)
		return *status.Sensor, r.Status().Update(ctx, obj)
	}

	if os.Getenv(cfg.RelatedImageEnvVar) != "" && (cfg.FalconAPI == nil || !cfg.FalconSecret.Enabled) {
		img := os.Getenv(cfg.RelatedImageEnvVar)
		status.Sensor = common.ImageVersion(img)
		return *status.Sensor, r.Status().Update(ctx, obj)
	}

	apiConfig, err := apiConfigFor(ctx, r, cfg)
	if err != nil {
		return "", err
	}

	registry, err := falcon_registry.NewFalconRegistry(ctx, apiConfig)
	if err != nil {
		return "", err
	}

	tag, err := registry.LastContainerTag(ctx, falcon.KacSensor, cfg.Version)
	if err == nil {
		status.Sensor = common.ImageVersion(tag)
	}

	return tag, err
}

func getTag(status *falconv1alpha1.FalconCRStatus) (string, error) {
	if status.Sensor != nil && *status.Sensor != "" {
		return *status.Sensor, nil
	}
	return "", fmt.Errorf("unable to get falcon cloud guard container image version")
}

func apiConfigFor(ctx context.Context, r Resolver, cfg Config) (*falcon.ApiConfig, error) {
	apiCfg, err := cfg.FalconAPI.ApiConfigWithSecret(ctx, r.GetK8sReader(), cfg.FalconSecret)
	apiCfg.Context = ctx
	return apiCfg, err
}

func versionLock(cfg Config, status *falconv1alpha1.FalconCRStatus) bool {
	return (cfg.Version != nil && status.Sensor != nil && strings.Contains(*status.Sensor, *cfg.Version)) || (cfg.Version == nil && status.Sensor != nil)
}
