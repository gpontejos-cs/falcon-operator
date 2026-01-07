package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type MultiClusterClient struct {
	client         *api.Client
	clusterID      string
	authPath       string
	role           string
	serviceAccount string
	tokenPath      string
	authInfo       *api.Secret
	tokenIssueTime time.Time // Track when the token was issued
	logger         logr.Logger
}

type ClientConfig struct {
	VaultAddress            string
	ClusterID               string
	Role                    string
	AuthPath                string
	ServiceAccount          string
	ServiceAccountNamespace string
	TokenPath               string
	TLSConfig               *TLSConfig
}

type TLSConfig struct {
	CAData             []byte
	ClientCertData     []byte
	ClientKeyData      []byte
	InsecureSkipVerify bool
}

func NewMultiClusterClient(config ClientConfig) (*MultiClusterClient, error) {
	logger := log.Log.WithName("vault-client").WithValues("cluster", config.ClusterID)

	// Create Vault API config
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = config.VaultAddress

	// Configure TLS if provided
	if config.TLSConfig != nil {
		tlsClientConfig, err := buildTLSConfig(config.TLSConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}

		transport := &http.Transport{
			TLSClientConfig: tlsClientConfig,
		}
		vaultConfig.HttpClient.Transport = transport
	}

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Determine auth path
	authPath := config.AuthPath
	if authPath == "" {
		authPath = fmt.Sprintf("kubernetes-%s", config.ClusterID)
	}

	// Determine token path
	tokenPath := config.TokenPath
	if tokenPath == "" {
		tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}

	return &MultiClusterClient{
		client:         client,
		clusterID:      config.ClusterID,
		authPath:       authPath,
		role:           config.Role,
		serviceAccount: config.ServiceAccount,
		tokenPath:      tokenPath,
		logger:         logger,
	}, nil
}

func buildTLSConfig(config *TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
	}

	// Load CA certificate
	if len(config.CAData) > 0 {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(config.CAData) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate
	if len(config.ClientCertData) > 0 && len(config.ClientKeyData) > 0 {
		cert, err := tls.X509KeyPair(config.ClientCertData, config.ClientKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

func (c *MultiClusterClient) Authenticate(ctx context.Context) error {
	c.logger.Info("Authenticating with Vault", "authPath", c.authPath, "role", c.role)

	// Check if we have a valid token
	if c.isTokenValid() {
		c.logger.V(1).Info("Using existing valid token")
		return nil
	}

	// Try to renew existing token
	if c.authInfo != nil && c.authInfo.Auth != nil && c.authInfo.Auth.Renewable {
		err := c.renewToken(ctx)
		if err == nil {
			c.logger.Info("Successfully renewed existing token")
			return nil
		}
		c.logger.V(1).Info("Token renewal failed, will re-authenticate", "error", err)
	}

	// Perform fresh authentication
	return c.authenticateWithKubernetes(ctx)
}

func (c *MultiClusterClient) authenticateWithKubernetes(ctx context.Context) error {
	// Read service account token
	tokenBytes, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return fmt.Errorf("failed to read service account token from %s: %w", c.tokenPath, err)
	}

	// Create Kubernetes auth method
	k8sAuth, err := kubernetes.NewKubernetesAuth(
		c.role,
		kubernetes.WithServiceAccountToken(string(tokenBytes)),
		kubernetes.WithMountPath(c.authPath),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize kubernetes auth: %w", err)
	}

	// Authenticate with Vault
	c.logger.Info("Performing Kubernetes authentication", "authPath", c.authPath)
	authInfo, err := c.client.Auth().Login(ctx, k8sAuth)
	if err != nil {
		return fmt.Errorf("failed to authenticate with vault using path %s: %w", c.authPath, err)
	}

	// Store auth info and set token
	c.authInfo = authInfo
	c.tokenIssueTime = time.Now() // Record when we got the token
	c.client.SetToken(authInfo.Auth.ClientToken)

	c.logger.Info("Successfully authenticated with Vault",
		"ttl", authInfo.Auth.LeaseDuration,
		"renewable", authInfo.Auth.Renewable)

	return nil
}

func (c *MultiClusterClient) isTokenValid() bool {
	if c.client.Token() == "" {
		return false
	}

	if c.authInfo == nil || c.authInfo.Auth == nil {
		return false
	}

	// Check if we have a valid issue time
	if c.tokenIssueTime.IsZero() {
		return false
	}

	// Check if token is expired (with 5 minute buffer)
	bufferTime := 5 * time.Minute
	tokenDuration := time.Duration(c.authInfo.Auth.LeaseDuration) * time.Second
	tokenExpiryTime := c.tokenIssueTime.Add(tokenDuration)

	return time.Now().Add(bufferTime).Before(tokenExpiryTime)
}

func (c *MultiClusterClient) renewToken(ctx context.Context) error {
	if c.authInfo == nil || c.authInfo.Auth == nil {
		return fmt.Errorf("no authentication info available")
	}

	if !c.authInfo.Auth.Renewable {
		return fmt.Errorf("token is not renewable")
	}

	c.logger.V(1).Info("Renewing Vault token")
	secret, err := c.client.Auth().Token().RenewSelf(int(c.authInfo.Auth.LeaseDuration))
	if err != nil {
		return fmt.Errorf("failed to renew token: %w", err)
	}

	c.authInfo.Auth = secret.Auth
	c.tokenIssueTime = time.Now() // Update issue time for renewed token
	c.logger.Info("Successfully renewed token", "newTTL", secret.Auth.LeaseDuration)

	return nil
}

func (c *MultiClusterClient) GetSecret(ctx context.Context, path, key string, clusterSpecific bool) (string, error) {
	secretPath := path

	// Try cluster-specific path first if requested
	if clusterSpecific {
		clusterPath := fmt.Sprintf("%s/%s", c.clusterID, path)
		if value, err := c.getSecretFromPath(ctx, clusterPath, key); err == nil {
			c.logger.V(1).Info("Retrieved cluster-specific secret", "path", clusterPath)
			return value, nil
		}
		c.logger.V(1).Info("Cluster-specific secret not found, trying global path",
			"clusterPath", clusterPath, "globalPath", path)
	}

	// Try global path
	return c.getSecretFromPath(ctx, secretPath, key)
}

func (c *MultiClusterClient) getSecretFromPath(ctx context.Context, path, key string) (string, error) {
	secret, err := c.client.KVv2("secret").Get(ctx, path)
	if err != nil {
		return "", fmt.Errorf("failed to read secret %s: %w", path, err)
	}

	value, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s", key, path)
	}

	valueStr, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("value for key %s is not a string", key)
	}

	return valueStr, nil
}

func (c *MultiClusterClient) GetClusterID() string {
	return c.clusterID
}

func (c *MultiClusterClient) GetAuthPath() string {
	return c.authPath
}

func (c *MultiClusterClient) IsAuthenticated() bool {
	return c.client.Token() != "" && c.isTokenValid()
}
