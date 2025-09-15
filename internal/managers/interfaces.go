/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package managers

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// DatabaseManager defines the interface for database management operations
type DatabaseManager interface {
	// ReconcileDatabase ensures database configuration is correct
	ReconcileDatabase(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// ValidateConnection validates database connectivity
	ValidateConnection(ctx context.Context, config DatabaseConfig) error

	// GetConnectionString returns the database connection string
	GetConnectionString(ctx context.Context, config DatabaseConfig) (string, error)

	// RotateCredentials handles credential rotation
	RotateCredentials(ctx context.Context, config DatabaseConfig) error
}

// CacheManager defines the interface for cache management operations
type CacheManager interface {
	// ReconcileCache ensures cache configuration is correct
	ReconcileCache(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// ValidateConnection validates cache connectivity
	ValidateConnection(ctx context.Context, config CacheConfig) error

	// GetConnectionString returns the cache connection string
	GetConnectionString(ctx context.Context, config CacheConfig) (string, error)

	// ConfigureTTL configures TTL policies
	ConfigureTTL(ctx context.Context, config CacheConfig) error
}

// StorageManager defines the interface for storage management operations
type StorageManager interface {
	// ReconcileStorage ensures all storage configurations are correct
	ReconcileStorage(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// ReconcileS3Buckets creates and configures S3 buckets
	ReconcileS3Buckets(ctx context.Context, config StorageConfig) error

	// ReconcileCloudFront creates and configures CloudFront distribution
	ReconcileCloudFront(ctx context.Context, config StorageConfig) error

	// ReconcilePersistentVolumes creates and configures persistent volumes
	ReconcilePersistentVolumes(ctx context.Context, config StorageConfig) error

	// ValidateFileUpload validates file uploads against policies
	ValidateFileUpload(ctx context.Context, filename string, size int64, config StorageConfig) error
}

// NetworkManager defines the interface for network management operations
type NetworkManager interface {
	// ReconcileNetworking ensures all networking configurations are correct
	ReconcileNetworking(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// ReconcileDNS creates and configures DNS records
	ReconcileDNS(ctx context.Context, config NetworkingConfig) error

	// ReconcileSSL creates and configures SSL certificates
	ReconcileSSL(ctx context.Context, config NetworkingConfig) error

	// ReconcileIstio creates and configures Istio resources
	ReconcileIstio(ctx context.Context, config NetworkingConfig) error

	// ValidateIstioInstallation validates Istio is properly installed
	ValidateIstioInstallation(ctx context.Context) error
}

// SecurityManager defines the interface for security management operations
type SecurityManager interface {
	// ReconcileSecurity ensures all security configurations are correct
	ReconcileSecurity(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// ReconcileSecrets creates and manages secrets
	ReconcileSecrets(ctx context.Context, config SecurityConfig) error

	// ReconcileIAM creates and configures IAM roles and policies
	ReconcileIAM(ctx context.Context, config SecurityConfig) error

	// ReconcileNetworkPolicies creates and configures network policies
	ReconcileNetworkPolicies(ctx context.Context, config SecurityConfig) error

	// RotateSecrets handles automatic secret rotation
	RotateSecrets(ctx context.Context, config SecurityConfig) error

	// ValidateSecurityCompliance validates security compliance
	ValidateSecurityCompliance(ctx context.Context, config SecurityConfig) error
}

// DeploymentManager defines the interface for deployment management operations
type DeploymentManager interface {
	// ReconcileDeployments ensures all deployments are correct
	ReconcileDeployments(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// ReconcileConfigMaps creates and manages config maps
	ReconcileConfigMaps(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// ReconcileAutoscaling creates and manages HPA resources
	ReconcileAutoscaling(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error
}

// ServicesManager defines the interface for services management operations
type ServicesManager interface {
	// ReconcileServices ensures all services are correct
	ReconcileServices(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// ReconcileIngress creates and manages ingress resources
	ReconcileIngress(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error
}

// MonitoringManager defines the interface for monitoring management operations
type MonitoringManager interface {
	// ReconcileMonitoring ensures all monitoring configurations are correct
	ReconcileMonitoring(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// ReconcilePrometheusMonitoring creates Prometheus monitoring resources
	ReconcilePrometheusMonitoring(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// ReconcileCloudWatchMonitoring creates CloudWatch monitoring resources
	ReconcileCloudWatchMonitoring(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// ReconcileAlerts creates and manages alert rules
	ReconcileAlerts(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error
}

// Configuration types for managers

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Type                 string
	Endpoint             string
	Port                 int
	DatabaseName         string
	CredentialsSource    string
	SecretsManagerArn    string
	KubernetesSecretName string
	SSLMode              string
	ConnectionPooling    ConnectionPoolingConfig
}

// ConnectionPoolingConfig holds connection pooling configuration
type ConnectionPoolingConfig struct {
	Enabled        bool
	MaxConnections int
	IdleTimeout    time.Duration
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	Type                 string
	Endpoint             string
	Port                 int
	ClusterMode          bool
	AuthEnabled          bool
	CredentialsSource    string
	SecretsManagerArn    string
	KubernetesSecretName string
	TLSEnabled           bool
	TTLDefault           time.Duration
}

// StorageConfig holds storage configuration
type StorageConfig struct {
	Workflows  WorkflowsStorageConfig
	Assets     AssetsStorageConfig
	Persistent PersistentStorageConfig
}

// WorkflowsStorageConfig holds workflows storage configuration
type WorkflowsStorageConfig struct {
	Type string
	S3   S3Config
}

// AssetsStorageConfig holds assets storage configuration
type AssetsStorageConfig struct {
	Type       string
	S3         S3Config
	CloudFront CloudFrontConfig
}

// PersistentStorageConfig holds persistent storage configuration
type PersistentStorageConfig struct {
	Type           string
	StorageClass   string
	Size           string
	AutoExpansion  bool
	SnapshotPolicy SnapshotPolicyConfig
}

// S3Config holds S3 configuration
type S3Config struct {
	BucketName       string
	Region           string
	Encryption       EncryptionConfig
	Versioning       bool
	Lifecycle        LifecycleConfig
	AllowedFileTypes []string
	MaxFileSize      string
}

// CloudFrontConfig holds CloudFront configuration
type CloudFrontConfig struct {
	Enabled               bool
	CachePolicyId         string
	OriginRequestPolicyId string
	CustomDomain          string
}

// EncryptionConfig holds encryption configuration
type EncryptionConfig struct {
	Enabled  bool
	KMSKeyId string
}

// LifecycleConfig holds lifecycle configuration
type LifecycleConfig struct {
	Enabled             bool
	TransitionToIA      string
	TransitionToGlacier string
}

// SnapshotPolicyConfig holds snapshot policy configuration
type SnapshotPolicyConfig struct {
	Enabled   bool
	Schedule  string
	Retention string
}

// NetworkingConfig holds networking configuration
type NetworkingConfig struct {
	DNS   DNSConfig
	SSL   SSLConfig
	Istio IstioConfig
}

// DNSConfig holds DNS configuration
type DNSConfig struct {
	Provider string
	Route53  Route53Config
}

// Route53Config holds Route53 configuration
type Route53Config struct {
	HostedZoneId string
	CreateZone   bool
}

// SSLConfig holds SSL configuration
type SSLConfig struct {
	Provider string
	ACM      ACMConfig
}

// ACMConfig holds ACM configuration
type ACMConfig struct {
	CertificateArn   string
	AutoValidation   bool
	ValidationMethod string
}

// IstioConfig holds Istio configuration
type IstioConfig struct {
	Enabled             bool
	Gateway             GatewayConfig
	VirtualService      VirtualServiceConfig
	AuthorizationPolicy AuthorizationPolicyConfig
}

// GatewayConfig holds Gateway configuration
type GatewayConfig struct {
	Name  string
	Hosts []string
}

// VirtualServiceConfig holds VirtualService configuration
type VirtualServiceConfig struct {
	Timeout string
	Retries int
}

// AuthorizationPolicyConfig holds AuthorizationPolicy configuration
type AuthorizationPolicyConfig struct {
	Enabled        bool
	AllowedSources []string
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	SecretsManagement SecretsManagementConfig
	IAM               IAMConfig
	NetworkPolicies   NetworkPoliciesConfig
}

// SecretsManagementConfig holds secrets management configuration
type SecretsManagementConfig struct {
	Provider   string
	Rotation   RotationConfig
	Encryption EncryptionConfig
}

// RotationConfig holds rotation configuration
type RotationConfig struct {
	Enabled  bool
	Schedule string
}

// IAMConfig holds IAM configuration
type IAMConfig struct {
	ServiceAccountName string
	RoleArn            string
	Policies           []string
}

// NetworkPoliciesConfig holds network policies configuration
type NetworkPoliciesConfig struct {
	Enabled        bool
	DenyAll        bool
	AllowedIngress []IngressRule
}

// IngressRule holds ingress rule configuration
type IngressRule struct {
	From  string
	Ports []int
}

// DatabaseCredentials holds database credentials
type DatabaseCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Engine   string `json:"engine"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	DBName   string `json:"dbname"`
}
