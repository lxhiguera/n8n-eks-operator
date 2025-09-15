/*
miniCopyright 2024.

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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/go-redis/redis/v8"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// ElastiCacheManager implements the CacheManager interface for AWS ElastiCache Redis
type ElastiCacheManager struct {
	client               client.Client
	awsConfig            aws.Config
	elastiCacheClient    *elasticache.Client
	secretsManagerClient *secretsmanager.Client
}

// NewElastiCacheManager creates a new ElastiCacheManager instance
func NewElastiCacheManager(client client.Client, awsConfig aws.Config) *ElastiCacheManager {
	return &ElastiCacheManager{
		client:               client,
		awsConfig:            awsConfig,
		elastiCacheClient:    elasticache.NewFromConfig(awsConfig),
		secretsManagerClient: secretsmanager.NewFromConfig(awsConfig),
	}
}

// ReconcileCache ensures cache configuration is correct
func (m *ElastiCacheManager) ReconcileCache(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Reconciling ElastiCache Redis configuration")

	// Extract cache configuration from N8nInstance
	cacheConfig, err := m.extractCacheConfig(instance)
	if err != nil {
		logger.Error(err, "Failed to extract cache configuration")
		return fmt.Errorf("failed to extract cache configuration: %w", err)
	}

	// Validate ElastiCache cluster exists and is available
	if err := m.validateElastiCacheCluster(ctx, cacheConfig); err != nil {
		logger.Error(err, "ElastiCache cluster validation failed")
		return fmt.Errorf("ElastiCache cluster validation failed: %w", err)
	}

	// Validate connection to Redis
	if err := m.ValidateConnection(ctx, cacheConfig); err != nil {
		logger.Error(err, "Redis connection validation failed")
		return fmt.Errorf("Redis connection validation failed: %w", err)
	}

	// Create or update Kubernetes secret with Redis credentials
	if err := m.createRedisSecret(ctx, instance, cacheConfig); err != nil {
		logger.Error(err, "Failed to create Redis secret")
		return fmt.Errorf("failed to create Redis secret: %w", err)
	}

	// Configure TTL policies
	if err := m.ConfigureTTL(ctx, cacheConfig); err != nil {
		logger.Error(err, "Failed to configure TTL policies")
		return fmt.Errorf("failed to configure TTL policies: %w", err)
	}

	logger.Info("ElastiCache Redis configuration reconciled successfully")
	return nil
}

// ValidateConnection validates cache connectivity
func (m *ElastiCacheManager) ValidateConnection(ctx context.Context, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Validating Redis connection", "endpoint", config.Endpoint, "port", config.Port)

	// Get Redis credentials
	credentials, err := m.getRedisCredentials(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to get Redis credentials: %w", err)
	}

	// Create Redis client
	redisClient, err := m.createRedisClient(config, credentials)
	if err != nil {
		return fmt.Errorf("failed to create Redis client: %w", err)
	}
	defer redisClient.Close()

	// Test connection with PING
	if err := m.testRedisConnection(ctx, redisClient); err != nil {
		return fmt.Errorf("Redis connection test failed: %w", err)
	}

	logger.Info("Redis connection validated successfully")
	return nil
}

// GetConnectionString returns the cache connection string
func (m *ElastiCacheManager) GetConnectionString(ctx context.Context, config CacheConfig) (string, error) {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")

	// Get Redis credentials
	credentials, err := m.getRedisCredentials(ctx, config)
	if err != nil {
		return "", fmt.Errorf("failed to get Redis credentials: %w", err)
	}

	// Build connection string based on configuration
	var connectionString string
	if config.TLSEnabled {
		if config.AuthEnabled && credentials.Password != "" {
			connectionString = fmt.Sprintf("rediss://:%s@%s:%d", credentials.Password, config.Endpoint, config.Port)
		} else {
			connectionString = fmt.Sprintf("rediss://%s:%d", config.Endpoint, config.Port)
		}
	} else {
		if config.AuthEnabled && credentials.Password != "" {
			connectionString = fmt.Sprintf("redis://:%s@%s:%d", credentials.Password, config.Endpoint, config.Port)
		} else {
			connectionString = fmt.Sprintf("redis://%s:%d", config.Endpoint, config.Port)
		}
	}

	logger.Info("Generated Redis connection string", "endpoint", config.Endpoint, "tls", config.TLSEnabled, "auth", config.AuthEnabled)
	return connectionString, nil
}

// ConfigureTTL configures TTL policies
func (m *ElastiCacheManager) ConfigureTTL(ctx context.Context, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Configuring TTL policies", "defaultTTL", config.TTLDefault)

	// Get Redis credentials
	credentials, err := m.getRedisCredentials(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to get Redis credentials: %w", err)
	}

	// Create Redis client
	redisClient, err := m.createRedisClient(config, credentials)
	if err != nil {
		return fmt.Errorf("failed to create Redis client: %w", err)
	}
	defer redisClient.Close()

	// Configure default TTL policies for n8n specific keys
	ttlPolicies := map[string]time.Duration{
		"n8n:cache:*":     config.TTLDefault,
		"n8n:session:*":   24 * time.Hour,
		"n8n:workflow:*":  config.TTLDefault,
		"n8n:execution:*": 7 * 24 * time.Hour, // Keep execution data longer
	}

	// Note: Redis doesn't support pattern-based TTL configuration
	// This would be handled at the application level in n8n
	// Here we just validate that we can set TTL on test keys
	for pattern, ttl := range ttlPolicies {
		testKey := strings.Replace(pattern, "*", "test", 1)
		if err := redisClient.Set(ctx, testKey, "test-value", ttl).Err(); err != nil {
			logger.Error(err, "Failed to set test key with TTL", "key", testKey, "ttl", ttl)
			return fmt.Errorf("failed to configure TTL for pattern %s: %w", pattern, err)
		}
		// Clean up test key
		redisClient.Del(ctx, testKey)
	}

	logger.Info("TTL policies configured successfully")
	return nil
}

// extractCacheConfig extracts cache configuration from N8nInstance
func (m *ElastiCacheManager) extractCacheConfig(instance *n8nv1alpha1.N8nInstance) (CacheConfig, error) {
	if instance.Spec.Cache == nil {
		return CacheConfig{}, fmt.Errorf("cache configuration is required")
	}

	cache := instance.Spec.Cache
	if cache.Type != "elasticache-redis" {
		return CacheConfig{}, fmt.Errorf("unsupported cache type: %s", cache.Type)
	}

	if cache.Redis == nil {
		return CacheConfig{}, fmt.Errorf("Redis configuration is required for elasticache-redis type")
	}

	redis := cache.Redis

	// Parse TTL default
	ttlDefault := time.Hour // Default 1 hour
	if redis.TTLDefault != "" {
		if parsed, err := time.ParseDuration(redis.TTLDefault); err == nil {
			ttlDefault = parsed
		}
	}

	config := CacheConfig{
		Type:                 cache.Type,
		Endpoint:             redis.Endpoint,
		Port:                 redis.Port,
		ClusterMode:          redis.ClusterMode,
		AuthEnabled:          redis.AuthEnabled,
		CredentialsSource:    redis.CredentialsSource,
		SecretsManagerArn:    redis.SecretsManagerArn,
		KubernetesSecretName: redis.KubernetesSecretName,
		TLSEnabled:           redis.TLSEnabled,
		TTLDefault:           ttlDefault,
	}

	// Set defaults
	if config.Port == 0 {
		config.Port = 6379
	}

	return config, nil
}

// validateElastiCacheCluster validates that the ElastiCache cluster exists and is available
func (m *ElastiCacheManager) validateElastiCacheCluster(ctx context.Context, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")

	// Extract cluster ID from endpoint
	clusterID := m.extractClusterIDFromEndpoint(config.Endpoint)
	if clusterID == "" {
		return fmt.Errorf("could not extract cluster ID from endpoint: %s", config.Endpoint)
	}

	logger.Info("Validating ElastiCache cluster", "clusterID", clusterID)

	if config.ClusterMode {
		// For cluster mode, use DescribeReplicationGroups
		input := &elasticache.DescribeReplicationGroupsInput{
			ReplicationGroupId: aws.String(clusterID),
		}

		result, err := m.elastiCacheClient.DescribeReplicationGroups(ctx, input)
		if err != nil {
			return fmt.Errorf("failed to describe replication group %s: %w", clusterID, err)
		}

		if len(result.ReplicationGroups) == 0 {
			return fmt.Errorf("replication group %s not found", clusterID)
		}

		replicationGroup := result.ReplicationGroups[0]
		if replicationGroup.Status == nil || *replicationGroup.Status != "available" {
			return fmt.Errorf("replication group %s is not available, current status: %s",
				clusterID, aws.ToString(replicationGroup.Status))
		}

		logger.Info("ElastiCache replication group validated", "clusterID", clusterID, "status", *replicationGroup.Status)
	} else {
		// For standalone mode, use DescribeCacheClusters
		input := &elasticache.DescribeCacheClustersInput{
			CacheClusterId: aws.String(clusterID),
		}

		result, err := m.elastiCacheClient.DescribeCacheClusters(ctx, input)
		if err != nil {
			return fmt.Errorf("failed to describe cache cluster %s: %w", clusterID, err)
		}

		if len(result.CacheClusters) == 0 {
			return fmt.Errorf("cache cluster %s not found", clusterID)
		}

		cacheCluster := result.CacheClusters[0]
		if cacheCluster.CacheClusterStatus == nil || *cacheCluster.CacheClusterStatus != "available" {
			return fmt.Errorf("cache cluster %s is not available, current status: %s",
				clusterID, aws.ToString(cacheCluster.CacheClusterStatus))
		}

		logger.Info("ElastiCache cluster validated", "clusterID", clusterID, "status", *cacheCluster.CacheClusterStatus)
	}

	return nil
}

// extractClusterIDFromEndpoint extracts cluster ID from ElastiCache endpoint
func (m *ElastiCacheManager) extractClusterIDFromEndpoint(endpoint string) string {
	// ElastiCache endpoints typically follow patterns like:
	// my-cluster.abc123.cache.amazonaws.com
	// my-cluster.abc123.clustercfg.cache.amazonaws.com (cluster mode)
	parts := strings.Split(endpoint, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// RedisCredentials holds Redis authentication credentials
type RedisCredentials struct {
	Password  string `json:"password"`
	AuthToken string `json:"auth_token"`
}

// getRedisCredentials retrieves Redis credentials from the configured source
func (m *ElastiCacheManager) getRedisCredentials(ctx context.Context, config CacheConfig) (*RedisCredentials, error) {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")

	if !config.AuthEnabled {
		logger.Info("Redis authentication is disabled")
		return &RedisCredentials{}, nil
	}

	switch config.CredentialsSource {
	case "secrets-manager":
		return m.getCredentialsFromSecretsManager(ctx, config.SecretsManagerArn)
	case "kubernetes-secret":
		return m.getCredentialsFromKubernetesSecret(ctx, config.KubernetesSecretName)
	default:
		return nil, fmt.Errorf("unsupported credentials source: %s", config.CredentialsSource)
	}
}

// getCredentialsFromSecretsManager retrieves credentials from AWS Secrets Manager
func (m *ElastiCacheManager) getCredentialsFromSecretsManager(ctx context.Context, secretArn string) (*RedisCredentials, error) {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Retrieving Redis credentials from Secrets Manager", "secretArn", secretArn)

	if secretArn == "" {
		return nil, fmt.Errorf("secrets manager ARN is required")
	}

	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretArn),
	}

	result, err := m.secretsManagerClient.GetSecretValue(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret from Secrets Manager: %w", err)
	}

	if result.SecretString == nil {
		return nil, fmt.Errorf("secret value is empty")
	}

	var credentials RedisCredentials
	if err := json.Unmarshal([]byte(*result.SecretString), &credentials); err != nil {
		return nil, fmt.Errorf("failed to parse Redis credentials JSON: %w", err)
	}

	logger.Info("Redis credentials retrieved from Secrets Manager successfully")
	return &credentials, nil
}

// getCredentialsFromKubernetesSecret retrieves credentials from Kubernetes Secret
func (m *ElastiCacheManager) getCredentialsFromKubernetesSecret(ctx context.Context, secretName string) (*RedisCredentials, error) {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Retrieving Redis credentials from Kubernetes Secret", "secretName", secretName)

	if secretName == "" {
		return nil, fmt.Errorf("kubernetes secret name is required")
	}

	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{
		Namespace: "default", // TODO: Make namespace configurable
		Name:      secretName,
	}

	if err := m.client.Get(ctx, secretKey, secret); err != nil {
		return nil, fmt.Errorf("failed to get Kubernetes secret: %w", err)
	}

	credentials := &RedisCredentials{}

	if password, exists := secret.Data["password"]; exists {
		credentials.Password = string(password)
	}

	if authToken, exists := secret.Data["auth_token"]; exists {
		credentials.AuthToken = string(authToken)
	}

	// Use auth_token if available, otherwise use password
	if credentials.AuthToken != "" {
		credentials.Password = credentials.AuthToken
	}

	logger.Info("Redis credentials retrieved from Kubernetes Secret successfully")
	return credentials, nil
}

// createRedisClient creates a Redis client with the given configuration
func (m *ElastiCacheManager) createRedisClient(config CacheConfig, credentials *RedisCredentials) (*redis.Client, error) {
	options := &redis.Options{
		Addr: fmt.Sprintf("%s:%d", config.Endpoint, config.Port),
	}

	// Configure authentication
	if config.AuthEnabled && credentials.Password != "" {
		options.Password = credentials.Password
	}

	// Configure TLS
	if config.TLSEnabled {
		options.TLSConfig = &tls.Config{
			ServerName: config.Endpoint,
		}
	}

	// Configure timeouts
	options.DialTimeout = 10 * time.Second
	options.ReadTimeout = 5 * time.Second
	options.WriteTimeout = 5 * time.Second

	// Configure connection pool
	options.PoolSize = 10
	options.MinIdleConns = 2
	options.MaxConnAge = 30 * time.Minute
	options.PoolTimeout = 10 * time.Second
	options.IdleTimeout = 5 * time.Minute

	return redis.NewClient(options), nil
}

// testRedisConnection tests the Redis connection
func (m *ElastiCacheManager) testRedisConnection(ctx context.Context, client *redis.Client) error {
	// Test basic connectivity with PING
	if err := client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("Redis PING failed: %w", err)
	}

	// Test basic operations
	testKey := "n8n:operator:connection-test"
	testValue := fmt.Sprintf("test-%d", time.Now().Unix())

	// Test SET operation
	if err := client.Set(ctx, testKey, testValue, time.Minute).Err(); err != nil {
		return fmt.Errorf("Redis SET operation failed: %w", err)
	}

	// Test GET operation
	result, err := client.Get(ctx, testKey).Result()
	if err != nil {
		return fmt.Errorf("Redis GET operation failed: %w", err)
	}

	if result != testValue {
		return fmt.Errorf("Redis GET returned unexpected value: expected %s, got %s", testValue, result)
	}

	// Clean up test key
	client.Del(ctx, testKey)

	return nil
}

// createRedisSecret creates or updates a Kubernetes secret with Redis connection information
func (m *ElastiCacheManager) createRedisSecret(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")

	secretName := fmt.Sprintf("%s-redis", instance.Name)
	logger.Info("Creating Redis secret", "secretName", secretName)

	// Get connection string
	connectionString, err := m.GetConnectionString(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to get connection string: %w", err)
	}

	// Get credentials for individual fields
	credentials, err := m.getRedisCredentials(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to get Redis credentials: %w", err)
	}

	// Prepare secret data
	secretData := map[string][]byte{
		"redis-url":     []byte(connectionString),
		"redis-host":    []byte(config.Endpoint),
		"redis-port":    []byte(strconv.Itoa(config.Port)),
		"redis-tls":     []byte(strconv.FormatBool(config.TLSEnabled)),
		"redis-cluster": []byte(strconv.FormatBool(config.ClusterMode)),
	}

	if config.AuthEnabled && credentials.Password != "" {
		secretData["redis-password"] = []byte(credentials.Password)
	}

	// Create secret object
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "cache",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: secretData,
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, secret, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update secret
	existingSecret := &corev1.Secret{}
	secretKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      secretName,
	}

	if err := m.client.Get(ctx, secretKey, existingSecret); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing secret: %w", err)
		}
		// Secret doesn't exist, create it
		if err := m.client.Create(ctx, secret); err != nil {
			return fmt.Errorf("failed to create Redis secret: %w", err)
		}
		logger.Info("Redis secret created successfully", "secretName", secretName)
	} else {
		// Secret exists, update it
		existingSecret.Data = secretData
		if err := m.client.Update(ctx, existingSecret); err != nil {
			return fmt.Errorf("failed to update Redis secret: %w", err)
		}
		logger.Info("Redis secret updated successfully", "secretName", secretName)
	}

	return nil
}

// validateElastiCacheClusterAdvanced performs advanced validation of ElastiCache cluster
func (m *ElastiCacheManager) validateElastiCacheClusterAdvanced(ctx context.Context, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")

	// Extract cluster ID from endpoint
	clusterID := m.extractClusterIDFromEndpoint(config.Endpoint)
	if clusterID == "" {
		return fmt.Errorf("could not extract cluster ID from endpoint: %s", config.Endpoint)
	}

	logger.Info("Performing advanced ElastiCache cluster validation", "clusterID", clusterID, "clusterMode", config.ClusterMode)

	if config.ClusterMode {
		return m.validateReplicationGroup(ctx, clusterID, config)
	} else {
		return m.validateCacheCluster(ctx, clusterID, config)
	}
}

// validateReplicationGroup validates ElastiCache replication group (cluster mode)
func (m *ElastiCacheManager) validateReplicationGroup(ctx context.Context, replicationGroupID string, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")

	input := &elasticache.DescribeReplicationGroupsInput{
		ReplicationGroupId: aws.String(replicationGroupID),
	}

	result, err := m.elastiCacheClient.DescribeReplicationGroups(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to describe replication group %s: %w", replicationGroupID, err)
	}

	if len(result.ReplicationGroups) == 0 {
		return fmt.Errorf("replication group %s not found", replicationGroupID)
	}

	replicationGroup := result.ReplicationGroups[0]

	// Validate status
	if replicationGroup.Status == nil || *replicationGroup.Status != "available" {
		return fmt.Errorf("replication group %s is not available, current status: %s",
			replicationGroupID, aws.ToString(replicationGroup.Status))
	}

	// Validate engine
	if replicationGroup.CacheNodeType == nil {
		return fmt.Errorf("replication group %s has no cache node type information", replicationGroupID)
	}

	// Validate cluster configuration
	if replicationGroup.ClusterEnabled == nil || !*replicationGroup.ClusterEnabled {
		logger.Warn("Replication group is not in cluster mode", "replicationGroupID", replicationGroupID)
	}

	// Validate auth token configuration
	if config.AuthEnabled {
		if replicationGroup.AuthTokenEnabled == nil || !*replicationGroup.AuthTokenEnabled {
			return fmt.Errorf("replication group %s does not have auth token enabled, but configuration requires authentication", replicationGroupID)
		}
	}

	// Validate TLS configuration
	if config.TLSEnabled {
		if replicationGroup.TransitEncryptionEnabled == nil || !*replicationGroup.TransitEncryptionEnabled {
			return fmt.Errorf("replication group %s does not have transit encryption enabled, but configuration requires TLS", replicationGroupID)
		}
	}

	// Validate node groups
	if len(replicationGroup.NodeGroups) == 0 {
		return fmt.Errorf("replication group %s has no node groups", replicationGroupID)
	}

	for _, nodeGroup := range replicationGroup.NodeGroups {
		if nodeGroup.Status == nil || *nodeGroup.Status != "available" {
			return fmt.Errorf("node group %s in replication group %s is not available, status: %s",
				aws.ToString(nodeGroup.NodeGroupId), replicationGroupID, aws.ToString(nodeGroup.Status))
		}
	}

	logger.Info("Replication group validation successful",
		"replicationGroupID", replicationGroupID,
		"status", aws.ToString(replicationGroup.Status),
		"nodeGroups", len(replicationGroup.NodeGroups))

	return nil
}

// validateCacheCluster validates ElastiCache cache cluster (standalone mode)
func (m *ElastiCacheManager) validateCacheCluster(ctx context.Context, cacheClusterID string, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")

	input := &elasticache.DescribeCacheClustersInput{
		CacheClusterId:    aws.String(cacheClusterID),
		ShowCacheNodeInfo: aws.Bool(true),
	}

	result, err := m.elastiCacheClient.DescribeCacheClusters(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to describe cache cluster %s: %w", cacheClusterID, err)
	}

	if len(result.CacheClusters) == 0 {
		return fmt.Errorf("cache cluster %s not found", cacheClusterID)
	}

	cacheCluster := result.CacheClusters[0]

	// Validate status
	if cacheCluster.CacheClusterStatus == nil || *cacheCluster.CacheClusterStatus != "available" {
		return fmt.Errorf("cache cluster %s is not available, current status: %s",
			cacheClusterID, aws.ToString(cacheCluster.CacheClusterStatus))
	}

	// Validate engine
	if cacheCluster.Engine == nil || *cacheCluster.Engine != "redis" {
		return fmt.Errorf("cache cluster %s is not a Redis cluster, engine: %s",
			cacheClusterID, aws.ToString(cacheCluster.Engine))
	}

	// Validate cache nodes
	if len(cacheCluster.CacheNodes) == 0 {
		return fmt.Errorf("cache cluster %s has no cache nodes", cacheClusterID)
	}

	for _, node := range cacheCluster.CacheNodes {
		if node.CacheNodeStatus == nil || *node.CacheNodeStatus != "available" {
			return fmt.Errorf("cache node %s in cluster %s is not available, status: %s",
				aws.ToString(node.CacheNodeId), cacheClusterID, aws.ToString(node.CacheNodeStatus))
		}
	}

	// Validate endpoint matches configuration
	if cacheCluster.RedisConfiguration != nil && cacheCluster.RedisConfiguration.PrimaryEndpoint != nil {
		expectedEndpoint := *cacheCluster.RedisConfiguration.PrimaryEndpoint.Address
		if !strings.Contains(config.Endpoint, expectedEndpoint) {
			logger.Warn("Endpoint mismatch detected",
				"configEndpoint", config.Endpoint,
				"clusterEndpoint", expectedEndpoint)
		}
	}

	logger.Info("Cache cluster validation successful",
		"cacheClusterID", cacheClusterID,
		"status", aws.ToString(cacheCluster.CacheClusterStatus),
		"nodes", len(cacheCluster.CacheNodes))

	return nil
}

// testRedisConnectionAdvanced performs advanced Redis connection testing
func (m *ElastiCacheManager) testRedisConnectionAdvanced(ctx context.Context, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Performing advanced Redis connection test", "endpoint", config.Endpoint, "clusterMode", config.ClusterMode)

	// Get Redis credentials
	credentials, err := m.getRedisCredentials(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to get Redis credentials: %w", err)
	}

	if config.ClusterMode {
		return m.testClusterModeConnection(ctx, config, credentials)
	} else {
		return m.testStandaloneModeConnection(ctx, config, credentials)
	}
}

// testClusterModeConnection tests Redis connection in cluster mode
func (m *ElastiCacheManager) testClusterModeConnection(ctx context.Context, config CacheConfig, credentials *RedisCredentials) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")

	// For cluster mode, we need to use redis.NewClusterClient
	options := &redis.ClusterOptions{
		Addrs: []string{fmt.Sprintf("%s:%d", config.Endpoint, config.Port)},
	}

	// Configure authentication
	if config.AuthEnabled && credentials.Password != "" {
		options.Password = credentials.Password
	}

	// Configure TLS
	if config.TLSEnabled {
		options.TLSConfig = &tls.Config{
			ServerName: config.Endpoint,
		}
	}

	// Configure timeouts
	options.DialTimeout = 10 * time.Second
	options.ReadTimeout = 5 * time.Second
	options.WriteTimeout = 5 * time.Second

	// Configure connection pool
	options.PoolSize = 10
	options.MinIdleConns = 2
	options.MaxConnAge = 30 * time.Minute
	options.PoolTimeout = 10 * time.Second
	options.IdleTimeout = 5 * time.Minute

	clusterClient := redis.NewClusterClient(options)
	defer clusterClient.Close()

	// Test cluster connectivity
	if err := clusterClient.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("Redis cluster PING failed: %w", err)
	}

	// Test cluster info
	clusterInfo, err := clusterClient.ClusterInfo(ctx).Result()
	if err != nil {
		return fmt.Errorf("Redis CLUSTER INFO failed: %w", err)
	}

	if !strings.Contains(clusterInfo, "cluster_state:ok") {
		return fmt.Errorf("Redis cluster is not in OK state: %s", clusterInfo)
	}

	// Test basic operations across cluster
	testKey := "n8n:operator:cluster-test"
	testValue := fmt.Sprintf("cluster-test-%d", time.Now().Unix())

	// Test SET operation
	if err := clusterClient.Set(ctx, testKey, testValue, time.Minute).Err(); err != nil {
		return fmt.Errorf("Redis cluster SET operation failed: %w", err)
	}

	// Test GET operation
	result, err := clusterClient.Get(ctx, testKey).Result()
	if err != nil {
		return fmt.Errorf("Redis cluster GET operation failed: %w", err)
	}

	if result != testValue {
		return fmt.Errorf("Redis cluster GET returned unexpected value: expected %s, got %s", testValue, result)
	}

	// Clean up test key
	clusterClient.Del(ctx, testKey)

	logger.Info("Redis cluster connection test successful")
	return nil
}

// testStandaloneModeConnection tests Redis connection in standalone mode
func (m *ElastiCacheManager) testStandaloneModeConnection(ctx context.Context, config CacheConfig, credentials *RedisCredentials) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")

	// Create Redis client
	redisClient, err := m.createRedisClient(config, credentials)
	if err != nil {
		return fmt.Errorf("failed to create Redis client: %w", err)
	}
	defer redisClient.Close()

	// Test basic connectivity
	if err := m.testRedisConnection(ctx, redisClient); err != nil {
		return fmt.Errorf("basic Redis connection test failed: %w", err)
	}

	// Test Redis info
	info, err := redisClient.Info(ctx).Result()
	if err != nil {
		return fmt.Errorf("Redis INFO command failed: %w", err)
	}

	// Validate Redis version and configuration
	if !strings.Contains(info, "redis_version:") {
		return fmt.Errorf("Redis INFO does not contain version information")
	}

	// Test memory usage
	memoryInfo, err := redisClient.Info(ctx, "memory").Result()
	if err != nil {
		logger.Warn("Failed to get Redis memory info", "error", err)
	} else {
		logger.Info("Redis memory info retrieved", "info", memoryInfo)
	}

	// Test persistence configuration if applicable
	persistenceInfo, err := redisClient.Info(ctx, "persistence").Result()
	if err != nil {
		logger.Warn("Failed to get Redis persistence info", "error", err)
	} else {
		logger.Info("Redis persistence info retrieved", "info", persistenceInfo)
	}

	logger.Info("Redis standalone connection test successful")
	return nil
}

// detectClusterMode detects whether the Redis instance is running in cluster mode
func (m *ElastiCacheManager) detectClusterMode(ctx context.Context, config CacheConfig) (bool, error) {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")

	// Get Redis credentials
	credentials, err := m.getRedisCredentials(ctx, config)
	if err != nil {
		return false, fmt.Errorf("failed to get Redis credentials: %w", err)
	}

	// Create Redis client
	redisClient, err := m.createRedisClient(config, credentials)
	if err != nil {
		return false, fmt.Errorf("failed to create Redis client: %w", err)
	}
	defer redisClient.Close()

	// Try to execute CLUSTER INFO command
	_, err = redisClient.ClusterInfo(ctx).Result()
	if err != nil {
		if strings.Contains(err.Error(), "This instance has cluster support disabled") {
			logger.Info("Redis instance is in standalone mode")
			return false, nil
		}
		return false, fmt.Errorf("failed to detect cluster mode: %w", err)
	}

	logger.Info("Redis instance is in cluster mode")
	return true, nil
}

// getElastiCacheClusterMetrics retrieves basic metrics from ElastiCache cluster
func (m *ElastiCacheManager) getElastiCacheClusterMetrics(ctx context.Context, config CacheConfig) (map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")

	metrics := make(map[string]interface{})

	// Get Redis credentials
	credentials, err := m.getRedisCredentials(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to get Redis credentials: %w", err)
	}

	// Create Redis client
	redisClient, err := m.createRedisClient(config, credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis client: %w", err)
	}
	defer redisClient.Close()

	// Get basic info
	info, err := redisClient.Info(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get Redis info: %w", err)
	}

	// Parse info for key metrics
	lines := strings.Split(info, "\r\n")
	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				// Store important metrics
				switch key {
				case "redis_version", "used_memory_human", "connected_clients",
					"total_commands_processed", "instantaneous_ops_per_sec",
					"keyspace_hits", "keyspace_misses":
					metrics[key] = value
				}
			}
		}
	}

	// Get database info
	dbSize, err := redisClient.DBSize(ctx).Result()
	if err == nil {
		metrics["db_size"] = dbSize
	}

	logger.Info("Retrieved ElastiCache cluster metrics", "metricsCount", len(metrics))
	return metrics, nil
}

// getAuthToken retrieves authentication token for Redis
func (m *ElastiCacheManager) getAuthToken(ctx context.Context, config CacheConfig) (string, error) {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Retrieving Redis auth token", "credentialsSource", config.CredentialsSource)

	if !config.AuthEnabled {
		logger.Info("Redis authentication is disabled")
		return "", nil
	}

	switch config.CredentialsSource {
	case "secrets-manager":
		return m.getAuthTokenFromSecretsManager(ctx, config.SecretsManagerArn)
	case "kubernetes-secret":
		return m.getAuthTokenFromKubernetesSecret(ctx, config.KubernetesSecretName)
	default:
		return "", fmt.Errorf("unsupported credentials source: %s", config.CredentialsSource)
	}
}

// getAuthTokenFromSecretsManager retrieves auth token from AWS Secrets Manager
func (m *ElastiCacheManager) getAuthTokenFromSecretsManager(ctx context.Context, secretArn string) (string, error) {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Retrieving Redis auth token from Secrets Manager", "secretArn", secretArn)

	if secretArn == "" {
		return "", fmt.Errorf("secrets manager ARN is required")
	}

	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretArn),
	}

	result, err := m.secretsManagerClient.GetSecretValue(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to get secret from Secrets Manager: %w", err)
	}

	if result.SecretString == nil {
		return "", fmt.Errorf("secret value is empty")
	}

	// Try to parse as JSON first
	var credentials map[string]interface{}
	if err := json.Unmarshal([]byte(*result.SecretString), &credentials); err == nil {
		// Check for various auth token field names
		for _, field := range []string{"auth_token", "authToken", "password", "token"} {
			if value, exists := credentials[field]; exists {
				if strValue, ok := value.(string); ok && strValue != "" {
					logger.Info("Redis auth token retrieved from Secrets Manager successfully")
					return strValue, nil
				}
			}
		}
		return "", fmt.Errorf("no valid auth token found in secret JSON")
	}

	// If not JSON, treat as plain text auth token
	authToken := strings.TrimSpace(*result.SecretString)
	if authToken == "" {
		return "", fmt.Errorf("auth token is empty")
	}

	logger.Info("Redis auth token retrieved from Secrets Manager successfully")
	return authToken, nil
}

// getAuthTokenFromKubernetesSecret retrieves auth token from Kubernetes Secret
func (m *ElastiCacheManager) getAuthTokenFromKubernetesSecret(ctx context.Context, secretName string) (string, error) {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Retrieving Redis auth token from Kubernetes Secret", "secretName", secretName)

	if secretName == "" {
		return "", fmt.Errorf("kubernetes secret name is required")
	}

	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{
		Namespace: "default", // TODO: Make namespace configurable
		Name:      secretName,
	}

	if err := m.client.Get(ctx, secretKey, secret); err != nil {
		return "", fmt.Errorf("failed to get Kubernetes secret: %w", err)
	}

	// Check for various auth token field names
	for _, field := range []string{"auth_token", "authToken", "password", "token"} {
		if value, exists := secret.Data[field]; exists && len(value) > 0 {
			authToken := strings.TrimSpace(string(value))
			if authToken != "" {
				logger.Info("Redis auth token retrieved from Kubernetes Secret successfully")
				return authToken, nil
			}
		}
	}

	return "", fmt.Errorf("no valid auth token found in Kubernetes secret")
}

// createRedisSecret creates or updates a Kubernetes secret with Redis authentication information
func (m *ElastiCacheManager) createRedisSecretWithAuth(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")

	secretName := fmt.Sprintf("%s-redis-auth", instance.Name)
	logger.Info("Creating Redis authentication secret", "secretName", secretName)

	// Get auth token
	authToken, err := m.getAuthToken(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to get auth token: %w", err)
	}

	// Prepare secret data
	secretData := map[string][]byte{
		"redis-host":    []byte(config.Endpoint),
		"redis-port":    []byte(strconv.Itoa(config.Port)),
		"redis-tls":     []byte(strconv.FormatBool(config.TLSEnabled)),
		"redis-cluster": []byte(strconv.FormatBool(config.ClusterMode)),
		"redis-auth":    []byte(strconv.FormatBool(config.AuthEnabled)),
	}

	if config.AuthEnabled && authToken != "" {
		secretData["redis-password"] = []byte(authToken)
		secretData["redis-auth-token"] = []byte(authToken)

		// Create connection URLs with authentication
		var redisURL, redissURL string
		if config.TLSEnabled {
			redissURL = fmt.Sprintf("rediss://:%s@%s:%d", authToken, config.Endpoint, config.Port)
			secretData["redis-url-tls"] = []byte(redissURL)
		} else {
			redisURL = fmt.Sprintf("redis://:%s@%s:%d", authToken, config.Endpoint, config.Port)
			secretData["redis-url"] = []byte(redisURL)
		}
	} else {
		// Create connection URLs without authentication
		var redisURL, redissURL string
		if config.TLSEnabled {
			redissURL = fmt.Sprintf("rediss://%s:%d", config.Endpoint, config.Port)
			secretData["redis-url-tls"] = []byte(redissURL)
		} else {
			redisURL = fmt.Sprintf("redis://%s:%d", config.Endpoint, config.Port)
			secretData["redis-url"] = []byte(redisURL)
		}
	}

	// Create secret object
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "cache-auth",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
			Annotations: map[string]string{
				"n8n.io/redis-endpoint":     config.Endpoint,
				"n8n.io/redis-cluster":      strconv.FormatBool(config.ClusterMode),
				"n8n.io/redis-tls":          strconv.FormatBool(config.TLSEnabled),
				"n8n.io/redis-auth":         strconv.FormatBool(config.AuthEnabled),
				"n8n.io/credentials-source": config.CredentialsSource,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: secretData,
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, secret, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update secret
	existingSecret := &corev1.Secret{}
	secretKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      secretName,
	}

	if err := m.client.Get(ctx, secretKey, existingSecret); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing secret: %w", err)
		}
		// Secret doesn't exist, create it
		if err := m.client.Create(ctx, secret); err != nil {
			return fmt.Errorf("failed to create Redis auth secret: %w", err)
		}
		logger.Info("Redis auth secret created successfully", "secretName", secretName)
	} else {
		// Secret exists, update it
		existingSecret.Data = secretData
		existingSecret.Annotations = secret.Annotations
		if err := m.client.Update(ctx, existingSecret); err != nil {
			return fmt.Errorf("failed to update Redis auth secret: %w", err)
		}
		logger.Info("Redis auth secret updated successfully", "secretName", secretName)
	}

	return nil
}

// rotateAuthToken handles rotation of Redis auth tokens
func (m *ElastiCacheManager) rotateAuthToken(ctx context.Context, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Rotating Redis auth token", "credentialsSource", config.CredentialsSource)

	if !config.AuthEnabled {
		logger.Info("Redis authentication is disabled, skipping token rotation")
		return nil
	}

	switch config.CredentialsSource {
	case "secrets-manager":
		return m.rotateAuthTokenInSecretsManager(ctx, config.SecretsManagerArn)
	case "kubernetes-secret":
		logger.Info("Auth token rotation for Kubernetes secrets should be handled externally")
		return nil
	default:
		return fmt.Errorf("unsupported credentials source for rotation: %s", config.CredentialsSource)
	}
}

// rotateAuthTokenInSecretsManager rotates auth token in AWS Secrets Manager
func (m *ElastiCacheManager) rotateAuthTokenInSecretsManager(ctx context.Context, secretArn string) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Initiating auth token rotation in Secrets Manager", "secretArn", secretArn)

	if secretArn == "" {
		return fmt.Errorf("secrets manager ARN is required")
	}

	// Check if rotation is already configured
	input := &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretArn),
	}

	result, err := m.secretsManagerClient.DescribeSecret(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to describe secret: %w", err)
	}

	if result.RotationEnabled == nil || !*result.RotationEnabled {
		logger.Info("Rotation is not enabled for this secret", "secretArn", secretArn)
		return nil
	}

	// Trigger rotation if needed
	rotateInput := &secretsmanager.RotateSecretInput{
		SecretId: aws.String(secretArn),
	}

	_, err = m.secretsManagerClient.RotateSecret(ctx, rotateInput)
	if err != nil {
		return fmt.Errorf("failed to rotate secret: %w", err)
	}

	logger.Info("Auth token rotation initiated successfully", "secretArn", secretArn)
	return nil
}

// configureTLSConnection configures TLS for Redis connections
func (m *ElastiCacheManager) configureTLSConnection(ctx context.Context, config CacheConfig) (*tls.Config, error) {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")

	if !config.TLSEnabled {
		logger.Info("TLS is disabled for Redis connection")
		return nil, nil
	}

	logger.Info("Configuring TLS for Redis connection", "endpoint", config.Endpoint)

	tlsConfig := &tls.Config{
		ServerName: config.Endpoint,
		MinVersion: tls.VersionTLS12, // Enforce minimum TLS 1.2
	}

	// For ElastiCache, we typically don't need client certificates
	// but we want to verify the server certificate
	tlsConfig.InsecureSkipVerify = false

	logger.Info("TLS configuration created successfully")
	return tlsConfig, nil
}

// validateAuthConfiguration validates Redis authentication configuration
func (m *ElastiCacheManager) validateAuthConfiguration(ctx context.Context, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Validating Redis authentication configuration", "authEnabled", config.AuthEnabled)

	if !config.AuthEnabled {
		logger.Info("Redis authentication is disabled")
		return nil
	}

	// Validate credentials source is specified
	if config.CredentialsSource == "" {
		return fmt.Errorf("credentials source is required when authentication is enabled")
	}

	// Validate credentials source specific configuration
	switch config.CredentialsSource {
	case "secrets-manager":
		if config.SecretsManagerArn == "" {
			return fmt.Errorf("secrets manager ARN is required when using secrets-manager credentials source")
		}
		// Validate ARN format
		if !strings.HasPrefix(config.SecretsManagerArn, "arn:aws:secretsmanager:") {
			return fmt.Errorf("invalid secrets manager ARN format: %s", config.SecretsManagerArn)
		}
	case "kubernetes-secret":
		if config.KubernetesSecretName == "" {
			return fmt.Errorf("kubernetes secret name is required when using kubernetes-secret credentials source")
		}
	default:
		return fmt.Errorf("unsupported credentials source: %s", config.CredentialsSource)
	}

	// Test auth token retrieval
	authToken, err := m.getAuthToken(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to retrieve auth token: %w", err)
	}

	if authToken == "" {
		return fmt.Errorf("auth token is empty")
	}

	logger.Info("Redis authentication configuration validated successfully")
	return nil
}

// testAuthenticatedConnection tests Redis connection with authentication
func (m *ElastiCacheManager) testAuthenticatedConnection(ctx context.Context, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Testing authenticated Redis connection", "endpoint", config.Endpoint, "authEnabled", config.AuthEnabled)

	if !config.AuthEnabled {
		logger.Info("Authentication is disabled, performing basic connection test")
		return m.ValidateConnection(ctx, config)
	}

	// Get auth token
	authToken, err := m.getAuthToken(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to get auth token: %w", err)
	}

	if authToken == "" {
		return fmt.Errorf("auth token is empty")
	}

	// Create credentials object
	credentials := &RedisCredentials{
		Password:  authToken,
		AuthToken: authToken,
	}

	// Create Redis client with authentication
	redisClient, err := m.createRedisClient(config, credentials)
	if err != nil {
		return fmt.Errorf("failed to create authenticated Redis client: %w", err)
	}
	defer redisClient.Close()

	// Test authentication by running AUTH command explicitly
	if err := redisClient.Auth(ctx, authToken).Err(); err != nil {
		return fmt.Errorf("Redis AUTH command failed: %w", err)
	}

	// Test basic operations with authenticated client
	if err := m.testRedisConnection(ctx, redisClient); err != nil {
		return fmt.Errorf("authenticated Redis connection test failed: %w", err)
	}

	logger.Info("Authenticated Redis connection test successful")
	return nil
}

// TTLPolicy represents a TTL policy for Redis keys
type TTLPolicy struct {
	Pattern     string        `json:"pattern"`
	TTL         time.Duration `json:"ttl"`
	Description string        `json:"description"`
}

// CacheMetrics represents cache performance metrics
type CacheMetrics struct {
	HitRate           float64 `json:"hit_rate"`
	MissRate          float64 `json:"miss_rate"`
	EvictedKeys       int64   `json:"evicted_keys"`
	ExpiredKeys       int64   `json:"expired_keys"`
	UsedMemory        int64   `json:"used_memory"`
	MaxMemory         int64   `json:"max_memory"`
	MemoryUtilization float64 `json:"memory_utilization"`
	ConnectedClients  int64   `json:"connected_clients"`
	CommandsProcessed int64   `json:"commands_processed"`
	OpsPerSecond      int64   `json:"ops_per_second"`
}

// configureTTLPolicies configures TTL policies for different key patterns
func (m *ElastiCacheManager) configureTTLPolicies(ctx context.Context, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Configuring TTL policies for Redis", "defaultTTL", config.TTLDefault)

	// Define TTL policies for different n8n key patterns
	policies := []TTLPolicy{
		{
			Pattern:     "n8n:cache:*",
			TTL:         config.TTLDefault,
			Description: "General cache data with default TTL",
		},
		{
			Pattern:     "n8n:session:*",
			TTL:         24 * time.Hour,
			Description: "User session data",
		},
		{
			Pattern:     "n8n:workflow:cache:*",
			TTL:         config.TTLDefault,
			Description: "Workflow execution cache",
		},
		{
			Pattern:     "n8n:execution:*",
			TTL:         7 * 24 * time.Hour,
			Description: "Execution history and logs",
		},
		{
			Pattern:     "n8n:webhook:*",
			TTL:         30 * time.Minute,
			Description: "Webhook temporary data",
		},
		{
			Pattern:     "n8n:queue:*",
			TTL:         2 * time.Hour,
			Description: "Job queue data",
		},
		{
			Pattern:     "n8n:lock:*",
			TTL:         5 * time.Minute,
			Description: "Distributed locks",
		},
		{
			Pattern:     "n8n:rate-limit:*",
			TTL:         time.Hour,
			Description: "Rate limiting counters",
		},
	}

	// Get Redis credentials
	credentials, err := m.getRedisCredentials(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to get Redis credentials: %w", err)
	}

	// Create Redis client
	redisClient, err := m.createRedisClient(config, credentials)
	if err != nil {
		return fmt.Errorf("failed to create Redis client: %w", err)
	}
	defer redisClient.Close()

	// Test each TTL policy by setting and verifying test keys
	for _, policy := range policies {
		if err := m.testTTLPolicy(ctx, redisClient, policy); err != nil {
			logger.Error(err, "Failed to test TTL policy", "pattern", policy.Pattern)
			return fmt.Errorf("failed to test TTL policy %s: %w", policy.Pattern, err)
		}
	}

	// Store TTL policies in Redis for application reference
	if err := m.storeTTLPolicies(ctx, redisClient, policies); err != nil {
		logger.Error(err, "Failed to store TTL policies")
		return fmt.Errorf("failed to store TTL policies: %w", err)
	}

	logger.Info("TTL policies configured successfully", "policiesCount", len(policies))
	return nil
}

// testTTLPolicy tests a TTL policy by creating a test key
func (m *ElastiCacheManager) testTTLPolicy(ctx context.Context, client *redis.Client, policy TTLPolicy) error {
	// Create test key based on pattern
	testKey := strings.Replace(policy.Pattern, "*", fmt.Sprintf("test-%d", time.Now().Unix()), 1)
	testValue := fmt.Sprintf("ttl-test-%s", policy.Description)

	// Set key with TTL
	if err := client.Set(ctx, testKey, testValue, policy.TTL).Err(); err != nil {
		return fmt.Errorf("failed to set test key with TTL: %w", err)
	}

	// Verify TTL was set correctly
	ttl, err := client.TTL(ctx, testKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get TTL for test key: %w", err)
	}

	// TTL should be close to the configured value (within 10 seconds tolerance)
	expectedTTL := policy.TTL
	tolerance := 10 * time.Second
	if ttl < expectedTTL-tolerance || ttl > expectedTTL+tolerance {
		return fmt.Errorf("TTL mismatch: expected ~%v, got %v", expectedTTL, ttl)
	}

	// Clean up test key
	client.Del(ctx, testKey)

	return nil
}

// storeTTLPolicies stores TTL policies in Redis for application reference
func (m *ElastiCacheManager) storeTTLPolicies(ctx context.Context, client *redis.Client, policies []TTLPolicy) error {
	policiesKey := "n8n:operator:ttl-policies"

	// Convert policies to JSON
	policiesJSON, err := json.Marshal(policies)
	if err != nil {
		return fmt.Errorf("failed to marshal TTL policies: %w", err)
	}

	// Store policies with a long TTL (24 hours)
	if err := client.Set(ctx, policiesKey, string(policiesJSON), 24*time.Hour).Err(); err != nil {
		return fmt.Errorf("failed to store TTL policies: %w", err)
	}

	return nil
}

// configureEvictionPolicies configures memory eviction policies
func (m *ElastiCacheManager) configureEvictionPolicies(ctx context.Context, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Configuring eviction policies for Redis")

	// Get Redis credentials
	credentials, err := m.getRedisCredentials(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to get Redis credentials: %w", err)
	}

	// Create Redis client
	redisClient, err := m.createRedisClient(config, credentials)
	if err != nil {
		return fmt.Errorf("failed to create Redis client: %w", err)
	}
	defer redisClient.Close()

	// Get current maxmemory-policy
	currentPolicy, err := redisClient.ConfigGet(ctx, "maxmemory-policy").Result()
	if err != nil {
		logger.Warn("Failed to get current maxmemory-policy", "error", err)
	} else {
		logger.Info("Current maxmemory-policy", "policy", currentPolicy)
	}

	// Note: For ElastiCache, memory policies are typically configured at the cluster level
	// We can only read the configuration, not modify it
	// This method serves as validation and monitoring

	// Get memory information
	memoryInfo, err := redisClient.Info(ctx, "memory").Result()
	if err != nil {
		return fmt.Errorf("failed to get memory info: %w", err)
	}

	logger.Info("Redis memory information retrieved", "info", memoryInfo)

	// Parse memory info for key metrics
	memoryMetrics := m.parseMemoryInfo(memoryInfo)
	logger.Info("Memory metrics", "metrics", memoryMetrics)

	// Check if memory usage is approaching limits
	if memoryMetrics.MemoryUtilization > 0.8 {
		logger.Warn("High memory utilization detected", "utilization", memoryMetrics.MemoryUtilization)
	}

	return nil
}

// parseMemoryInfo parses Redis memory info into structured metrics
func (m *ElastiCacheManager) parseMemoryInfo(memoryInfo string) CacheMetrics {
	metrics := CacheMetrics{}

	lines := strings.Split(memoryInfo, "\r\n")
	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch key {
				case "used_memory":
					if val, err := strconv.ParseInt(value, 10, 64); err == nil {
						metrics.UsedMemory = val
					}
				case "maxmemory":
					if val, err := strconv.ParseInt(value, 10, 64); err == nil {
						metrics.MaxMemory = val
					}
				}
			}
		}
	}

	// Calculate memory utilization
	if metrics.MaxMemory > 0 {
		metrics.MemoryUtilization = float64(metrics.UsedMemory) / float64(metrics.MaxMemory)
	}

	return metrics
}

// validateMemoryConfiguration validates Redis memory configuration
func (m *ElastiCacheManager) validateMemoryConfiguration(ctx context.Context, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Validating Redis memory configuration")

	// Get Redis credentials
	credentials, err := m.getRedisCredentials(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to get Redis credentials: %w", err)
	}

	// Create Redis client
	redisClient, err := m.createRedisClient(config, credentials)
	if err != nil {
		return fmt.Errorf("failed to create Redis client: %w", err)
	}
	defer redisClient.Close()

	// Get memory configuration
	maxMemoryResult, err := redisClient.ConfigGet(ctx, "maxmemory").Result()
	if err != nil {
		return fmt.Errorf("failed to get maxmemory configuration: %w", err)
	}

	maxMemoryPolicyResult, err := redisClient.ConfigGet(ctx, "maxmemory-policy").Result()
	if err != nil {
		return fmt.Errorf("failed to get maxmemory-policy configuration: %w", err)
	}

	logger.Info("Memory configuration",
		"maxmemory", maxMemoryResult,
		"maxmemory-policy", maxMemoryPolicyResult)

	// Validate that maxmemory is set (should not be 0 for production)
	if len(maxMemoryResult) >= 2 {
		if maxMemory := maxMemoryResult[1]; maxMemory == "0" {
			logger.Warn("maxmemory is set to 0 (unlimited), this may not be suitable for production")
		}
	}

	// Validate eviction policy
	if len(maxMemoryPolicyResult) >= 2 {
		policy := maxMemoryPolicyResult[1]
		recommendedPolicies := []string{"allkeys-lru", "allkeys-lfu", "volatile-lru", "volatile-lfu"}

		isRecommended := false
		for _, recommended := range recommendedPolicies {
			if policy == recommended {
				isRecommended = true
				break
			}
		}

		if !isRecommended {
			logger.Warn("Current eviction policy may not be optimal for cache workloads", "policy", policy)
		}
	}

	return nil
}

// getCacheMetrics retrieves comprehensive cache performance metrics
func (m *ElastiCacheManager) getCacheMetrics(ctx context.Context, config CacheConfig) (*CacheMetrics, error) {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Retrieving cache performance metrics")

	// Get Redis credentials
	credentials, err := m.getRedisCredentials(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to get Redis credentials: %w", err)
	}

	// Create Redis client
	redisClient, err := m.createRedisClient(config, credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis client: %w", err)
	}
	defer redisClient.Close()

	metrics := &CacheMetrics{}

	// Get stats info
	statsInfo, err := redisClient.Info(ctx, "stats").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get stats info: %w", err)
	}

	// Get memory info
	memoryInfo, err := redisClient.Info(ctx, "memory").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get memory info: %w", err)
	}

	// Get clients info
	clientsInfo, err := redisClient.Info(ctx, "clients").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get clients info: %w", err)
	}

	// Parse all info sections
	m.parseStatsInfo(statsInfo, metrics)
	m.parseMemoryInfoDetailed(memoryInfo, metrics)
	m.parseClientsInfo(clientsInfo, metrics)

	// Calculate derived metrics
	if metrics.HitRate+metrics.MissRate > 0 {
		totalRequests := metrics.HitRate + metrics.MissRate
		metrics.HitRate = metrics.HitRate / totalRequests
		metrics.MissRate = metrics.MissRate / totalRequests
	}

	logger.Info("Cache metrics retrieved successfully",
		"hitRate", metrics.HitRate,
		"memoryUtilization", metrics.MemoryUtilization,
		"connectedClients", metrics.ConnectedClients)

	return metrics, nil
}

// parseStatsInfo parses Redis stats info
func (m *ElastiCacheManager) parseStatsInfo(statsInfo string, metrics *CacheMetrics) {
	lines := strings.Split(statsInfo, "\r\n")
	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch key {
				case "keyspace_hits":
					if val, err := strconv.ParseFloat(value, 64); err == nil {
						metrics.HitRate = val
					}
				case "keyspace_misses":
					if val, err := strconv.ParseFloat(value, 64); err == nil {
						metrics.MissRate = val
					}
				case "evicted_keys":
					if val, err := strconv.ParseInt(value, 10, 64); err == nil {
						metrics.EvictedKeys = val
					}
				case "expired_keys":
					if val, err := strconv.ParseInt(value, 10, 64); err == nil {
						metrics.ExpiredKeys = val
					}
				case "total_commands_processed":
					if val, err := strconv.ParseInt(value, 10, 64); err == nil {
						metrics.CommandsProcessed = val
					}
				case "instantaneous_ops_per_sec":
					if val, err := strconv.ParseInt(value, 10, 64); err == nil {
						metrics.OpsPerSecond = val
					}
				}
			}
		}
	}
}

// parseMemoryInfoDetailed parses Redis memory info in detail
func (m *ElastiCacheManager) parseMemoryInfoDetailed(memoryInfo string, metrics *CacheMetrics) {
	lines := strings.Split(memoryInfo, "\r\n")
	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch key {
				case "used_memory":
					if val, err := strconv.ParseInt(value, 10, 64); err == nil {
						metrics.UsedMemory = val
					}
				case "maxmemory":
					if val, err := strconv.ParseInt(value, 10, 64); err == nil {
						metrics.MaxMemory = val
					}
				}
			}
		}
	}

	// Calculate memory utilization
	if metrics.MaxMemory > 0 {
		metrics.MemoryUtilization = float64(metrics.UsedMemory) / float64(metrics.MaxMemory)
	}
}

// parseClientsInfo parses Redis clients info
func (m *ElastiCacheManager) parseClientsInfo(clientsInfo string, metrics *CacheMetrics) {
	lines := strings.Split(clientsInfo, "\r\n")
	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch key {
				case "connected_clients":
					if val, err := strconv.ParseInt(value, 10, 64); err == nil {
						metrics.ConnectedClients = val
					}
				}
			}
		}
	}
}

// monitorCachePerformance monitors cache performance and logs warnings for issues
func (m *ElastiCacheManager) monitorCachePerformance(ctx context.Context, config CacheConfig) error {
	logger := log.FromContext(ctx).WithName("ElastiCacheManager")
	logger.Info("Monitoring cache performance")

	metrics, err := m.getCacheMetrics(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to get cache metrics: %w", err)
	}

	// Check for performance issues
	if metrics.HitRate < 0.8 {
		logger.Warn("Low cache hit rate detected", "hitRate", metrics.HitRate)
	}

	if metrics.MemoryUtilization > 0.9 {
		logger.Warn("High memory utilization detected", "utilization", metrics.MemoryUtilization)
	}

	if metrics.EvictedKeys > 1000 {
		logger.Warn("High number of evicted keys", "evictedKeys", metrics.EvictedKeys)
	}

	if metrics.ConnectedClients > 100 {
		logger.Warn("High number of connected clients", "connectedClients", metrics.ConnectedClients)
	}

	logger.Info("Cache performance monitoring completed",
		"hitRate", metrics.HitRate,
		"memoryUtilization", metrics.MemoryUtilization,
		"evictedKeys", metrics.EvictedKeys,
		"connectedClients", metrics.ConnectedClients)

	return nil
}
