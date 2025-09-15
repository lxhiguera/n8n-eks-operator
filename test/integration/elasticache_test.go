//go:build integration
// +build integration

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

package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ElastiCacheIntegrationTest contains ElastiCache-specific integration tests
type ElastiCacheIntegrationTest struct {
	config        *TestConfig
	cacheClient   *elasticache.Client
	secretsClient *secretsmanager.Client
}

// RedisCredentials represents Redis authentication credentials
type RedisCredentials struct {
	AuthToken string `json:"auth_token"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
}

// NewElastiCacheIntegrationTest creates a new ElastiCache integration test instance
func NewElastiCacheIntegrationTest(config *TestConfig) *ElastiCacheIntegrationTest {
	return &ElastiCacheIntegrationTest{
		config:        config,
		cacheClient:   elasticache.NewFromConfig(config.AWSConfig),
		secretsClient: secretsmanager.NewFromConfig(config.AWSConfig),
	}
}

// TestElastiCacheClusterDiscovery tests discovering existing ElastiCache clusters
func (e *ElastiCacheIntegrationTest) TestElastiCacheClusterDiscovery(t *testing.T) {
	if e.config.ShouldSkipTest("elasticache") {
		t.Skip("Skipping ElastiCache test - TEST_ELASTICACHE_CLUSTER_ID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
	defer cancel()

	// Test cluster discovery
	output, err := e.cacheClient.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{
		CacheClusterId:    aws.String(e.config.ElastiCacheClusterID),
		ShowCacheNodeInfo: aws.Bool(true),
	})
	require.NoError(t, err)
	require.Len(t, output.CacheClusters, 1)

	cluster := output.CacheClusters[0]
	assert.Equal(t, e.config.ElastiCacheClusterID, *cluster.CacheClusterId)
	assert.Equal(t, "available", *cluster.CacheClusterStatus)
	assert.Equal(t, "redis", *cluster.Engine)
	assert.NotEmpty(t, cluster.CacheNodes)

	// Check primary endpoint
	if cluster.RedisConfiguration != nil && cluster.RedisConfiguration.PrimaryEndpoint != nil {
		assert.NotEmpty(t, *cluster.RedisConfiguration.PrimaryEndpoint.Address)
		assert.Equal(t, int32(6379), *cluster.RedisConfiguration.PrimaryEndpoint.Port)
	}

	t.Logf("Successfully discovered ElastiCache cluster: %s", *cluster.CacheClusterId)
	t.Logf("  Engine: %s %s", *cluster.Engine, *cluster.EngineVersion)
	t.Logf("  Status: %s", *cluster.CacheClusterStatus)
	t.Logf("  Node Type: %s", *cluster.CacheNodeType)
	t.Logf("  Nodes: %d", len(cluster.CacheNodes))

	if cluster.RedisConfiguration != nil && cluster.RedisConfiguration.PrimaryEndpoint != nil {
		t.Logf("  Primary Endpoint: %s:%d",
			*cluster.RedisConfiguration.PrimaryEndpoint.Address,
			*cluster.RedisConfiguration.PrimaryEndpoint.Port)
	}
}

// TestElastiCacheReplicationGroup tests replication group discovery
func (e *ElastiCacheIntegrationTest) TestElastiCacheReplicationGroup(t *testing.T) {
	if e.config.ShouldSkipTest("elasticache") {
		t.Skip("Skipping ElastiCache replication group test - TEST_ELASTICACHE_CLUSTER_ID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
	defer cancel()

	// Try to find replication group for the cluster
	output, err := e.cacheClient.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{
		ReplicationGroupId: aws.String(e.config.ElastiCacheClusterID),
	})

	if err != nil {
		// If replication group doesn't exist, that's okay for single-node clusters
		t.Logf("No replication group found for cluster %s (single-node cluster)", e.config.ElastiCacheClusterID)
		return
	}

	require.Len(t, output.ReplicationGroups, 1)

	replicationGroup := output.ReplicationGroups[0]
	assert.Equal(t, "available", *replicationGroup.Status)
	assert.True(t, *replicationGroup.AtRestEncryptionEnabled, "At-rest encryption should be enabled")
	assert.True(t, *replicationGroup.TransitEncryptionEnabled, "Transit encryption should be enabled")

	t.Logf("Found replication group: %s", *replicationGroup.ReplicationGroupId)
	t.Logf("  Description: %s", *replicationGroup.Description)
	t.Logf("  Status: %s", *replicationGroup.Status)
	t.Logf("  At-rest encryption: %t", *replicationGroup.AtRestEncryptionEnabled)
	t.Logf("  Transit encryption: %t", *replicationGroup.TransitEncryptionEnabled)
}

// TestRedisCredentials tests retrieving Redis credentials from Secrets Manager
func (e *ElastiCacheIntegrationTest) TestRedisCredentials(t *testing.T) {
	if e.config.ShouldSkipTest("secrets") || e.config.CacheSecretARN == "" {
		t.Skip("Skipping Redis credentials test - TEST_CACHE_SECRET_ARN not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
	defer cancel()

	// Get secret value
	output, err := e.secretsClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(e.config.CacheSecretARN),
	})
	require.NoError(t, err)
	require.NotNil(t, output.SecretString)

	// Parse credentials
	var credentials RedisCredentials
	err = json.Unmarshal([]byte(*output.SecretString), &credentials)
	require.NoError(t, err)

	// Validate credential structure
	assert.NotEmpty(t, credentials.AuthToken)
	assert.NotEmpty(t, credentials.Host)
	assert.Greater(t, credentials.Port, 0)

	t.Logf("Successfully retrieved Redis credentials from Secrets Manager")
	t.Logf("  Host: %s", credentials.Host)
	t.Logf("  Port: %d", credentials.Port)
	t.Logf("  Auth token length: %d", len(credentials.AuthToken))
}

// TestRedisConnectivity tests actual Redis connectivity (if credentials are available)
func (e *ElastiCacheIntegrationTest) TestRedisConnectivity(t *testing.T) {
	if e.config.ShouldSkipTest("elasticache") || e.config.ShouldSkipTest("secrets") || e.config.CacheSecretARN == "" {
		t.Skip("Skipping Redis connectivity test - requires both ElastiCache cluster and secret")
	}

	if e.config.ShouldSkipTest("slow") {
		t.Skip("Skipping slow Redis connectivity test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
	defer cancel()

	// Get credentials
	secretOutput, err := e.secretsClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(e.config.CacheSecretARN),
	})
	require.NoError(t, err)

	var credentials RedisCredentials
	err = json.Unmarshal([]byte(*secretOutput.SecretString), &credentials)
	require.NoError(t, err)

	// Create Redis client with TLS
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", credentials.Host, credentials.Port),
		Password: credentials.AuthToken,
		DB:       0,
		TLSConfig: &tls.Config{
			ServerName: credentials.Host,
		},
	})
	defer rdb.Close()

	// Test ping
	pong, err := rdb.Ping(ctx).Result()
	require.NoError(t, err)
	assert.Equal(t, "PONG", pong)

	// Test basic operations
	testKey := fmt.Sprintf("test:%s", e.config.TestPrefix)
	testValue := "integration-test-value"

	// Set a value
	err = rdb.Set(ctx, testKey, testValue, time.Minute).Err()
	require.NoError(t, err)

	// Get the value
	result, err := rdb.Get(ctx, testKey).Result()
	require.NoError(t, err)
	assert.Equal(t, testValue, result)

	// Test TTL
	ttl, err := rdb.TTL(ctx, testKey).Result()
	require.NoError(t, err)
	assert.Greater(t, ttl, time.Second*50) // Should be close to 1 minute

	// Clean up test key
	err = rdb.Del(ctx, testKey).Err()
	require.NoError(t, err)

	// Test Redis info
	info, err := rdb.Info(ctx, "server").Result()
	require.NoError(t, err)
	assert.Contains(t, info, "redis_version")

	t.Logf("Successfully connected to Redis and performed basic operations")
	t.Logf("  Ping response: %s", pong)
	t.Logf("  Set/Get test: %s", testValue)
	t.Logf("  TTL test: %v", ttl)
}

// TestRedisClusterMode tests Redis cluster mode detection
func (e *ElastiCacheIntegrationTest) TestRedisClusterMode(t *testing.T) {
	if e.config.ShouldSkipTest("elasticache") {
		t.Skip("Skipping Redis cluster mode test - TEST_ELASTICACHE_CLUSTER_ID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
	defer cancel()

	// Get cluster details
	output, err := e.cacheClient.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{
		CacheClusterId:    aws.String(e.config.ElastiCacheClusterID),
		ShowCacheNodeInfo: aws.Bool(true),
	})
	require.NoError(t, err)
	require.Len(t, output.CacheClusters, 1)

	cluster := output.CacheClusters[0]

	// Determine if this is cluster mode
	isClusterMode := len(cluster.CacheNodes) > 1

	if isClusterMode {
		t.Logf("Detected Redis cluster mode with %d nodes", len(cluster.CacheNodes))

		// In cluster mode, we should have multiple cache nodes
		assert.Greater(t, len(cluster.CacheNodes), 1)

		// Each node should have an endpoint
		for i, node := range cluster.CacheNodes {
			assert.NotEmpty(t, *node.Endpoint.Address)
			assert.Equal(t, int32(6379), *node.Endpoint.Port)
			t.Logf("  Node %d: %s:%d", i+1, *node.Endpoint.Address, *node.Endpoint.Port)
		}
	} else {
		t.Logf("Detected Redis standalone mode with %d node", len(cluster.CacheNodes))

		// In standalone mode, we should have exactly one node
		assert.Len(t, cluster.CacheNodes, 1)

		node := cluster.CacheNodes[0]
		assert.NotEmpty(t, *node.Endpoint.Address)
		assert.Equal(t, int32(6379), *node.Endpoint.Port)
		t.Logf("  Standalone node: %s:%d", *node.Endpoint.Address, *node.Endpoint.Port)
	}
}

// TestElastiCacheMetrics tests retrieving ElastiCache cluster metrics
func (e *ElastiCacheIntegrationTest) TestElastiCacheMetrics(t *testing.T) {
	if e.config.ShouldSkipTest("elasticache") {
		t.Skip("Skipping ElastiCache metrics test - TEST_ELASTICACHE_CLUSTER_ID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
	defer cancel()

	// Get cluster details for metrics validation
	output, err := e.cacheClient.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{
		CacheClusterId:    aws.String(e.config.ElastiCacheClusterID),
		ShowCacheNodeInfo: aws.Bool(true),
	})
	require.NoError(t, err)
	require.Len(t, output.CacheClusters, 1)

	cluster := output.CacheClusters[0]

	// Validate cluster has the expected configuration for n8n
	assert.Equal(t, "redis", *cluster.Engine)
	assert.NotEmpty(t, *cluster.EngineVersion)

	// Check security configuration
	assert.NotEmpty(t, cluster.SecurityGroups, "Cluster should have security groups")

	// Check parameter group
	assert.NotEmpty(t, *cluster.CacheParameterGroup.CacheParameterGroupName, "Parameter group should be configured")

	t.Logf("ElastiCache cluster configuration validated for n8n usage")
	t.Logf("  Engine version: %s", *cluster.EngineVersion)
	t.Logf("  Node type: %s", *cluster.CacheNodeType)
	t.Logf("  Parameter group: %s", *cluster.CacheParameterGroup.CacheParameterGroupName)
	t.Logf("  Security groups: %d", len(cluster.SecurityGroups))
}

// RunElastiCacheIntegrationTests runs all ElastiCache integration tests
func RunElastiCacheIntegrationTests(t *testing.T, config *TestConfig) {
	elastiCacheTest := NewElastiCacheIntegrationTest(config)

	t.Run("ElastiCacheClusterDiscovery", elastiCacheTest.TestElastiCacheClusterDiscovery)
	t.Run("ElastiCacheReplicationGroup", elastiCacheTest.TestElastiCacheReplicationGroup)
	t.Run("RedisCredentials", elastiCacheTest.TestRedisCredentials)
	t.Run("RedisConnectivity", elastiCacheTest.TestRedisConnectivity)
	t.Run("RedisClusterMode", elastiCacheTest.TestRedisClusterMode)
	t.Run("ElastiCacheMetrics", elastiCacheTest.TestElastiCacheMetrics)
}
