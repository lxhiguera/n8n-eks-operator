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
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lxhiguera/n8n-eks-operator/internal/managers"
)

// RDSIntegrationTest contains RDS-specific integration tests
type RDSIntegrationTest struct {
	config        *TestConfig
	rdsClient     *rds.Client
	secretsClient *secretsmanager.Client
}

// NewRDSIntegrationTest creates a new RDS integration test instance
func NewRDSIntegrationTest(config *TestConfig) *RDSIntegrationTest {
	return &RDSIntegrationTest{
		config:        config,
		rdsClient:     rds.NewFromConfig(config.AWSConfig),
		secretsClient: secretsmanager.NewFromConfig(config.AWSConfig),
	}
}

// TestRDSClusterDiscovery tests discovering existing RDS clusters
func (r *RDSIntegrationTest) TestRDSClusterDiscovery(t *testing.T) {
	if r.config.ShouldSkipTest("rds") {
		t.Skip("Skipping RDS test - TEST_RDS_CLUSTER_ID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.config.Timeout)
	defer cancel()

	// Test cluster discovery
	output, err := r.rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(r.config.RDSClusterID),
	})
	require.NoError(t, err)
	require.Len(t, output.DBClusters, 1)

	cluster := output.DBClusters[0]
	assert.Equal(t, r.config.RDSClusterID, *cluster.DBClusterIdentifier)
	assert.Equal(t, "available", *cluster.Status)
	assert.NotEmpty(t, *cluster.Endpoint)
	assert.Equal(t, int32(5432), *cluster.Port)
	assert.Equal(t, "aurora-postgresql", *cluster.Engine)

	t.Logf("Successfully discovered RDS cluster: %s", *cluster.DBClusterIdentifier)
	t.Logf("  Endpoint: %s", *cluster.Endpoint)
	t.Logf("  Port: %d", *cluster.Port)
	t.Logf("  Engine: %s", *cluster.Engine)
	t.Logf("  Status: %s", *cluster.Status)
}

// TestRDSClusterInstances tests discovering cluster instances
func (r *RDSIntegrationTest) TestRDSClusterInstances(t *testing.T) {
	if r.config.ShouldSkipTest("rds") {
		t.Skip("Skipping RDS test - TEST_RDS_CLUSTER_ID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.config.Timeout)
	defer cancel()

	// Get cluster instances
	output, err := r.rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
		Filters: []rds.Filter{
			{
				Name:   aws.String("db-cluster-id"),
				Values: []string{r.config.RDSClusterID},
			},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, output.DBInstances)

	for _, instance := range output.DBInstances {
		assert.Equal(t, "available", *instance.DBInstanceStatus)
		assert.Equal(t, r.config.RDSClusterID, *instance.DBClusterIdentifier)

		t.Logf("Found cluster instance: %s", *instance.DBInstanceIdentifier)
		t.Logf("  Class: %s", *instance.DBInstanceClass)
		t.Logf("  Status: %s", *instance.DBInstanceStatus)
	}
}

// TestSecretsManagerCredentials tests retrieving database credentials from Secrets Manager
func (r *RDSIntegrationTest) TestSecretsManagerCredentials(t *testing.T) {
	if r.config.ShouldSkipTest("secrets") || r.config.DBSecretARN == "" {
		t.Skip("Skipping Secrets Manager test - TEST_DB_SECRET_ARN not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.config.Timeout)
	defer cancel()

	// Get secret value
	output, err := r.secretsClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(r.config.DBSecretARN),
	})
	require.NoError(t, err)
	require.NotNil(t, output.SecretString)

	// Parse credentials
	var credentials managers.DatabaseCredentials
	err = json.Unmarshal([]byte(*output.SecretString), &credentials)
	require.NoError(t, err)

	// Validate credential structure
	assert.NotEmpty(t, credentials.Username)
	assert.NotEmpty(t, credentials.Password)
	assert.NotEmpty(t, credentials.Host)
	assert.NotEmpty(t, credentials.DBName)
	assert.Greater(t, credentials.Port, 0)
	assert.Equal(t, "postgres", credentials.Engine)

	t.Logf("Successfully retrieved database credentials from Secrets Manager")
	t.Logf("  Username: %s", credentials.Username)
	t.Logf("  Host: %s", credentials.Host)
	t.Logf("  Port: %d", credentials.Port)
	t.Logf("  Database: %s", credentials.DBName)
	t.Logf("  Engine: %s", credentials.Engine)
}

// TestDatabaseConnectivity tests actual database connectivity (if credentials are available)
func (r *RDSIntegrationTest) TestDatabaseConnectivity(t *testing.T) {
	if r.config.ShouldSkipTest("rds") || r.config.ShouldSkipTest("secrets") || r.config.DBSecretARN == "" {
		t.Skip("Skipping database connectivity test - requires both RDS cluster and secret")
	}

	if r.config.ShouldSkipTest("slow") {
		t.Skip("Skipping slow database connectivity test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.config.Timeout)
	defer cancel()

	// Get credentials
	secretOutput, err := r.secretsClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(r.config.DBSecretARN),
	})
	require.NoError(t, err)

	var credentials managers.DatabaseCredentials
	err = json.Unmarshal([]byte(*secretOutput.SecretString), &credentials)
	require.NoError(t, err)

	// Build connection string
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=require",
		credentials.Username,
		credentials.Password,
		credentials.Host,
		credentials.Port,
		credentials.DBName,
	)

	// Test connection
	db, err := sql.Open("postgres", connStr)
	require.NoError(t, err)
	defer db.Close()

	// Set connection timeout
	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Test ping
	err = db.PingContext(ctx)
	require.NoError(t, err)

	// Test simple query
	var version string
	err = db.QueryRowContext(ctx, "SELECT version()").Scan(&version)
	require.NoError(t, err)
	assert.Contains(t, version, "PostgreSQL")

	t.Logf("Successfully connected to database")
	t.Logf("  PostgreSQL version: %s", version)
}

// TestRDSClusterMetrics tests retrieving RDS cluster metrics
func (r *RDSIntegrationTest) TestRDSClusterMetrics(t *testing.T) {
	if r.config.ShouldSkipTest("rds") {
		t.Skip("Skipping RDS metrics test - TEST_RDS_CLUSTER_ID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.config.Timeout)
	defer cancel()

	// Get cluster details for metrics validation
	output, err := r.rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(r.config.RDSClusterID),
	})
	require.NoError(t, err)
	require.Len(t, output.DBClusters, 1)

	cluster := output.DBClusters[0]

	// Validate cluster has the expected configuration for n8n
	assert.Equal(t, "aurora-postgresql", *cluster.Engine)
	assert.True(t, *cluster.StorageEncrypted, "Storage should be encrypted")
	assert.NotEmpty(t, cluster.AssociatedRoles, "Cluster should have associated IAM roles")

	// Check backup configuration
	assert.Greater(t, *cluster.BackupRetentionPeriod, int32(0), "Backup retention should be configured")
	assert.NotEmpty(t, *cluster.PreferredBackupWindow, "Backup window should be configured")
	assert.NotEmpty(t, *cluster.PreferredMaintenanceWindow, "Maintenance window should be configured")

	t.Logf("RDS cluster configuration validated for n8n usage")
	t.Logf("  Backup retention: %d days", *cluster.BackupRetentionPeriod)
	t.Logf("  Backup window: %s", *cluster.PreferredBackupWindow)
	t.Logf("  Maintenance window: %s", *cluster.PreferredMaintenanceWindow)
	t.Logf("  Storage encrypted: %t", *cluster.StorageEncrypted)
}

// RunRDSIntegrationTests runs all RDS integration tests
func RunRDSIntegrationTests(t *testing.T, config *TestConfig) {
	rdsTest := NewRDSIntegrationTest(config)

	t.Run("RDSClusterDiscovery", rdsTest.TestRDSClusterDiscovery)
	t.Run("RDSClusterInstances", rdsTest.TestRDSClusterInstances)
	t.Run("SecretsManagerCredentials", rdsTest.TestSecretsManagerCredentials)
	t.Run("DatabaseConnectivity", rdsTest.TestDatabaseConnectivity)
	t.Run("RDSClusterMetrics", rdsTest.TestRDSClusterMetrics)
}
