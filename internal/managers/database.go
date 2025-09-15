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
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/go-logr/logr"
	_ "github.com/lib/pq"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// DatabaseManagerImpl implements the DatabaseManager interface
type DatabaseManagerImpl struct {
	awsConfig     aws.Config
	client        client.Client
	logger        logr.Logger
	rdsClient     *rds.Client
	secretsClient *secretsmanager.Client
}

// NewDatabaseManager creates a new DatabaseManager instance
func NewDatabaseManager(awsConfig aws.Config, client client.Client, logger logr.Logger) DatabaseManager {
	return &DatabaseManagerImpl{
		awsConfig:     awsConfig,
		client:        client,
		logger:        logger,
		rdsClient:     rds.NewFromConfig(awsConfig),
		secretsClient: secretsmanager.NewFromConfig(awsConfig),
	}
}

// ReconcileDatabase ensures database configuration is correct
func (m *DatabaseManagerImpl) ReconcileDatabase(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	m.logger.Info("Reconciling database for N8nInstance", "instance", instance.Name)

	// Convert N8nInstance spec to DatabaseConfig
	config, err := m.convertToConfig(instance)
	if err != nil {
		return fmt.Errorf("failed to convert instance spec to database config: %w", err)
	}

	// 1. Validate RDS instance exists and is available
	if err := m.validateRDSInstance(ctx, config.Endpoint); err != nil {
		return fmt.Errorf("RDS validation failed: %w", err)
	}

	// 2. Retrieve or create database credentials
	credentials, err := m.getOrCreateCredentials(ctx, config)
	if err != nil {
		return fmt.Errorf("credential management failed: %w", err)
	}

	// 3. Test database connectivity
	if err := m.testConnection(ctx, config, credentials); err != nil {
		return fmt.Errorf("database connection test failed: %w", err)
	}

	// 4. Create or update Kubernetes secret
	if err := m.createKubernetesSecret(ctx, instance, credentials); err != nil {
		return fmt.Errorf("Kubernetes secret creation failed: %w", err)
	}

	// 5. Setup connection pooling if enabled
	if config.ConnectionPooling.Enabled {
		if err := m.setupConnectionPooling(ctx, instance, config); err != nil {
			return fmt.Errorf("connection pooling setup failed: %w", err)
		}
	}

	// 6. Update instance status
	if err := m.updateInstanceStatus(ctx, instance, config, credentials); err != nil {
		return fmt.Errorf("failed to update instance status: %w", err)
	}

	return nil
}

// ValidateConnection validates database connectivity
func (m *DatabaseManagerImpl) ValidateConnection(ctx context.Context, config DatabaseConfig) error {
	m.logger.Info("Validating database connection", "endpoint", config.Endpoint)

	// Get credentials
	credentials, err := m.getOrCreateCredentials(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to get credentials: %w", err)
	}

	// Test connection
	return m.testConnection(ctx, config, credentials)
}

// GetConnectionString returns the database connection string
func (m *DatabaseManagerImpl) GetConnectionString(ctx context.Context, config DatabaseConfig) (string, error) {
	m.logger.Info("Getting database connection string")

	credentials, err := m.getOrCreateCredentials(ctx, config)
	if err != nil {
		return "", fmt.Errorf("failed to get credentials: %w", err)
	}

	sslMode := config.SSLMode
	if sslMode == "" {
		sslMode = "require"
	}

	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Endpoint,
		config.Port,
		credentials.Username,
		credentials.Password,
		config.DatabaseName,
		sslMode,
	)

	return connStr, nil
}

// RotateCredentials handles credential rotation
func (m *DatabaseManagerImpl) RotateCredentials(ctx context.Context, config DatabaseConfig) error {
	m.logger.Info("Rotating database credentials")

	if config.CredentialsSource != "secrets-manager" {
		return fmt.Errorf("credential rotation is only supported for secrets-manager source")
	}

	// Trigger rotation in AWS Secrets Manager
	input := &secretsmanager.RotateSecretInput{
		SecretId: aws.String(config.SecretsManagerArn),
	}

	_, err := m.secretsClient.RotateSecret(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to rotate secret in AWS Secrets Manager: %w", err)
	}

	m.logger.Info("Successfully triggered credential rotation", "secretArn", config.SecretsManagerArn)
	return nil
}

// convertToConfig converts N8nInstance spec to DatabaseConfig
func (m *DatabaseManagerImpl) convertToConfig(instance *n8nv1alpha1.N8nInstance) (DatabaseConfig, error) {
	if instance.Spec.Database.Type != "rds-postgresql" {
		return DatabaseConfig{}, fmt.Errorf("unsupported database type: %s", instance.Spec.Database.Type)
	}

	if instance.Spec.Database.RDS == nil {
		return DatabaseConfig{}, fmt.Errorf("RDS configuration is required")
	}

	rds := instance.Spec.Database.RDS
	config := DatabaseConfig{
		Type:                 instance.Spec.Database.Type,
		Endpoint:             rds.Endpoint,
		Port:                 int(rds.Port),
		DatabaseName:         rds.DatabaseName,
		CredentialsSource:    rds.CredentialsSource,
		SecretsManagerArn:    rds.SecretsManagerArn,
		KubernetesSecretName: rds.KubernetesSecretName,
		SSLMode:              rds.SSLMode,
	}

	// Set default port if not specified
	if config.Port == 0 {
		config.Port = 5432
	}

	// Convert connection pooling config
	if rds.ConnectionPooling != nil {
		duration, err := time.ParseDuration(rds.ConnectionPooling.IdleTimeout)
		if err != nil {
			duration = 30 * time.Second
		}

		config.ConnectionPooling = ConnectionPoolingConfig{
			Enabled:        rds.ConnectionPooling.Enabled,
			MaxConnections: int(rds.ConnectionPooling.MaxConnections),
			IdleTimeout:    duration,
		}
	}

	return config, nil
}

// validateRDSInstance validates that the RDS instance exists and is available
func (m *DatabaseManagerImpl) validateRDSInstance(ctx context.Context, endpoint string) error {
	m.logger.Info("Validating RDS instance", "endpoint", endpoint)

	// Extract cluster identifier from endpoint
	clusterID := m.extractClusterID(endpoint)
	if clusterID == "" {
		return fmt.Errorf("could not extract cluster ID from endpoint: %s", endpoint)
	}

	// Check if it's a cluster or instance
	if strings.Contains(endpoint, ".cluster-") {
		return m.validateRDSCluster(ctx, clusterID)
	}
	return m.validateRDSDBInstance(ctx, clusterID)
}

// validateRDSCluster validates RDS cluster
func (m *DatabaseManagerImpl) validateRDSCluster(ctx context.Context, clusterID string) error {
	input := &rds.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(clusterID),
	}

	result, err := m.rdsClient.DescribeDBClusters(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to describe RDS cluster: %w", err)
	}

	if len(result.DBClusters) == 0 {
		return fmt.Errorf("RDS cluster %s not found", clusterID)
	}

	cluster := result.DBClusters[0]
	if *cluster.Status != "available" {
		return fmt.Errorf("RDS cluster %s is not available, current status: %s", clusterID, *cluster.Status)
	}

	m.logger.Info("RDS cluster validation successful", "clusterID", clusterID, "status", *cluster.Status)
	return nil
}

// validateRDSDBInstance validates RDS DB instance
func (m *DatabaseManagerImpl) validateRDSDBInstance(ctx context.Context, instanceID string) error {
	input := &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(instanceID),
	}

	result, err := m.rdsClient.DescribeDBInstances(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to describe RDS instance: %w", err)
	}

	if len(result.DBInstances) == 0 {
		return fmt.Errorf("RDS instance %s not found", instanceID)
	}

	instance := result.DBInstances[0]
	if *instance.DBInstanceStatus != "available" {
		return fmt.Errorf("RDS instance %s is not available, current status: %s", instanceID, *instance.DBInstanceStatus)
	}

	m.logger.Info("RDS instance validation successful", "instanceID", instanceID, "status", *instance.DBInstanceStatus)
	return nil
}

// extractClusterID extracts cluster/instance ID from RDS endpoint
func (m *DatabaseManagerImpl) extractClusterID(endpoint string) string {
	// Pattern for cluster endpoints: cluster-name.cluster-xxx.region.rds.amazonaws.com
	// Pattern for instance endpoints: instance-name.xxx.region.rds.amazonaws.com

	parts := strings.Split(endpoint, ".")
	if len(parts) < 4 {
		return ""
	}

	// For cluster endpoints, remove the "cluster-" prefix if present
	clusterID := parts[0]
	if strings.HasPrefix(clusterID, "cluster-") {
		clusterID = strings.TrimPrefix(clusterID, "cluster-")
	}

	return clusterID
}

// getOrCreateCredentials retrieves credentials from the specified source
func (m *DatabaseManagerImpl) getOrCreateCredentials(ctx context.Context, config DatabaseConfig) (*DatabaseCredentials, error) {
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
func (m *DatabaseManagerImpl) getCredentialsFromSecretsManager(ctx context.Context, secretArn string) (*DatabaseCredentials, error) {
	m.logger.Info("Retrieving credentials from AWS Secrets Manager", "secretArn", secretArn)

	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretArn),
	}

	result, err := m.secretsClient.GetSecretValue(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve secret from Secrets Manager: %w", err)
	}

	var credentials DatabaseCredentials
	if err := json.Unmarshal([]byte(*result.SecretString), &credentials); err != nil {
		return nil, fmt.Errorf("failed to parse credentials JSON: %w", err)
	}

	// Validate required fields
	if credentials.Username == "" || credentials.Password == "" {
		return nil, fmt.Errorf("credentials missing required fields (username/password)")
	}

	m.logger.Info("Successfully retrieved credentials from Secrets Manager")
	return &credentials, nil
}

// getCredentialsFromKubernetesSecret retrieves credentials from Kubernetes secret
func (m *DatabaseManagerImpl) getCredentialsFromKubernetesSecret(ctx context.Context, secretName string) (*DatabaseCredentials, error) {
	m.logger.Info("Retrieving credentials from Kubernetes secret", "secretName", secretName)

	// For now, return an error as this should be implemented when we have the namespace context
	return nil, fmt.Errorf("kubernetes secret credentials source not yet implemented")
}

// testConnection tests the database connection
func (m *DatabaseManagerImpl) testConnection(ctx context.Context, config DatabaseConfig, credentials *DatabaseCredentials) error {
	m.logger.Info("Testing database connection", "endpoint", config.Endpoint, "database", config.DatabaseName)

	sslMode := config.SSLMode
	if sslMode == "" {
		sslMode = "require"
	}

	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=10",
		config.Endpoint,
		config.Port,
		credentials.Username,
		credentials.Password,
		config.DatabaseName,
		sslMode,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database connection: %w", err)
	}
	defer db.Close()

	// Set connection timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Test the connection
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	// Test a simple query
	var version string
	err = db.QueryRowContext(ctx, "SELECT version()").Scan(&version)
	if err != nil {
		return fmt.Errorf("failed to query database version: %w", err)
	}

	m.logger.Info("Database connection test successful", "version", version)
	return nil
}

// createKubernetesSecret creates or updates the Kubernetes secret with database credentials
func (m *DatabaseManagerImpl) createKubernetesSecret(ctx context.Context, instance *n8nv1alpha1.N8nInstance, credentials *DatabaseCredentials) error {
	secretName := fmt.Sprintf("n8n-%s-database", instance.Name)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "n8n",
				"app.kubernetes.io/instance":  instance.Name,
				"app.kubernetes.io/component": "database",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"host":     []byte(credentials.Host),
			"port":     []byte(fmt.Sprintf("%d", credentials.Port)),
			"database": []byte(credentials.DBName),
			"username": []byte(credentials.Username),
			"password": []byte(credentials.Password),
		},
	}

	// Set owner reference
	if err := controllerutil.SetControllerReference(instance, secret, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update secret
	existing := &corev1.Secret{}
	err := m.client.Get(ctx, types.NamespacedName{Name: secretName, Namespace: instance.Namespace}, existing)
	if err != nil {
		if apierrors.IsNotFound(err) {
			if err := m.client.Create(ctx, secret); err != nil {
				return fmt.Errorf("failed to create secret: %w", err)
			}
			m.logger.Info("Created database secret", "secretName", secretName)
		} else {
			return fmt.Errorf("failed to get existing secret: %w", err)
		}
	} else {
		existing.Data = secret.Data
		if err := m.client.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}
		m.logger.Info("Updated database secret", "secretName", secretName)
	}

	return nil
}

// setupConnectionPooling configures connection pooling (placeholder for future implementation)
func (m *DatabaseManagerImpl) setupConnectionPooling(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config DatabaseConfig) error {
	m.logger.Info("Setting up connection pooling",
		"maxConnections", config.ConnectionPooling.MaxConnections,
		"idleTimeout", config.ConnectionPooling.IdleTimeout)

	// This would typically involve creating a connection pooler like PgBouncer
	// For now, we'll just log the configuration
	m.logger.Info("Connection pooling configuration applied")
	return nil
}

// updateInstanceStatus updates the N8nInstance status with database information
func (m *DatabaseManagerImpl) updateInstanceStatus(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config DatabaseConfig, credentials *DatabaseCredentials) error {
	if instance.Status.Resources == nil {
		instance.Status.Resources = &n8nv1alpha1.ResourcesStatus{}
	}
	if instance.Status.Resources.Database == nil {
		instance.Status.Resources.Database = &n8nv1alpha1.DatabaseStatus{}
	}

	instance.Status.Resources.Database.Status = "Ready"
	instance.Status.Resources.Database.Endpoint = config.Endpoint

	return nil
}
