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
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// S3Manager implements the StorageManager interface for AWS S3, CloudFront and EBS
type S3Manager struct {
	client           client.Client
	awsConfig        aws.Config
	s3Client         *s3.Client
	cloudFrontClient *cloudfront.Client
}

// NewS3Manager creates a new S3Manager instance
func NewS3Manager(client client.Client, awsConfig aws.Config) *S3Manager {
	return &S3Manager{
		client:           client,
		awsConfig:        awsConfig,
		s3Client:         s3.NewFromConfig(awsConfig),
		cloudFrontClient: cloudfront.NewFromConfig(awsConfig),
	}
}

// ReconcileStorage ensures all storage configurations are correct
func (m *S3Manager) ReconcileStorage(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Reconciling storage configuration")

	// Extract storage configuration from N8nInstance
	storageConfig, err := m.extractStorageConfig(instance)
	if err != nil {
		logger.Error(err, "Failed to extract storage configuration")
		return fmt.Errorf("failed to extract storage configuration: %w", err)
	}

	// Reconcile S3 buckets
	if err := m.ReconcileS3Buckets(ctx, storageConfig); err != nil {
		logger.Error(err, "Failed to reconcile S3 buckets")
		return fmt.Errorf("failed to reconcile S3 buckets: %w", err)
	}

	// Reconcile CloudFront distribution
	if err := m.ReconcileCloudFront(ctx, storageConfig); err != nil {
		logger.Error(err, "Failed to reconcile CloudFront")
		return fmt.Errorf("failed to reconcile CloudFront: %w", err)
	}

	// Reconcile persistent volumes
	if err := m.ReconcilePersistentVolumes(ctx, storageConfig); err != nil {
		logger.Error(err, "Failed to reconcile persistent volumes")
		return fmt.Errorf("failed to reconcile persistent volumes: %w", err)
	}

	// Create storage configuration secret
	if err := m.createStorageSecret(ctx, instance, storageConfig); err != nil {
		logger.Error(err, "Failed to create storage secret")
		return fmt.Errorf("failed to create storage secret: %w", err)
	}

	logger.Info("Storage configuration reconciled successfully")
	return nil
}

// ReconcileS3Buckets creates and configures S3 buckets
func (m *S3Manager) ReconcileS3Buckets(ctx context.Context, config StorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Reconciling S3 buckets")

	// Reconcile workflows bucket
	if config.Workflows.Type == "s3" {
		if err := m.reconcileS3Bucket(ctx, config.Workflows.S3, "workflows"); err != nil {
			return fmt.Errorf("failed to reconcile workflows bucket: %w", err)
		}
	}

	// Reconcile assets bucket
	if config.Assets.Type == "s3-cloudfront" {
		if err := m.reconcileS3Bucket(ctx, config.Assets.S3, "assets"); err != nil {
			return fmt.Errorf("failed to reconcile assets bucket: %w", err)
		}
	}

	logger.Info("S3 buckets reconciled successfully")
	return nil
}

// ReconcileCloudFront creates and configures CloudFront distribution
func (m *S3Manager) ReconcileCloudFront(ctx context.Context, config StorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Reconciling CloudFront distribution")

	if config.Assets.Type != "s3-cloudfront" || !config.Assets.CloudFront.Enabled {
		logger.Info("CloudFront is disabled, skipping")
		return nil
	}

	// Check if distribution exists
	distributionId, err := m.findCloudFrontDistribution(ctx, config.Assets.S3.BucketName)
	if err != nil {
		return fmt.Errorf("failed to find CloudFront distribution: %w", err)
	}

	if distributionId == "" {
		// Create new distribution
		distributionId, err = m.createCloudFrontDistribution(ctx, config.Assets)
		if err != nil {
			return fmt.Errorf("failed to create CloudFront distribution: %w", err)
		}
		logger.Info("CloudFront distribution created", "distributionId", distributionId)
	} else {
		// Update existing distribution if needed
		if err := m.updateCloudFrontDistribution(ctx, distributionId, config.Assets); err != nil {
			return fmt.Errorf("failed to update CloudFront distribution: %w", err)
		}
		logger.Info("CloudFront distribution updated", "distributionId", distributionId)
	}

	logger.Info("CloudFront distribution reconciled successfully")
	return nil
}

// ReconcilePersistentVolumes creates and configures persistent volumes
func (m *S3Manager) ReconcilePersistentVolumes(ctx context.Context, config StorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Reconciling persistent volumes")

	if config.Persistent.Type != "ebs-csi" {
		logger.Info("EBS CSI is not configured, skipping persistent volumes")
		return nil
	}

	// Create or update StorageClass
	if err := m.reconcileStorageClass(ctx, config.Persistent); err != nil {
		return fmt.Errorf("failed to reconcile storage class: %w", err)
	}

	logger.Info("Persistent volumes reconciled successfully")
	return nil
}

// ValidateFileUpload validates file uploads against policies
func (m *S3Manager) ValidateFileUpload(ctx context.Context, filename string, size int64, config StorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Validating file upload", "filename", filename, "size", size)

	// Get file extension
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != "" && ext[0] == '.' {
		ext = ext[1:] // Remove the dot
	}

	// Validate file type for assets
	if len(config.Assets.S3.AllowedFileTypes) > 0 {
		allowed := false
		for _, allowedType := range config.Assets.S3.AllowedFileTypes {
			if ext == strings.ToLower(allowedType) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("file type %s is not allowed", ext)
		}
	}

	// Validate file size
	maxSize, err := m.parseFileSize(config.Assets.S3.MaxFileSize)
	if err != nil {
		return fmt.Errorf("failed to parse max file size: %w", err)
	}

	if size > maxSize {
		return fmt.Errorf("file size %d exceeds maximum allowed size %d", size, maxSize)
	}

	logger.Info("File upload validation successful")
	return nil
}

// extractStorageConfig extracts storage configuration from N8nInstance
func (m *S3Manager) extractStorageConfig(instance *n8nv1alpha1.N8nInstance) (StorageConfig, error) {
	if instance.Spec.Storage == nil {
		return StorageConfig{}, fmt.Errorf("storage configuration is required")
	}

	storage := instance.Spec.Storage
	config := StorageConfig{}

	// Extract workflows storage config
	if storage.Workflows != nil {
		config.Workflows = WorkflowsStorageConfig{
			Type: storage.Workflows.Type,
		}
		if storage.Workflows.S3 != nil {
			config.Workflows.S3 = m.extractS3Config(*storage.Workflows.S3)
		}
	}

	// Extract assets storage config
	if storage.Assets != nil {
		config.Assets = AssetsStorageConfig{
			Type: storage.Assets.Type,
		}
		if storage.Assets.S3 != nil {
			config.Assets.S3 = m.extractS3Config(*storage.Assets.S3)
		}
		if storage.Assets.CloudFront != nil {
			config.Assets.CloudFront = CloudFrontConfig{
				Enabled:                storage.Assets.CloudFront.Enabled,
				CachePolicyId:         storage.Assets.CloudFront.CachePolicyId,
				OriginRequestPolicyId: storage.Assets.CloudFront.OriginRequestPolicyId,
				CustomDomain:          storage.Assets.CloudFront.CustomDomain,
			}
		}
	}

	// Extract persistent storage config
	if storage.Persistent != nil {
		config.Persistent = PersistentStorageConfig{
			Type:          storage.Persistent.Type,
			StorageClass:  storage.Persistent.StorageClass,
			Size:          storage.Persistent.Size,
			AutoExpansion: storage.Persistent.AutoExpansion,
		}
		if storage.Persistent.SnapshotPolicy != nil {
			config.Persistent.SnapshotPolicy = SnapshotPolicyConfig{
				Enabled:   storage.Persistent.SnapshotPolicy.Enabled,
				Schedule:  storage.Persistent.SnapshotPolicy.Schedule,
				Retention: storage.Persistent.SnapshotPolicy.Retention,
			}
		}
	}

	return config, nil
}

// extractS3Config extracts S3 configuration from spec
func (m *S3Manager) extractS3Config(s3Spec n8nv1alpha1.S3StorageConfig) S3Config {
	config := S3Config{
		BucketName:       s3Spec.BucketName,
		Region:           s3Spec.Region,
		Versioning:       s3Spec.Versioning,
		AllowedFileTypes: s3Spec.AllowedFileTypes,
		MaxFileSize:      s3Spec.MaxFileSize,
	}

	// Extract encryption config
	if s3Spec.Encryption != nil {
		config.Encryption = EncryptionConfig{
			Enabled:  s3Spec.Encryption.Enabled,
			KMSKeyId: s3Spec.Encryption.KMSKeyId,
		}
	}

	// Extract lifecycle config
	if s3Spec.Lifecycle != nil {
		config.Lifecycle = LifecycleConfig{
			Enabled:             s3Spec.Lifecycle.Enabled,
			TransitionToIA:      s3Spec.Lifecycle.TransitionToIA,
			TransitionToGlacier: s3Spec.Lifecycle.TransitionToGlacier,
		}
	}

	// Set defaults
	if config.MaxFileSize == "" {
		config.MaxFileSize = "10MB"
	}
	if len(config.AllowedFileTypes) == 0 {
		config.AllowedFileTypes = []string{"jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "xls", "xlsx"}
	}

	return config
}

// parseFileSize parses file size string (e.g., "10MB") to bytes
func (m *S3Manager) parseFileSize(sizeStr string) (int64, error) {
	if sizeStr == "" {
		return 10 * 1024 * 1024, nil // Default 10MB
	}

	sizeStr = strings.ToUpper(strings.TrimSpace(sizeStr))
	
	// Parse using Kubernetes resource.Quantity
	quantity, err := resource.ParseQuantity(sizeStr)
	if err != nil {
		return 0, fmt.Errorf("invalid file size format: %s", sizeStr)
	}

	return quantity.Value(), nil
}

///
 reconcileS3Bucket creates or updates an S3 bucket with the specified configuration
func (m *S3Manager) reconcileS3Bucket(ctx context.Context, config S3Config, bucketType string) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Reconciling S3 bucket", "bucket", config.BucketName, "type", bucketType)

	// Check if bucket exists
	exists, err := m.bucketExists(ctx, config.BucketName)
	if err != nil {
		return fmt.Errorf("failed to check if bucket exists: %w", err)
	}

	if !exists {
		// Create bucket
		if err := m.createS3Bucket(ctx, config); err != nil {
			return fmt.Errorf("failed to create S3 bucket: %w", err)
		}
		logger.Info("S3 bucket created", "bucket", config.BucketName)
	}

	// Configure bucket encryption
	if config.Encryption.Enabled {
		if err := m.configureBucketEncryption(ctx, config); err != nil {
			return fmt.Errorf("failed to configure bucket encryption: %w", err)
		}
	}

	// Configure bucket versioning
	if config.Versioning {
		if err := m.configureBucketVersioning(ctx, config.BucketName); err != nil {
			return fmt.Errorf("failed to configure bucket versioning: %w", err)
		}
	}

	// Configure lifecycle policies
	if config.Lifecycle.Enabled {
		if err := m.configureBucketLifecycle(ctx, config); err != nil {
			return fmt.Errorf("failed to configure bucket lifecycle: %w", err)
		}
	}

	// Configure bucket policies based on type
	if err := m.configureBucketPolicies(ctx, config, bucketType); err != nil {
		return fmt.Errorf("failed to configure bucket policies: %w", err)
	}

	// Configure CORS for assets bucket
	if bucketType == "assets" {
		if err := m.configureBucketCORS(ctx, config.BucketName); err != nil {
			return fmt.Errorf("failed to configure bucket CORS: %w", err)
		}
	}

	logger.Info("S3 bucket reconciled successfully", "bucket", config.BucketName)
	return nil
}

// bucketExists checks if an S3 bucket exists
func (m *S3Manager) bucketExists(ctx context.Context, bucketName string) (bool, error) {
	_, err := m.s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		// Check if it's a "not found" error
		if strings.Contains(err.Error(), "NotFound") || strings.Contains(err.Error(), "NoSuchBucket") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// createS3Bucket creates a new S3 bucket
func (m *S3Manager) createS3Bucket(ctx context.Context, config S3Config) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Creating S3 bucket", "bucket", config.BucketName, "region", config.Region)

	input := &s3.CreateBucketInput{
		Bucket: aws.String(config.BucketName),
	}

	// Add location constraint if not in us-east-1
	if config.Region != "" && config.Region != "us-east-1" {
		input.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
			LocationConstraint: s3types.BucketLocationConstraint(config.Region),
		}
	}

	_, err := m.s3Client.CreateBucket(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to create bucket: %w", err)
	}

	// Wait for bucket to be available
	waiter := s3.NewBucketExistsWaiter(m.s3Client)
	if err := waiter.Wait(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(config.BucketName),
	}, 2*time.Minute); err != nil {
		return fmt.Errorf("bucket creation timeout: %w", err)
	}

	logger.Info("S3 bucket created successfully", "bucket", config.BucketName)
	return nil
}

// configureBucketEncryption configures S3 bucket encryption
func (m *S3Manager) configureBucketEncryption(ctx context.Context, config S3Config) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring bucket encryption", "bucket", config.BucketName)

	var serverSideEncryptionConfiguration s3types.ServerSideEncryptionConfiguration

	if config.Encryption.KMSKeyId != "" {
		// Use KMS encryption
		serverSideEncryptionConfiguration.Rules = []s3types.ServerSideEncryptionRule{
			{
				ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
					SSEAlgorithm:   s3types.ServerSideEncryptionAwsKms,
					KMSMasterKeyID: aws.String(config.Encryption.KMSKeyId),
				},
				BucketKeyEnabled: aws.Bool(true),
			},
		}
	} else {
		// Use AES256 encryption
		serverSideEncryptionConfiguration.Rules = []s3types.ServerSideEncryptionRule{
			{
				ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
					SSEAlgorithm: s3types.ServerSideEncryptionAes256,
				},
			},
		}
	}

	input := &s3.PutBucketEncryptionInput{
		Bucket: aws.String(config.BucketName),
		ServerSideEncryptionConfiguration: &serverSideEncryptionConfiguration,
	}

	_, err := m.s3Client.PutBucketEncryption(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to configure bucket encryption: %w", err)
	}

	logger.Info("Bucket encryption configured successfully", "bucket", config.BucketName)
	return nil
}

// configureBucketVersioning configures S3 bucket versioning
func (m *S3Manager) configureBucketVersioning(ctx context.Context, bucketName string) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring bucket versioning", "bucket", bucketName)

	input := &s3.PutBucketVersioningInput{
		Bucket: aws.String(bucketName),
		VersioningConfiguration: &s3types.VersioningConfiguration{
			Status: s3types.BucketVersioningStatusEnabled,
		},
	}

	_, err := m.s3Client.PutBucketVersioning(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to configure bucket versioning: %w", err)
	}

	logger.Info("Bucket versioning configured successfully", "bucket", bucketName)
	return nil
}

// configureBucketLifecycle configures S3 bucket lifecycle policies
func (m *S3Manager) configureBucketLifecycle(ctx context.Context, config S3Config) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring bucket lifecycle", "bucket", config.BucketName)

	// Parse transition periods
	transitionToIA, err := m.parseDuration(config.Lifecycle.TransitionToIA)
	if err != nil {
		return fmt.Errorf("invalid transition to IA duration: %w", err)
	}

	transitionToGlacier, err := m.parseDuration(config.Lifecycle.TransitionToGlacier)
	if err != nil {
		return fmt.Errorf("invalid transition to Glacier duration: %w", err)
	}

	rules := []s3types.LifecycleRule{
		{
			ID:     aws.String("n8n-lifecycle-rule"),
			Status: s3types.ExpirationStatusEnabled,
			Filter: &s3types.LifecycleRuleFilterMemberPrefix{
				Value: "",
			},
			Transitions: []s3types.Transition{
				{
					Days:         aws.Int32(int32(transitionToIA.Hours() / 24)),
					StorageClass: s3types.TransitionStorageClassStandardIa,
				},
				{
					Days:         aws.Int32(int32(transitionToGlacier.Hours() / 24)),
					StorageClass: s3types.TransitionStorageClassGlacier,
				},
			},
		},
	}

	// Add rule for incomplete multipart uploads
	rules = append(rules, s3types.LifecycleRule{
		ID:     aws.String("n8n-multipart-cleanup"),
		Status: s3types.ExpirationStatusEnabled,
		Filter: &s3types.LifecycleRuleFilterMemberPrefix{
			Value: "",
		},
		AbortIncompleteMultipartUpload: &s3types.AbortIncompleteMultipartUpload{
			DaysAfterInitiation: aws.Int32(7),
		},
	})

	input := &s3.PutBucketLifecycleConfigurationInput{
		Bucket: aws.String(config.BucketName),
		LifecycleConfiguration: &s3types.BucketLifecycleConfiguration{
			Rules: rules,
		},
	}

	_, err = m.s3Client.PutBucketLifecycleConfiguration(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to configure bucket lifecycle: %w", err)
	}

	logger.Info("Bucket lifecycle configured successfully", "bucket", config.BucketName)
	return nil
}

// parseDuration parses duration string (e.g., "30d", "90d") to time.Duration
func (m *S3Manager) parseDuration(durationStr string) (time.Duration, error) {
	if durationStr == "" {
		return 0, fmt.Errorf("duration string is empty")
	}

	durationStr = strings.TrimSpace(durationStr)
	
	// Handle days format (e.g., "30d")
	if strings.HasSuffix(durationStr, "d") {
		daysStr := strings.TrimSuffix(durationStr, "d")
		days, err := strconv.Atoi(daysStr)
		if err != nil {
			return 0, fmt.Errorf("invalid days format: %s", durationStr)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	// Try to parse as standard duration
	return time.ParseDuration(durationStr)
}

// configureBucketPolicies configures S3 bucket policies based on bucket type
func (m *S3Manager) configureBucketPolicies(ctx context.Context, config S3Config, bucketType string) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring bucket policies", "bucket", config.BucketName, "type", bucketType)

	var policyDocument string
	var err error

	switch bucketType {
	case "workflows":
		policyDocument, err = m.generateWorkflowsBucketPolicy(config.BucketName)
	case "assets":
		policyDocument, err = m.generateAssetsBucketPolicy(config.BucketName)
	default:
		policyDocument, err = m.generateDefaultBucketPolicy(config.BucketName)
	}

	if err != nil {
		return fmt.Errorf("failed to generate bucket policy: %w", err)
	}

	input := &s3.PutBucketPolicyInput{
		Bucket: aws.String(config.BucketName),
		Policy: aws.String(policyDocument),
	}

	_, err = m.s3Client.PutBucketPolicy(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to configure bucket policy: %w", err)
	}

	logger.Info("Bucket policies configured successfully", "bucket", config.BucketName)
	return nil
}

// generateWorkflowsBucketPolicy generates IAM policy for workflows bucket
func (m *S3Manager) generateWorkflowsBucketPolicy(bucketName string) (string, error) {
	policy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Sid":    "DenyInsecureConnections",
				"Effect": "Deny",
				"Principal": "*",
				"Action":    "s3:*",
				"Resource": []string{
					fmt.Sprintf("arn:aws:s3:::%s", bucketName),
					fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
				},
				"Condition": map[string]interface{}{
					"Bool": map[string]interface{}{
						"aws:SecureTransport": "false",
					},
				},
			},
			{
				"Sid":    "DenyUnencryptedObjectUploads",
				"Effect": "Deny",
				"Principal": "*",
				"Action":    "s3:PutObject",
				"Resource":  fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
				"Condition": map[string]interface{}{
					"StringNotEquals": map[string]interface{}{
						"s3:x-amz-server-side-encryption": "AES256",
					},
				},
			},
		},
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy: %w", err)
	}

	return string(policyJSON), nil
}

// generateAssetsBucketPolicy generates IAM policy for assets bucket
func (m *S3Manager) generateAssetsBucketPolicy(bucketName string) (string, error) {
	policy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Sid":    "DenyInsecureConnections",
				"Effect": "Deny",
				"Principal": "*",
				"Action":    "s3:*",
				"Resource": []string{
					fmt.Sprintf("arn:aws:s3:::%s", bucketName),
					fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
				},
				"Condition": map[string]interface{}{
					"Bool": map[string]interface{}{
						"aws:SecureTransport": "false",
					},
				},
			},
			{
				"Sid":       "AllowCloudFrontAccess",
				"Effect":    "Allow",
				"Principal": map[string]interface{}{
					"Service": "cloudfront.amazonaws.com",
				},
				"Action":   "s3:GetObject",
				"Resource": fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
			},
		},
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy: %w", err)
	}

	return string(policyJSON), nil
}

// generateDefaultBucketPolicy generates default IAM policy for bucket
func (m *S3Manager) generateDefaultBucketPolicy(bucketName string) (string, error) {
	policy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Sid":    "DenyInsecureConnections",
				"Effect": "Deny",
				"Principal": "*",
				"Action":    "s3:*",
				"Resource": []string{
					fmt.Sprintf("arn:aws:s3:::%s", bucketName),
					fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
				},
				"Condition": map[string]interface{}{
					"Bool": map[string]interface{}{
						"aws:SecureTransport": "false",
					},
				},
			},
		},
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy: %w", err)
	}

	return string(policyJSON), nil
}

// configureBucketCORS configures CORS for assets bucket
func (m *S3Manager) configureBucketCORS(ctx context.Context, bucketName string) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring bucket CORS", "bucket", bucketName)

	corsConfiguration := &s3types.CORSConfiguration{
		CORSRules: []s3types.CORSRule{
			{
				AllowedHeaders: []string{"*"},
				AllowedMethods: []string{"GET", "HEAD"},
				AllowedOrigins: []string{"*"},
				ExposeHeaders:  []string{"ETag"},
				MaxAgeSeconds:  aws.Int32(3000),
			},
		},
	}

	input := &s3.PutBucketCorsInput{
		Bucket:            aws.String(bucketName),
		CORSConfiguration: corsConfiguration,
	}

	_, err := m.s3Client.PutBucketCors(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to configure bucket CORS: %w", err)
	}

	logger.Info("Bucket CORS configured successfully", "bucket", bucketName)
	return nil
}

// findCl
oudFrontDistribution finds existing CloudFront distribution for the bucket
func (m *S3Manager) findCloudFrontDistribution(ctx context.Context, bucketName string) (string, error) {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Finding CloudFront distribution", "bucket", bucketName)

	input := &cloudfront.ListDistributionsInput{}
	
	result, err := m.cloudFrontClient.ListDistributions(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to list distributions: %w", err)
	}

	if result.DistributionList == nil {
		return "", nil
	}

	// Look for distribution with matching origin
	originDomainName := fmt.Sprintf("%s.s3.amazonaws.com", bucketName)
	
	for _, distribution := range result.DistributionList.Items {
		if distribution.Origins != nil {
			for _, origin := range distribution.Origins.Items {
				if origin.DomainName != nil && *origin.DomainName == originDomainName {
					if distribution.Id != nil {
						logger.Info("Found existing CloudFront distribution", "distributionId", *distribution.Id)
						return *distribution.Id, nil
					}
				}
			}
		}
	}

	logger.Info("No existing CloudFront distribution found")
	return "", nil
}

// createCloudFrontDistribution creates a new CloudFront distribution
func (m *S3Manager) createCloudFrontDistribution(ctx context.Context, config AssetsStorageConfig) (string, error) {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Creating CloudFront distribution", "bucket", config.S3.BucketName)

	// Create Origin Access Identity (OAI) for S3 access
	oaiId, err := m.createOriginAccessIdentity(ctx, config.S3.BucketName)
	if err != nil {
		return "", fmt.Errorf("failed to create origin access identity: %w", err)
	}

	// Build distribution configuration
	distributionConfig := &types.DistributionConfig{
		CallerReference: aws.String(fmt.Sprintf("n8n-assets-%d", time.Now().Unix())),
		Comment:         aws.String(fmt.Sprintf("n8n assets distribution for %s", config.S3.BucketName)),
		Enabled:         aws.Bool(true),
		
		Origins: &types.Origins{
			Quantity: aws.Int32(1),
			Items: []types.Origin{
				{
					Id:         aws.String("S3-" + config.S3.BucketName),
					DomainName: aws.String(fmt.Sprintf("%s.s3.amazonaws.com", config.S3.BucketName)),
					S3OriginConfig: &types.S3OriginConfig{
						OriginAccessIdentity: aws.String(fmt.Sprintf("origin-access-identity/cloudfront/%s", oaiId)),
					},
				},
			},
		},
		
		DefaultCacheBehavior: &types.DefaultCacheBehavior{
			TargetOriginId:       aws.String("S3-" + config.S3.BucketName),
			ViewerProtocolPolicy: types.ViewerProtocolPolicyRedirectToHttps,
			MinTTL:              aws.Int64(0),
			DefaultTTL:          aws.Int64(86400),  // 1 day
			MaxTTL:              aws.Int64(31536000), // 1 year
			
			ForwardedValues: &types.ForwardedValues{
				QueryString: aws.Bool(false),
				Cookies: &types.CookiePreference{
					Forward: types.ItemSelectionNone,
				},
			},
			
			TrustedSigners: &types.TrustedSigners{
				Enabled:  aws.Bool(false),
				Quantity: aws.Int32(0),
			},
		},
		
		PriceClass: types.PriceClassPriceClassAll,
	}

	// Configure cache policy if specified
	if config.CloudFront.CachePolicyId != "" {
		distributionConfig.DefaultCacheBehavior.CachePolicyId = aws.String(config.CloudFront.CachePolicyId)
		// Remove ForwardedValues when using cache policy
		distributionConfig.DefaultCacheBehavior.ForwardedValues = nil
	}

	// Configure origin request policy if specified
	if config.CloudFront.OriginRequestPolicyId != "" {
		distributionConfig.DefaultCacheBehavior.OriginRequestPolicyId = aws.String(config.CloudFront.OriginRequestPolicyId)
	}

	// Configure custom domain if specified
	if config.CloudFront.CustomDomain != "" {
		distributionConfig.Aliases = &types.Aliases{
			Quantity: aws.Int32(1),
			Items:    []string{config.CloudFront.CustomDomain},
		}
	}

	input := &cloudfront.CreateDistributionInput{
		DistributionConfig: distributionConfig,
	}

	result, err := m.cloudFrontClient.CreateDistribution(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to create distribution: %w", err)
	}

	if result.Distribution == nil || result.Distribution.Id == nil {
		return "", fmt.Errorf("distribution creation returned no ID")
	}

	distributionId := *result.Distribution.Id
	logger.Info("CloudFront distribution created", "distributionId", distributionId)

	// Wait for distribution to be deployed
	waiter := cloudfront.NewDistributionDeployedWaiter(m.cloudFrontClient)
	if err := waiter.Wait(ctx, &cloudfront.GetDistributionInput{
		Id: aws.String(distributionId),
	}, 15*time.Minute); err != nil {
		logger.Warn("Distribution deployment timeout, but distribution was created", "distributionId", distributionId)
	}

	return distributionId, nil
}

// createOriginAccessIdentity creates an Origin Access Identity for CloudFront
func (m *S3Manager) createOriginAccessIdentity(ctx context.Context, bucketName string) (string, error) {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Creating Origin Access Identity", "bucket", bucketName)

	config := &types.OriginAccessIdentityConfig{
		CallerReference: aws.String(fmt.Sprintf("n8n-oai-%s-%d", bucketName, time.Now().Unix())),
		Comment:         aws.String(fmt.Sprintf("OAI for n8n assets bucket %s", bucketName)),
	}

	input := &cloudfront.CreateOriginAccessIdentityInput{
		OriginAccessIdentityConfig: config,
	}

	result, err := m.cloudFrontClient.CreateOriginAccessIdentity(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to create origin access identity: %w", err)
	}

	if result.OriginAccessIdentity == nil || result.OriginAccessIdentity.Id == nil {
		return "", fmt.Errorf("origin access identity creation returned no ID")
	}

	oaiId := *result.OriginAccessIdentity.Id
	logger.Info("Origin Access Identity created", "oaiId", oaiId)

	return oaiId, nil
}

// updateCloudFrontDistribution updates an existing CloudFront distribution
func (m *S3Manager) updateCloudFrontDistribution(ctx context.Context, distributionId string, config AssetsStorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Updating CloudFront distribution", "distributionId", distributionId)

	// Get current distribution configuration
	getResult, err := m.cloudFrontClient.GetDistribution(ctx, &cloudfront.GetDistributionInput{
		Id: aws.String(distributionId),
	})
	if err != nil {
		return fmt.Errorf("failed to get distribution: %w", err)
	}

	if getResult.Distribution == nil || getResult.Distribution.DistributionConfig == nil {
		return fmt.Errorf("distribution configuration is nil")
	}

	distributionConfig := getResult.Distribution.DistributionConfig
	etag := getResult.ETag

	// Update cache policy if specified
	if config.CloudFront.CachePolicyId != "" {
		distributionConfig.DefaultCacheBehavior.CachePolicyId = aws.String(config.CloudFront.CachePolicyId)
	}

	// Update origin request policy if specified
	if config.CloudFront.OriginRequestPolicyId != "" {
		distributionConfig.DefaultCacheBehavior.OriginRequestPolicyId = aws.String(config.CloudFront.OriginRequestPolicyId)
	}

	// Update custom domain if specified
	if config.CloudFront.CustomDomain != "" {
		distributionConfig.Aliases = &types.Aliases{
			Quantity: aws.Int32(1),
			Items:    []string{config.CloudFront.CustomDomain},
		}
	}

	input := &cloudfront.UpdateDistributionInput{
		Id:                 aws.String(distributionId),
		DistributionConfig: distributionConfig,
		IfMatch:           etag,
	}

	_, err = m.cloudFrontClient.UpdateDistribution(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to update distribution: %w", err)
	}

	logger.Info("CloudFront distribution updated successfully", "distributionId", distributionId)
	return nil
}

// reconcileStorageClass creates or updates StorageClass for EBS CSI
func (m *S3Manager) reconcileStorageClass(ctx context.Context, config PersistentStorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Reconciling StorageClass", "storageClass", config.StorageClass)

	storageClassName := config.StorageClass
	if storageClassName == "" {
		storageClassName = "gp3"
	}

	// Check if StorageClass already exists
	existingStorageClass := &storagev1.StorageClass{}
	storageClassKey := client.ObjectKey{Name: fmt.Sprintf("n8n-%s", storageClassName)}

	if err := m.client.Get(ctx, storageClassKey, existingStorageClass); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing StorageClass: %w", err)
		}
		
		// StorageClass doesn't exist, create it
		if err := m.createStorageClass(ctx, config); err != nil {
			return fmt.Errorf("failed to create StorageClass: %w", err)
		}
		logger.Info("StorageClass created successfully", "storageClass", storageClassName)
	} else {
		logger.Info("StorageClass already exists", "storageClass", storageClassName)
	}

	return nil
}

// createStorageClass creates a new StorageClass for EBS CSI
func (m *S3Manager) createStorageClass(ctx context.Context, config PersistentStorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	
	storageClassName := config.StorageClass
	if storageClassName == "" {
		storageClassName = "gp3"
	}

	// Configure parameters based on storage class type
	parameters := map[string]string{
		"type": storageClassName,
	}

	// Add gp3 specific parameters
	if storageClassName == "gp3" {
		parameters["iops"] = "3000"
		parameters["throughput"] = "125"
	}

	// Configure volume expansion
	allowVolumeExpansion := config.AutoExpansion

	storageClass := &storagev1.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("n8n-%s", storageClassName),
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/component":  "storage",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Provisioner:          "ebs.csi.aws.com",
		Parameters:           parameters,
		AllowVolumeExpansion: &allowVolumeExpansion,
		VolumeBindingMode:    &[]storagev1.VolumeBindingMode{storagev1.VolumeBindingWaitForFirstConsumer}[0],
		ReclaimPolicy:        &[]corev1.PersistentVolumeReclaimPolicy{corev1.PersistentVolumeReclaimDelete}[0],
	}

	if err := m.client.Create(ctx, storageClass); err != nil {
		return fmt.Errorf("failed to create StorageClass: %w", err)
	}

	logger.Info("StorageClass created successfully", "name", storageClass.Name)
	return nil
}

// createStorageSecret creates a Kubernetes secret with storage configuration
func (m *S3Manager) createStorageSecret(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config StorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	
	secretName := fmt.Sprintf("%s-storage", instance.Name)
	logger.Info("Creating storage secret", "secretName", secretName)

	// Prepare secret data
	secretData := map[string][]byte{}

	// Add workflows storage configuration
	if config.Workflows.Type == "s3" {
		secretData["workflows-bucket"] = []byte(config.Workflows.S3.BucketName)
		secretData["workflows-region"] = []byte(config.Workflows.S3.Region)
		secretData["workflows-type"] = []byte("s3")
	}

	// Add assets storage configuration
	if config.Assets.Type == "s3-cloudfront" {
		secretData["assets-bucket"] = []byte(config.Assets.S3.BucketName)
		secretData["assets-region"] = []byte(config.Assets.S3.Region)
		secretData["assets-type"] = []byte("s3-cloudfront")
		
		// Add CloudFront configuration if enabled
		if config.Assets.CloudFront.Enabled {
			secretData["assets-cloudfront-enabled"] = []byte("true")
			if config.Assets.CloudFront.CustomDomain != "" {
				secretData["assets-cloudfront-domain"] = []byte(config.Assets.CloudFront.CustomDomain)
			}
		}
	}

	// Add persistent storage configuration
	if config.Persistent.Type == "ebs-csi" {
		secretData["persistent-type"] = []byte("ebs-csi")
		secretData["persistent-storage-class"] = []byte(fmt.Sprintf("n8n-%s", config.Persistent.StorageClass))
		secretData["persistent-size"] = []byte(config.Persistent.Size)
		secretData["persistent-auto-expansion"] = []byte(strconv.FormatBool(config.Persistent.AutoExpansion))
	}

	// Create secret object
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "storage",
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
			return fmt.Errorf("failed to create storage secret: %w", err)
		}
		logger.Info("Storage secret created successfully", "secretName", secretName)
	} else {
		// Secret exists, update it
		existingSecret.Data = secretData
		if err := m.client.Update(ctx, existingSecret); err != nil {
			return fmt.Errorf("failed to update storage secret: %w", err)
		}
		logger.Info("Storage secret updated successfully", "secretName", secretName)
	}

	return nil
}

// crea
teOrUpdateBucket creates or updates S3 buckets for different purposes
func (m *S3Manager) createOrUpdateBucket(ctx context.Context, bucketName, bucketType string, config S3Config) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Creating or updating S3 bucket", "bucket", bucketName, "type", bucketType)

	// Check if bucket exists
	exists, err := m.bucketExists(ctx, bucketName)
	if err != nil {
		return fmt.Errorf("failed to check if bucket exists: %w", err)
	}

	if !exists {
		// Create bucket with specific configuration for type
		if err := m.createTypedS3Bucket(ctx, bucketName, bucketType, config); err != nil {
			return fmt.Errorf("failed to create typed S3 bucket: %w", err)
		}
	}

	// Apply type-specific configurations
	switch bucketType {
	case "workflows":
		return m.configureWorkflowsBucket(ctx, bucketName, config)
	case "assets":
		return m.configureAssetsBucket(ctx, bucketName, config)
	case "backups":
		return m.configureBackupsBucket(ctx, bucketName, config)
	default:
		return m.configureDefaultBucket(ctx, bucketName, config)
	}
}

// createTypedS3Bucket creates S3 bucket with type-specific initial configuration
func (m *S3Manager) createTypedS3Bucket(ctx context.Context, bucketName, bucketType string, config S3Config) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Creating typed S3 bucket", "bucket", bucketName, "type", bucketType)

	// Create basic bucket
	if err := m.createS3Bucket(ctx, config); err != nil {
		return fmt.Errorf("failed to create basic S3 bucket: %w", err)
	}

	// Add type-specific tags
	tags := m.generateBucketTags(bucketType)
	if err := m.setBucketTags(ctx, bucketName, tags); err != nil {
		logger.Warn("Failed to set bucket tags", "error", err)
	}

	// Configure public access block (always block public access for security)
	if err := m.configureBucketPublicAccessBlock(ctx, bucketName); err != nil {
		return fmt.Errorf("failed to configure public access block: %w", err)
	}

	logger.Info("Typed S3 bucket created successfully", "bucket", bucketName, "type", bucketType)
	return nil
}

// configureWorkflowsBucket configures S3 bucket specifically for workflows
func (m *S3Manager) configureWorkflowsBucket(ctx context.Context, bucketName string, config S3Config) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring workflows bucket", "bucket", bucketName)

	// Enable versioning for workflow history
	if err := m.configureBucketVersioning(ctx, bucketName); err != nil {
		return fmt.Errorf("failed to configure versioning: %w", err)
	}

	// Configure encryption (mandatory for workflows)
	encryptionConfig := config.Encryption
	if !encryptionConfig.Enabled {
		// Force encryption for workflows
		encryptionConfig.Enabled = true
	}
	if err := m.configureBucketEncryption(ctx, S3Config{
		BucketName: bucketName,
		Encryption: encryptionConfig,
	}); err != nil {
		return fmt.Errorf("failed to configure encryption: %w", err)
	}

	// Configure lifecycle for workflow data
	workflowLifecycle := LifecycleConfig{
		Enabled:             true,
		TransitionToIA:      "30d",  // Move to IA after 30 days
		TransitionToGlacier: "90d",  // Move to Glacier after 90 days
	}
	if err := m.configureBucketLifecycle(ctx, S3Config{
		BucketName: bucketName,
		Lifecycle:  workflowLifecycle,
	}); err != nil {
		return fmt.Errorf("failed to configure lifecycle: %w", err)
	}

	// Configure notification for workflow changes (optional)
	if err := m.configureWorkflowNotifications(ctx, bucketName); err != nil {
		logger.Warn("Failed to configure workflow notifications", "error", err)
	}

	logger.Info("Workflows bucket configured successfully", "bucket", bucketName)
	return nil
}

// configureAssetsBucket configures S3 bucket specifically for assets
func (m *S3Manager) configureAssetsBucket(ctx context.Context, bucketName string, config S3Config) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring assets bucket", "bucket", bucketName)

	// Configure CORS for web access
	if err := m.configureBucketCORS(ctx, bucketName); err != nil {
		return fmt.Errorf("failed to configure CORS: %w", err)
	}

	// Configure encryption
	if config.Encryption.Enabled {
		if err := m.configureBucketEncryption(ctx, config); err != nil {
			return fmt.Errorf("failed to configure encryption: %w", err)
		}
	}

	// Configure lifecycle for assets (longer retention)
	assetsLifecycle := LifecycleConfig{
		Enabled:             true,
		TransitionToIA:      "60d",  // Move to IA after 60 days
		TransitionToGlacier: "180d", // Move to Glacier after 180 days
	}
	if err := m.configureBucketLifecycle(ctx, S3Config{
		BucketName: bucketName,
		Lifecycle:  assetsLifecycle,
	}); err != nil {
		return fmt.Errorf("failed to configure lifecycle: %w", err)
	}

	// Configure intelligent tiering for cost optimization
	if err := m.configureIntelligentTiering(ctx, bucketName); err != nil {
		logger.Warn("Failed to configure intelligent tiering", "error", err)
	}

	logger.Info("Assets bucket configured successfully", "bucket", bucketName)
	return nil
}

// configureBackupsBucket configures S3 bucket specifically for backups
func (m *S3Manager) configureBackupsBucket(ctx context.Context, bucketName string, config S3Config) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring backups bucket", "bucket", bucketName)

	// Enable versioning for backup history
	if err := m.configureBucketVersioning(ctx, bucketName); err != nil {
		return fmt.Errorf("failed to configure versioning: %w", err)
	}

	// Configure encryption (mandatory for backups)
	encryptionConfig := config.Encryption
	if !encryptionConfig.Enabled {
		// Force encryption for backups
		encryptionConfig.Enabled = true
	}
	if err := m.configureBucketEncryption(ctx, S3Config{
		BucketName: bucketName,
		Encryption: encryptionConfig,
	}); err != nil {
		return fmt.Errorf("failed to configure encryption: %w", err)
	}

	// Configure lifecycle for long-term backup retention
	backupLifecycle := LifecycleConfig{
		Enabled:             true,
		TransitionToIA:      "7d",   // Move to IA after 7 days
		TransitionToGlacier: "30d",  // Move to Glacier after 30 days
	}
	if err := m.configureBucketLifecycle(ctx, S3Config{
		BucketName: bucketName,
		Lifecycle:  backupLifecycle,
	}); err != nil {
		return fmt.Errorf("failed to configure lifecycle: %w", err)
	}

	// Configure MFA delete for critical backups
	if err := m.configureMFADelete(ctx, bucketName); err != nil {
		logger.Warn("Failed to configure MFA delete", "error", err)
	}

	logger.Info("Backups bucket configured successfully", "bucket", bucketName)
	return nil
}

// configureDefaultBucket configures S3 bucket with default settings
func (m *S3Manager) configureDefaultBucket(ctx context.Context, bucketName string, config S3Config) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring default bucket", "bucket", bucketName)

	// Configure encryption if enabled
	if config.Encryption.Enabled {
		if err := m.configureBucketEncryption(ctx, config); err != nil {
			return fmt.Errorf("failed to configure encryption: %w", err)
		}
	}

	// Configure versioning if enabled
	if config.Versioning {
		if err := m.configureBucketVersioning(ctx, bucketName); err != nil {
			return fmt.Errorf("failed to configure versioning: %w", err)
		}
	}

	// Configure lifecycle if enabled
	if config.Lifecycle.Enabled {
		if err := m.configureBucketLifecycle(ctx, config); err != nil {
			return fmt.Errorf("failed to configure lifecycle: %w", err)
		}
	}

	logger.Info("Default bucket configured successfully", "bucket", bucketName)
	return nil
}

// generateBucketTags generates appropriate tags for bucket type
func (m *S3Manager) generateBucketTags(bucketType string) []s3types.Tag {
	tags := []s3types.Tag{
		{
			Key:   aws.String("Application"),
			Value: aws.String("n8n"),
		},
		{
			Key:   aws.String("ManagedBy"),
			Value: aws.String("n8n-operator"),
		},
		{
			Key:   aws.String("BucketType"),
			Value: aws.String(bucketType),
		},
	}

	// Add type-specific tags
	switch bucketType {
	case "workflows":
		tags = append(tags, s3types.Tag{
			Key:   aws.String("DataClassification"),
			Value: aws.String("sensitive"),
		})
	case "assets":
		tags = append(tags, s3types.Tag{
			Key:   aws.String("DataClassification"),
			Value: aws.String("public"),
		})
	case "backups":
		tags = append(tags, s3types.Tag{
			Key:   aws.String("DataClassification"),
			Value: aws.String("critical"),
		})
		tags = append(tags, s3types.Tag{
			Key:   aws.String("RetentionPolicy"),
			Value: aws.String("long-term"),
		})
	}

	return tags
}

// setBucketTags sets tags on S3 bucket
func (m *S3Manager) setBucketTags(ctx context.Context, bucketName string, tags []s3types.Tag) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Setting bucket tags", "bucket", bucketName, "tagsCount", len(tags))

	input := &s3.PutBucketTaggingInput{
		Bucket: aws.String(bucketName),
		Tagging: &s3types.Tagging{
			TagSet: tags,
		},
	}

	_, err := m.s3Client.PutBucketTagging(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to set bucket tags: %w", err)
	}

	logger.Info("Bucket tags set successfully", "bucket", bucketName)
	return nil
}

// configureBucketPublicAccessBlock configures public access block settings
func (m *S3Manager) configureBucketPublicAccessBlock(ctx context.Context, bucketName string) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring public access block", "bucket", bucketName)

	// Block all public access for security
	publicAccessBlockConfiguration := &s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls:       aws.Bool(true),
		BlockPublicPolicy:     aws.Bool(true),
		IgnorePublicAcls:      aws.Bool(true),
		RestrictPublicBuckets: aws.Bool(true),
	}

	input := &s3.PutPublicAccessBlockInput{
		Bucket:                            aws.String(bucketName),
		PublicAccessBlockConfiguration:    publicAccessBlockConfiguration,
	}

	_, err := m.s3Client.PutPublicAccessBlock(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to configure public access block: %w", err)
	}

	logger.Info("Public access block configured successfully", "bucket", bucketName)
	return nil
}

// configureWorkflowNotifications configures S3 event notifications for workflow changes
func (m *S3Manager) configureWorkflowNotifications(ctx context.Context, bucketName string) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring workflow notifications", "bucket", bucketName)

	// This is a placeholder for workflow notifications
	// In a real implementation, you would configure SNS/SQS notifications
	// for workflow file changes to trigger operator reconciliation

	logger.Info("Workflow notifications configuration skipped (not implemented)")
	return nil
}

// configureIntelligentTiering configures S3 Intelligent Tiering for cost optimization
func (m *S3Manager) configureIntelligentTiering(ctx context.Context, bucketName string) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring intelligent tiering", "bucket", bucketName)

	configuration := &s3types.IntelligentTieringConfiguration{
		Id:     aws.String("n8n-intelligent-tiering"),
		Status: s3types.IntelligentTieringStatusEnabled,
		Filter: &s3types.IntelligentTieringFilterMemberPrefix{
			Value: "",
		},
	}

	input := &s3.PutBucketIntelligentTieringConfigurationInput{
		Bucket:                            aws.String(bucketName),
		Id:                               aws.String("n8n-intelligent-tiering"),
		IntelligentTieringConfiguration:   configuration,
	}

	_, err := m.s3Client.PutBucketIntelligentTieringConfiguration(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to configure intelligent tiering: %w", err)
	}

	logger.Info("Intelligent tiering configured successfully", "bucket", bucketName)
	return nil
}

// configureMFADelete configures MFA delete for critical buckets
func (m *S3Manager) configureMFADelete(ctx context.Context, bucketName string) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring MFA delete", "bucket", bucketName)

	// Note: MFA delete can only be enabled by the root account using AWS CLI or API
	// This is a placeholder for the configuration
	logger.Info("MFA delete configuration requires root account access (not implemented)")
	return nil
}

// validateFileType validates file type against allowed types
func (m *S3Manager) validateFileType(filename string, allowedTypes []string) error {
	if len(allowedTypes) == 0 {
		return nil // No restrictions
	}

	ext := strings.ToLower(filepath.Ext(filename))
	if ext != "" && ext[0] == '.' {
		ext = ext[1:] // Remove the dot
	}

	for _, allowedType := range allowedTypes {
		if ext == strings.ToLower(allowedType) {
			return nil
		}
	}

	return fmt.Errorf("file type %s is not allowed, allowed types: %v", ext, allowedTypes)
}

// sanitizeFilename sanitizes filename for safe S3 storage
func (m *S3Manager) sanitizeFilename(filename string) string {
	// Remove or replace unsafe characters
	unsafe := []string{" ", "<", ">", ":", "\"", "|", "?", "*", "\\"}
	sanitized := filename
	
	for _, char := range unsafe {
		sanitized = strings.ReplaceAll(sanitized, char, "_")
	}
	
	// Ensure filename is not too long
	if len(sanitized) > 255 {
		ext := filepath.Ext(sanitized)
		name := strings.TrimSuffix(sanitized, ext)
		if len(name) > 255-len(ext) {
			name = name[:255-len(ext)]
		}
		sanitized = name + ext
	}
	
	return sanitized
}

// generateSignedURL generates a signed URL for temporary access to S3 objects
func (m *S3Manager) generateSignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Generating signed URL", "bucket", bucketName, "key", objectKey, "expiration", expiration)

	// Create a presigner
	presigner := s3.NewPresignClient(m.s3Client)

	// Generate presigned URL for GetObject
	request, err := presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = expiration
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate signed URL: %w", err)
	}

	logger.Info("Signed URL generated successfully", "url", request.URL)
	return request.URL, nil
}

// getBucketMetrics retrieves S3 bucket metrics and usage information
func (m *S3Manager) getBucketMetrics(ctx context.Context, bucketName string) (map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Retrieving bucket metrics", "bucket", bucketName)

	metrics := make(map[string]interface{})

	// Get bucket location
	locationResult, err := m.s3Client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil && locationResult.LocationConstraint != "" {
		metrics["region"] = string(locationResult.LocationConstraint)
	}

	// Get bucket versioning status
	versioningResult, err := m.s3Client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil {
		metrics["versioning_enabled"] = versioningResult.Status == s3types.BucketVersioningStatusEnabled
	}

	// Get bucket encryption status
	encryptionResult, err := m.s3Client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil && encryptionResult.ServerSideEncryptionConfiguration != nil {
		metrics["encryption_enabled"] = len(encryptionResult.ServerSideEncryptionConfiguration.Rules) > 0
	}

	// Get object count (limited to first 1000 objects for performance)
	listResult, err := m.s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucketName),
		MaxKeys: aws.Int32(1000),
	})
	if err == nil {
		metrics["object_count"] = len(listResult.Contents)
		metrics["is_truncated"] = listResult.IsTruncated != nil && *listResult.IsTruncated
		
		// Calculate total size of listed objects
		var totalSize int64
		for _, obj := range listResult.Contents {
			if obj.Size != nil {
				totalSize += *obj.Size
			}
		}
		metrics["total_size_bytes"] = totalSize
	}

	logger.Info("Bucket metrics retrieved", "bucket", bucketName, "metricsCount", len(metrics))
	return metrics, nil
}

// reconcil
eCloudFront creates and configures CloudFront distribution with optimized settings
func (m *S3Manager) reconcileCloudFront(ctx context.Context, config AssetsStorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Reconciling CloudFront distribution for assets")

	if !config.CloudFront.Enabled {
		logger.Info("CloudFront is disabled, skipping distribution setup")
		return nil
	}

	// Find existing distribution
	distributionId, err := m.findCloudFrontDistribution(ctx, config.S3.BucketName)
	if err != nil {
		return fmt.Errorf("failed to find CloudFront distribution: %w", err)
	}

	if distributionId == "" {
		// Create new distribution with optimized configuration
		distributionId, err = m.createOptimizedCloudFrontDistribution(ctx, config)
		if err != nil {
			return fmt.Errorf("failed to create optimized CloudFront distribution: %w", err)
		}
		logger.Info("Optimized CloudFront distribution created", "distributionId", distributionId)
	} else {
		// Update existing distribution
		if err := m.updateCloudFrontDistribution(ctx, distributionId, config); err != nil {
			return fmt.Errorf("failed to update CloudFront distribution: %w", err)
		}
		logger.Info("CloudFront distribution updated", "distributionId", distributionId)
	}

	// Configure cache policies
	if err := m.configureCachePolicies(ctx, distributionId, config); err != nil {
		return fmt.Errorf("failed to configure cache policies: %w", err)
	}

	// Configure origin request policies
	if err := m.configureOriginRequestPolicies(ctx, distributionId, config); err != nil {
		return fmt.Errorf("failed to configure origin request policies: %w", err)
	}

	logger.Info("CloudFront distribution reconciled successfully")
	return nil
}

// createOptimizedCloudFrontDistribution creates CloudFront distribution with optimized cache policies
func (m *S3Manager) createOptimizedCloudFrontDistribution(ctx context.Context, config AssetsStorageConfig) (string, error) {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Creating optimized CloudFront distribution", "bucket", config.S3.BucketName)

	// Create Origin Access Identity (OAI)
	oaiId, err := m.createOriginAccessIdentity(ctx, config.S3.BucketName)
	if err != nil {
		return "", fmt.Errorf("failed to create origin access identity: %w", err)
	}

	// Build optimized distribution configuration
	distributionConfig := &types.DistributionConfig{
		CallerReference: aws.String(fmt.Sprintf("n8n-assets-optimized-%d", time.Now().Unix())),
		Comment:         aws.String(fmt.Sprintf("n8n optimized assets distribution for %s", config.S3.BucketName)),
		Enabled:         aws.Bool(true),
		
		Origins: &types.Origins{
			Quantity: aws.Int32(1),
			Items: []types.Origin{
				{
					Id:         aws.String("S3-" + config.S3.BucketName),
					DomainName: aws.String(fmt.Sprintf("%s.s3.amazonaws.com", config.S3.BucketName)),
					S3OriginConfig: &types.S3OriginConfig{
						OriginAccessIdentity: aws.String(fmt.Sprintf("origin-access-identity/cloudfront/%s", oaiId)),
					},
				},
			},
		},
		
		DefaultCacheBehavior: m.createOptimizedCacheBehavior(config),
		
		// Add cache behaviors for different asset types
		CacheBehaviors: m.createAssetTypeCacheBehaviors(config),
		
		PriceClass: types.PriceClassPriceClassAll,
		
		// Configure custom error pages
		CustomErrorPages: m.createCustomErrorPages(),
		
		// Configure logging if needed
		Logging: &types.LoggingConfig{
			Enabled:        aws.Bool(false), // Disable by default for cost
			IncludeCookies: aws.Bool(false),
		},
		
		// Configure HTTP version
		HttpVersion: types.HttpVersionHttp2,
		
		// Enable IPv6
		IsIPV6Enabled: aws.Bool(true),
	}

	// Configure custom domain if specified
	if config.CloudFront.CustomDomain != "" {
		distributionConfig.Aliases = &types.Aliases{
			Quantity: aws.Int32(1),
			Items:    []string{config.CloudFront.CustomDomain},
		}
	}

	input := &cloudfront.CreateDistributionInput{
		DistributionConfig: distributionConfig,
	}

	result, err := m.cloudFrontClient.CreateDistribution(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to create distribution: %w", err)
	}

	if result.Distribution == nil || result.Distribution.Id == nil {
		return "", fmt.Errorf("distribution creation returned no ID")
	}

	distributionId := *result.Distribution.Id
	logger.Info("Optimized CloudFront distribution created", "distributionId", distributionId)

	return distributionId, nil
}

// createOptimizedCacheBehavior creates optimized default cache behavior
func (m *S3Manager) createOptimizedCacheBehavior(config AssetsStorageConfig) *types.DefaultCacheBehavior {
	behavior := &types.DefaultCacheBehavior{
		TargetOriginId:       aws.String("S3-" + config.S3.BucketName),
		ViewerProtocolPolicy: types.ViewerProtocolPolicyRedirectToHttps,
		
		// Optimized TTL settings for assets
		MinTTL:     aws.Int64(0),
		DefaultTTL: aws.Int64(86400),    // 1 day
		MaxTTL:     aws.Int64(31536000), // 1 year
		
		// Enable compression
		Compress: aws.Bool(true),
		
		// Configure allowed HTTP methods
		AllowedMethods: &types.AllowedMethods{
			Quantity: aws.Int32(2),
			Items:    []types.Method{types.MethodGet, types.MethodHead},
			CachedMethods: &types.CachedMethods{
				Quantity: aws.Int32(2),
				Items:    []types.Method{types.MethodGet, types.MethodHead},
			},
		},
		
		TrustedSigners: &types.TrustedSigners{
			Enabled:  aws.Bool(false),
			Quantity: aws.Int32(0),
		},
	}

	// Use cache policy if specified, otherwise use legacy settings
	if config.CloudFront.CachePolicyId != "" {
		behavior.CachePolicyId = aws.String(config.CloudFront.CachePolicyId)
	} else {
		// Legacy cache settings
		behavior.ForwardedValues = &types.ForwardedValues{
			QueryString: aws.Bool(false),
			Cookies: &types.CookiePreference{
				Forward: types.ItemSelectionNone,
			},
			Headers: &types.Headers{
				Quantity: aws.Int32(0),
			},
		}
	}

	// Configure origin request policy if specified
	if config.CloudFront.OriginRequestPolicyId != "" {
		behavior.OriginRequestPolicyId = aws.String(config.CloudFront.OriginRequestPolicyId)
	}

	return behavior
}

// createAssetTypeCacheBehaviors creates cache behaviors for different asset types
func (m *S3Manager) createAssetTypeCacheBehaviors(config AssetsStorageConfig) *types.CacheBehaviors {
	behaviors := []types.CacheBehavior{
		// Images - long cache
		{
			PathPattern:          aws.String("*.jpg"),
			TargetOriginId:       aws.String("S3-" + config.S3.BucketName),
			ViewerProtocolPolicy: types.ViewerProtocolPolicyRedirectToHttps,
			MinTTL:              aws.Int64(0),
			DefaultTTL:          aws.Int64(604800),   // 1 week
			MaxTTL:              aws.Int64(31536000), // 1 year
			Compress:            aws.Bool(true),
			ForwardedValues: &types.ForwardedValues{
				QueryString: aws.Bool(false),
				Cookies: &types.CookiePreference{
					Forward: types.ItemSelectionNone,
				},
			},
			TrustedSigners: &types.TrustedSigners{
				Enabled:  aws.Bool(false),
				Quantity: aws.Int32(0),
			},
		},
		// Documents - medium cache
		{
			PathPattern:          aws.String("*.pdf"),
			TargetOriginId:       aws.String("S3-" + config.S3.BucketName),
			ViewerProtocolPolicy: types.ViewerProtocolPolicyRedirectToHttps,
			MinTTL:              aws.Int64(0),
			DefaultTTL:          aws.Int64(86400),    // 1 day
			MaxTTL:              aws.Int64(604800),   // 1 week
			Compress:            aws.Bool(true),
			ForwardedValues: &types.ForwardedValues{
				QueryString: aws.Bool(false),
				Cookies: &types.CookiePreference{
					Forward: types.ItemSelectionNone,
				},
			},
			TrustedSigners: &types.TrustedSigners{
				Enabled:  aws.Bool(false),
				Quantity: aws.Int32(0),
			},
		},
	}

	return &types.CacheBehaviors{
		Quantity: aws.Int32(int32(len(behaviors))),
		Items:    behaviors,
	}
}

// createCustomErrorPages creates custom error pages configuration
func (m *S3Manager) createCustomErrorPages() *types.CustomErrorPages {
	errorPages := []types.CustomErrorPage{
		{
			ErrorCode:        aws.Int32(403),
			ResponseCode:     aws.String("404"),
			ResponsePagePath: aws.String("/404.html"),
			ErrorCachingMinTTL: aws.Int64(300), // 5 minutes
		},
		{
			ErrorCode:        aws.Int32(404),
			ResponseCode:     aws.String("404"),
			ResponsePagePath: aws.String("/404.html"),
			ErrorCachingMinTTL: aws.Int64(300), // 5 minutes
		},
	}

	return &types.CustomErrorPages{
		Quantity: aws.Int32(int32(len(errorPages))),
		Items:    errorPages,
	}
}

// configureCachePolicies configures CloudFront cache policies
func (m *S3Manager) configureCachePolicies(ctx context.Context, distributionId string, config AssetsStorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring cache policies", "distributionId", distributionId)

	// If no custom cache policy is specified, create an optimized one
	if config.CloudFront.CachePolicyId == "" {
		policyId, err := m.createOptimizedCachePolicy(ctx, config.S3.BucketName)
		if err != nil {
			logger.Warn("Failed to create optimized cache policy", "error", err)
			return nil // Not critical, continue with default
		}
		
		// Update distribution with new cache policy
		if err := m.updateDistributionCachePolicy(ctx, distributionId, policyId); err != nil {
			logger.Warn("Failed to update distribution with cache policy", "error", err)
		}
	}

	logger.Info("Cache policies configured successfully")
	return nil
}

// createOptimizedCachePolicy creates an optimized cache policy for assets
func (m *S3Manager) createOptimizedCachePolicy(ctx context.Context, bucketName string) (string, error) {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Creating optimized cache policy", "bucket", bucketName)

	policyConfig := &types.CachePolicyConfig{
		Name:    aws.String(fmt.Sprintf("n8n-assets-policy-%s", bucketName)),
		Comment: aws.String(fmt.Sprintf("Optimized cache policy for n8n assets in %s", bucketName)),
		
		DefaultTTL: aws.Int64(86400),    // 1 day
		MaxTTL:     aws.Int64(31536000), // 1 year
		MinTTL:     aws.Int64(0),
		
		ParametersInCacheKeyAndForwardedToOrigin: &types.ParametersInCacheKeyAndForwardedToOrigin{
			EnableAcceptEncodingGzip:   aws.Bool(true),
			EnableAcceptEncodingBrotli: aws.Bool(true),
			
			QueryStringsConfig: &types.CachePolicyQueryStringsConfig{
				QueryStringBehavior: types.CachePolicyQueryStringBehaviorNone,
			},
			
			HeadersConfig: &types.CachePolicyHeadersConfig{
				HeaderBehavior: types.CachePolicyHeaderBehaviorNone,
			},
			
			CookiesConfig: &types.CachePolicyCookiesConfig{
				CookieBehavior: types.CachePolicyCookieBehaviorNone,
			},
		},
	}

	input := &cloudfront.CreateCachePolicyInput{
		CachePolicyConfig: policyConfig,
	}

	result, err := m.cloudFrontClient.CreateCachePolicy(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to create cache policy: %w", err)
	}

	if result.CachePolicy == nil || result.CachePolicy.Id == nil {
		return "", fmt.Errorf("cache policy creation returned no ID")
	}

	policyId := *result.CachePolicy.Id
	logger.Info("Optimized cache policy created", "policyId", policyId)
	return policyId, nil
}

// configureOriginRequestPolicies configures CloudFront origin request policies
func (m *S3Manager) configureOriginRequestPolicies(ctx context.Context, distributionId string, config AssetsStorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring origin request policies", "distributionId", distributionId)

	// If no custom origin request policy is specified, use the managed CORS-S3Origin policy
	if config.CloudFront.OriginRequestPolicyId == "" {
		// Use AWS managed policy for CORS-S3Origin
		managedPolicyId := "88a5eaf4-2fd4-4709-b370-b4c650ea3fcf" // CORS-S3Origin
		
		if err := m.updateDistributionOriginRequestPolicy(ctx, distributionId, managedPolicyId); err != nil {
			logger.Warn("Failed to update distribution with origin request policy", "error", err)
		}
	}

	logger.Info("Origin request policies configured successfully")
	return nil
}

// updateDistributionCachePolicy updates distribution with cache policy
func (m *S3Manager) updateDistributionCachePolicy(ctx context.Context, distributionId, policyId string) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Updating distribution cache policy", "distributionId", distributionId, "policyId", policyId)

	// Get current distribution configuration
	getResult, err := m.cloudFrontClient.GetDistribution(ctx, &cloudfront.GetDistributionInput{
		Id: aws.String(distributionId),
	})
	if err != nil {
		return fmt.Errorf("failed to get distribution: %w", err)
	}

	distributionConfig := getResult.Distribution.DistributionConfig
	etag := getResult.ETag

	// Update cache policy
	distributionConfig.DefaultCacheBehavior.CachePolicyId = aws.String(policyId)
	// Remove legacy ForwardedValues when using cache policy
	distributionConfig.DefaultCacheBehavior.ForwardedValues = nil

	input := &cloudfront.UpdateDistributionInput{
		Id:                 aws.String(distributionId),
		DistributionConfig: distributionConfig,
		IfMatch:           etag,
	}

	_, err = m.cloudFrontClient.UpdateDistribution(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to update distribution: %w", err)
	}

	logger.Info("Distribution cache policy updated successfully")
	return nil
}

// updateDistributionOriginRequestPolicy updates distribution with origin request policy
func (m *S3Manager) updateDistributionOriginRequestPolicy(ctx context.Context, distributionId, policyId string) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Updating distribution origin request policy", "distributionId", distributionId, "policyId", policyId)

	// Get current distribution configuration
	getResult, err := m.cloudFrontClient.GetDistribution(ctx, &cloudfront.GetDistributionInput{
		Id: aws.String(distributionId),
	})
	if err != nil {
		return fmt.Errorf("failed to get distribution: %w", err)
	}

	distributionConfig := getResult.Distribution.DistributionConfig
	etag := getResult.ETag

	// Update origin request policy
	distributionConfig.DefaultCacheBehavior.OriginRequestPolicyId = aws.String(policyId)

	input := &cloudfront.UpdateDistributionInput{
		Id:                 aws.String(distributionId),
		DistributionConfig: distributionConfig,
		IfMatch:           etag,
	}

	_, err = m.cloudFrontClient.UpdateDistribution(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to update distribution: %w", err)
	}

	logger.Info("Distribution origin request policy updated successfully")
	return nil
}

// getCloudFrontDistributionMetrics retrieves CloudFront distribution metrics
func (m *S3Manager) getCloudFrontDistributionMetrics(ctx context.Context, distributionId string) (map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Retrieving CloudFront distribution metrics", "distributionId", distributionId)

	metrics := make(map[string]interface{})

	// Get distribution configuration
	result, err := m.cloudFrontClient.GetDistribution(ctx, &cloudfront.GetDistributionInput{
		Id: aws.String(distributionId),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get distribution: %w", err)
	}

	if result.Distribution != nil {
		distribution := result.Distribution
		
		metrics["id"] = distributionId
		if distribution.Status != nil {
			metrics["status"] = *distribution.Status
		}
		if distribution.DomainName != nil {
			metrics["domain_name"] = *distribution.DomainName
		}
		if distribution.DistributionConfig != nil {
			config := distribution.DistributionConfig
			if config.Enabled != nil {
				metrics["enabled"] = *config.Enabled
			}
			if config.PriceClass != "" {
				metrics["price_class"] = string(config.PriceClass)
			}
			if config.Origins != nil {
				metrics["origins_count"] = len(config.Origins.Items)
			}
		}
		if distribution.LastModifiedTime != nil {
			metrics["last_modified"] = distribution.LastModifiedTime.Format(time.RFC3339)
		}
	}

	logger.Info("CloudFront distribution metrics retrieved", "distributionId", distributionId, "metricsCount", len(metrics))
	return metrics, nil
}

// c
onfigureBucketPoliciesAdvanced configures advanced S3 bucket policies with security best practices
func (m *S3Manager) configureBucketPoliciesAdvanced(ctx context.Context, bucketName, bucketType string, config S3Config) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring advanced bucket policies", "bucket", bucketName, "type", bucketType)

	// Generate comprehensive security policy
	policyDocument, err := m.generateSecurityBucketPolicy(bucketName, bucketType, config)
	if err != nil {
		return fmt.Errorf("failed to generate security bucket policy: %w", err)
	}

	input := &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucketName),
		Policy: aws.String(policyDocument),
	}

	_, err = m.s3Client.PutBucketPolicy(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to configure advanced bucket policy: %w", err)
	}

	logger.Info("Advanced bucket policies configured successfully", "bucket", bucketName)
	return nil
}

// generateSecurityBucketPolicy generates comprehensive security policy with principle of least privilege
func (m *S3Manager) generateSecurityBucketPolicy(bucketName, bucketType string, config S3Config) (string, error) {
	statements := []map[string]interface{}{}

	// Base security statements (always applied)
	baseStatements := []map[string]interface{}{
		// Deny insecure connections
		{
			"Sid":    "DenyInsecureConnections",
			"Effect": "Deny",
			"Principal": "*",
			"Action":    "s3:*",
			"Resource": []string{
				fmt.Sprintf("arn:aws:s3:::%s", bucketName),
				fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
			},
			"Condition": map[string]interface{}{
				"Bool": map[string]interface{}{
					"aws:SecureTransport": "false",
				},
			},
		},
		// Deny unencrypted object uploads
		{
			"Sid":    "DenyUnencryptedObjectUploads",
			"Effect": "Deny",
			"Principal": "*",
			"Action":    "s3:PutObject",
			"Resource":  fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
			"Condition": map[string]interface{}{
				"StringNotEquals": map[string]interface{}{
					"s3:x-amz-server-side-encryption": []string{"AES256", "aws:kms"},
				},
			},
		},
		// Deny public read access
		{
			"Sid":    "DenyPublicReadAccess",
			"Effect": "Deny",
			"Principal": "*",
			"Action": []string{
				"s3:GetObject",
				"s3:GetObjectVersion",
			},
			"Resource": fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
			"Condition": map[string]interface{}{
				"StringEquals": map[string]interface{}{
					"s3:ExistingObjectTag/Public": "false",
				},
			},
		},
		// Deny public write access
		{
			"Sid":    "DenyPublicWriteAccess",
			"Effect": "Deny",
			"Principal": "*",
			"Action": []string{
				"s3:PutObject",
				"s3:PutObjectAcl",
				"s3:DeleteObject",
			},
			"Resource": fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
			"Condition": map[string]interface{}{
				"StringNotEquals": map[string]interface{}{
					"aws:PrincipalServiceName": []string{
						"n8n.amazonaws.com",
						"cloudfront.amazonaws.com",
					},
				},
			},
		},
	}

	statements = append(statements, baseStatements...)

	// Add type-specific statements
	switch bucketType {
	case "workflows":
		workflowStatements := m.generateWorkflowsSecurityStatements(bucketName)
		statements = append(statements, workflowStatements...)
	case "assets":
		assetsStatements := m.generateAssetsSecurityStatements(bucketName)
		statements = append(statements, assetsStatements...)
	case "backups":
		backupStatements := m.generateBackupsSecurityStatements(bucketName)
		statements = append(statements, backupStatements...)
	}

	// Add IP restriction if configured
	if ipStatements := m.generateIPRestrictionStatements(bucketName); len(ipStatements) > 0 {
		statements = append(statements, ipStatements...)
	}

	// Add time-based access restrictions
	if timeStatements := m.generateTimeBasedAccessStatements(bucketName); len(timeStatements) > 0 {
		statements = append(statements, timeStatements...)
	}

	policy := map[string]interface{}{
		"Version":   "2012-10-17",
		"Statement": statements,
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal security policy: %w", err)
	}

	return string(policyJSON), nil
}

// generateWorkflowsSecurityStatements generates security statements specific to workflows bucket
func (m *S3Manager) generateWorkflowsSecurityStatements(bucketName string) []map[string]interface{} {
	return []map[string]interface{}{
		// Allow n8n service to read/write workflows
		{
			"Sid":    "AllowN8nWorkflowAccess",
			"Effect": "Allow",
			"Principal": map[string]interface{}{
				"AWS": "arn:aws:iam::*:role/n8n-*",
			},
			"Action": []string{
				"s3:GetObject",
				"s3:PutObject",
				"s3:DeleteObject",
				"s3:GetObjectVersion",
			},
			"Resource": fmt.Sprintf("arn:aws:s3:::%s/workflows/*", bucketName),
			"Condition": map[string]interface{}{
				"StringEquals": map[string]interface{}{
					"s3:ExistingObjectTag/WorkflowOwner": "${aws:userid}",
				},
			},
		},
		// Deny deletion of critical workflow files
		{
			"Sid":    "DenyCriticalWorkflowDeletion",
			"Effect": "Deny",
			"Principal": "*",
			"Action":    "s3:DeleteObject",
			"Resource":  fmt.Sprintf("arn:aws:s3:::%s/workflows/critical/*", bucketName),
		},
		// Require MFA for workflow deletion
		{
			"Sid":    "RequireMFAForWorkflowDeletion",
			"Effect": "Deny",
			"Principal": "*",
			"Action":    "s3:DeleteObject",
			"Resource":  fmt.Sprintf("arn:aws:s3:::%s/workflows/*", bucketName),
			"Condition": map[string]interface{}{
				"BoolIfExists": map[string]interface{}{
					"aws:MultiFactorAuthPresent": "false",
				},
			},
		},
	}
}

// generateAssetsSecurityStatements generates security statements specific to assets bucket
func (m *S3Manager) generateAssetsSecurityStatements(bucketName string) []map[string]interface{} {
	return []map[string]interface{}{
		// Allow CloudFront to read assets
		{
			"Sid":    "AllowCloudFrontAccess",
			"Effect": "Allow",
			"Principal": map[string]interface{}{
				"Service": "cloudfront.amazonaws.com",
			},
			"Action":   "s3:GetObject",
			"Resource": fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
		},
		// Allow n8n service to upload assets
		{
			"Sid":    "AllowN8nAssetUpload",
			"Effect": "Allow",
			"Principal": map[string]interface{}{
				"AWS": "arn:aws:iam::*:role/n8n-*",
			},
			"Action": []string{
				"s3:PutObject",
				"s3:PutObjectAcl",
			},
			"Resource": fmt.Sprintf("arn:aws:s3:::%s/assets/*", bucketName),
			"Condition": map[string]interface{}{
				"StringLike": map[string]interface{}{
					"s3:x-amz-content-sha256": "*",
				},
				"NumericLessThan": map[string]interface{}{
					"s3:content-length": 10485760, // 10MB limit
				},
			},
		},
		// Restrict file types for assets
		{
			"Sid":    "RestrictAssetFileTypes",
			"Effect": "Deny",
			"Principal": "*",
			"Action":    "s3:PutObject",
			"Resource":  fmt.Sprintf("arn:aws:s3:::%s/assets/*", bucketName),
			"Condition": map[string]interface{}{
				"StringNotLike": map[string]interface{}{
					"s3:x-amz-content-type": []string{
						"image/*",
						"application/pdf",
						"application/msword",
						"application/vnd.openxmlformats-officedocument.*",
					},
				},
			},
		},
	}
}

// generateBackupsSecurityStatements generates security statements specific to backups bucket
func (m *S3Manager) generateBackupsSecurityStatements(bucketName string) []map[string]interface{} {
	return []map[string]interface{}{
		// Allow backup service to write backups
		{
			"Sid":    "AllowBackupServiceAccess",
			"Effect": "Allow",
			"Principal": map[string]interface{}{
				"AWS": "arn:aws:iam::*:role/n8n-backup-*",
			},
			"Action": []string{
				"s3:PutObject",
				"s3:GetObject",
			},
			"Resource": fmt.Sprintf("arn:aws:s3:::%s/backups/*", bucketName),
			"Condition": map[string]interface{}{
				"StringEquals": map[string]interface{}{
					"s3:x-amz-server-side-encryption": "aws:kms",
				},
			},
		},
		// Deny deletion of recent backups
		{
			"Sid":    "DenyRecentBackupDeletion",
			"Effect": "Deny",
			"Principal": "*",
			"Action":    "s3:DeleteObject",
			"Resource":  fmt.Sprintf("arn:aws:s3:::%s/backups/*", bucketName),
			"Condition": map[string]interface{}{
				"DateGreaterThan": map[string]interface{}{
					"s3:object-creation-date": "${aws:CurrentTime - 7 days}",
				},
			},
		},
		// Require MFA for backup deletion
		{
			"Sid":    "RequireMFAForBackupDeletion",
			"Effect": "Deny",
			"Principal": "*",
			"Action": []string{
				"s3:DeleteObject",
				"s3:DeleteBucket",
			},
			"Resource": []string{
				fmt.Sprintf("arn:aws:s3:::%s", bucketName),
				fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
			},
			"Condition": map[string]interface{}{
				"BoolIfExists": map[string]interface{}{
					"aws:MultiFactorAuthPresent": "false",
				},
			},
		},
	}
}

// generateIPRestrictionStatements generates IP-based access restriction statements
func (m *S3Manager) generateIPRestrictionStatements(bucketName string) []map[string]interface{} {
	// This would be configurable in a real implementation
	// For now, return empty to allow access from anywhere
	return []map[string]interface{}{}
}

// generateTimeBasedAccessStatements generates time-based access restriction statements
func (m *S3Manager) generateTimeBasedAccessStatements(bucketName string) []map[string]interface{} {
	return []map[string]interface{}{
		// Deny access during maintenance window (example: 2-4 AM UTC)
		{
			"Sid":    "DenyMaintenanceWindowAccess",
			"Effect": "Deny",
			"Principal": "*",
			"Action":    "s3:*",
			"Resource": []string{
				fmt.Sprintf("arn:aws:s3:::%s", bucketName),
				fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
			},
			"Condition": map[string]interface{}{
				"DateGreaterThan": map[string]interface{}{
					"aws:CurrentTime": "02:00Z",
				},
				"DateLessThan": map[string]interface{}{
					"aws:CurrentTime": "04:00Z",
				},
				"StringNotEquals": map[string]interface{}{
					"aws:PrincipalServiceName": "n8n.amazonaws.com",
				},
			},
		},
	}
}

// configureCORSAdvanced configures advanced CORS settings for web access
func (m *S3Manager) configureCORSAdvanced(ctx context.Context, bucketName string, bucketType string) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring advanced CORS", "bucket", bucketName, "type", bucketType)

	var corsRules []s3types.CORSRule

	switch bucketType {
	case "assets":
		corsRules = []s3types.CORSRule{
			// Public assets access
			{
				AllowedHeaders: []string{"*"},
				AllowedMethods: []string{"GET", "HEAD"},
				AllowedOrigins: []string{"*"},
				ExposeHeaders:  []string{"ETag", "x-amz-meta-*"},
				MaxAgeSeconds:  aws.Int32(3600), // 1 hour
			},
			// Authenticated upload
			{
				AllowedHeaders: []string{
					"Content-Type",
					"Content-MD5",
					"Authorization",
					"x-amz-date",
					"x-amz-security-token",
				},
				AllowedMethods: []string{"PUT", "POST"},
				AllowedOrigins: []string{"https://*.n8n.io", "https://localhost:*"},
				ExposeHeaders:  []string{"ETag"},
				MaxAgeSeconds:  aws.Int32(300), // 5 minutes
			},
		}
	case "workflows":
		corsRules = []s3types.CORSRule{
			// Restricted access for workflows
			{
				AllowedHeaders: []string{
					"Content-Type",
					"Authorization",
					"x-amz-date",
					"x-amz-security-token",
				},
				AllowedMethods: []string{"GET", "PUT", "POST", "DELETE"},
				AllowedOrigins: []string{"https://*.n8n.io"},
				ExposeHeaders:  []string{"ETag"},
				MaxAgeSeconds:  aws.Int32(300), // 5 minutes
			},
		}
	default:
		// Default restrictive CORS
		corsRules = []s3types.CORSRule{
			{
				AllowedHeaders: []string{"Authorization"},
				AllowedMethods: []string{"GET"},
				AllowedOrigins: []string{"https://*.n8n.io"},
				MaxAgeSeconds:  aws.Int32(300),
			},
		}
	}

	corsConfiguration := &s3types.CORSConfiguration{
		CORSRules: corsRules,
	}

	input := &s3.PutBucketCorsInput{
		Bucket:            aws.String(bucketName),
		CORSConfiguration: corsConfiguration,
	}

	_, err := m.s3Client.PutBucketCors(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to configure advanced CORS: %w", err)
	}

	logger.Info("Advanced CORS configured successfully", "bucket", bucketName)
	return nil
}

// generatePresignedUploadURL generates a presigned URL for secure file uploads
func (m *S3Manager) generatePresignedUploadURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration, conditions map[string]interface{}) (string, map[string]string, error) {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Generating presigned upload URL", "bucket", bucketName, "key", objectKey, "expiration", expiration)

	// Create a presigner
	presigner := s3.NewPresignClient(m.s3Client)

	// Build conditions for the presigned POST
	var postConditions []interface{}
	
	// Add bucket condition
	postConditions = append(postConditions, map[string]string{"bucket": bucketName})
	
	// Add key condition
	postConditions = append(postConditions, []string{"starts-with", "$key", objectKey})
	
	// Add content length restrictions
	postConditions = append(postConditions, []interface{}{"content-length-range", 1, 10485760}) // 1 byte to 10MB
	
	// Add custom conditions
	for key, value := range conditions {
		switch key {
		case "content-type":
			postConditions = append(postConditions, []string{"starts-with", "$Content-Type", value.(string)})
		case "max-size":
			if size, ok := value.(int64); ok {
				postConditions = append(postConditions, []interface{}{"content-length-range", 1, size})
			}
		}
	}

	// Generate presigned POST
	request, err := presigner.PresignPostObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	}, func(opts *s3.PresignPostOptions) {
		opts.Expires = expiration
		opts.Conditions = postConditions
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate presigned upload URL: %w", err)
	}

	logger.Info("Presigned upload URL generated successfully")
	return request.URL, request.Values, nil
}

// validateUploadSecurity validates file upload against security policies
func (m *S3Manager) validateUploadSecurity(ctx context.Context, filename string, contentType string, size int64, bucketType string) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Validating upload security", "filename", filename, "contentType", contentType, "size", size, "bucketType", bucketType)

	// Validate filename for security
	if err := m.validateFilenameSecurity(filename); err != nil {
		return fmt.Errorf("filename security validation failed: %w", err)
	}

	// Validate content type
	if err := m.validateContentTypeSecurity(contentType, bucketType); err != nil {
		return fmt.Errorf("content type security validation failed: %w", err)
	}

	// Validate file size
	if err := m.validateFileSizeSecurity(size, bucketType); err != nil {
		return fmt.Errorf("file size security validation failed: %w", err)
	}

	logger.Info("Upload security validation successful")
	return nil
}

// validateFilenameSecurity validates filename for security issues
func (m *S3Manager) validateFilenameSecurity(filename string) error {
	// Check for path traversal attempts
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		return fmt.Errorf("filename contains path traversal characters")
	}

	// Check for executable extensions
	dangerousExtensions := []string{".exe", ".bat", ".cmd", ".com", ".scr", ".pif", ".js", ".vbs", ".jar", ".sh"}
	ext := strings.ToLower(filepath.Ext(filename))
	for _, dangerous := range dangerousExtensions {
		if ext == dangerous {
			return fmt.Errorf("executable file type not allowed: %s", ext)
		}
	}

	// Check filename length
	if len(filename) > 255 {
		return fmt.Errorf("filename too long: %d characters (max 255)", len(filename))
	}

	// Check for null bytes
	if strings.Contains(filename, "\x00") {
		return fmt.Errorf("filename contains null bytes")
	}

	return nil
}

// validateContentTypeSecurity validates content type for security
func (m *S3Manager) validateContentTypeSecurity(contentType, bucketType string) error {
	allowedTypes := map[string][]string{
		"assets": {
			"image/jpeg", "image/png", "image/gif", "image/webp",
			"application/pdf",
			"application/msword",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			"application/vnd.ms-excel",
			"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		},
		"workflows": {
			"application/json",
			"text/plain",
			"application/yaml",
		},
		"backups": {
			"application/gzip",
			"application/x-tar",
			"application/zip",
		},
	}

	if allowed, exists := allowedTypes[bucketType]; exists {
		for _, allowedType := range allowed {
			if contentType == allowedType {
				return nil
			}
		}
		return fmt.Errorf("content type %s not allowed for bucket type %s", contentType, bucketType)
	}

	return nil // No restrictions for unknown bucket types
}

// validateFileSizeSecurity validates file size for security
func (m *S3Manager) validateFileSizeSecurity(size int64, bucketType string) error {
	maxSizes := map[string]int64{
		"assets":    10 * 1024 * 1024,  // 10MB
		"workflows": 1 * 1024 * 1024,   // 1MB
		"backups":   100 * 1024 * 1024, // 100MB
	}

	if maxSize, exists := maxSizes[bucketType]; exists {
		if size > maxSize {
			return fmt.Errorf("file size %d exceeds maximum %d for bucket type %s", size, maxSize, bucketType)
		}
	}

	if size <= 0 {
		return fmt.Errorf("file size must be greater than 0")
	}

	return nil
}

// auditBucketAccess logs bucket access for security monitoring
func (m *S3Manager) auditBucketAccess(ctx context.Context, bucketName, operation, principal string) {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Bucket access audit",
		"bucket", bucketName,
		"operation", operation,
		"principal", principal,
		"timestamp", time.Now().UTC().Format(time.RFC3339),
	)
	
	// In a real implementation, this would send audit logs to CloudTrail, CloudWatch, or a SIEM system
}

// rec
oncilePersistentVolumes creates and manages EBS persistent volumes with CSI driver
func (m *S3Manager) reconcilePersistentVolumes(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config PersistentStorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Reconciling persistent volumes", "storageClass", config.StorageClass)

	if config.Type != "ebs-csi" {
		logger.Info("EBS CSI is not configured, skipping persistent volumes")
		return nil
	}

	// Create or update StorageClass
	if err := m.reconcileStorageClass(ctx, config); err != nil {
		return fmt.Errorf("failed to reconcile storage class: %w", err)
	}

	// Create PersistentVolumeClaims for n8n components
	if err := m.createPersistentVolumeClaims(ctx, instance, config); err != nil {
		return fmt.Errorf("failed to create persistent volume claims: %w", err)
	}

	// Configure snapshot policies if enabled
	if config.SnapshotPolicy.Enabled {
		if err := m.configureSnapshotPolicies(ctx, instance, config); err != nil {
			return fmt.Errorf("failed to configure snapshot policies: %w", err)
		}
	}

	// Configure volume expansion monitoring
	if config.AutoExpansion {
		if err := m.configureVolumeExpansionMonitoring(ctx, instance, config); err != nil {
			return fmt.Errorf("failed to configure volume expansion monitoring: %w", err)
		}
	}

	logger.Info("Persistent volumes reconciled successfully")
	return nil
}

// createPersistentVolumeClaims creates PVCs for n8n components
func (m *S3Manager) createPersistentVolumeClaims(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config PersistentStorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Creating persistent volume claims")

	// Define PVCs for different n8n components
	pvcConfigs := []struct {
		name        string
		component   string
		size        string
		accessModes []corev1.PersistentVolumeAccessMode
	}{
		{
			name:        fmt.Sprintf("%s-main-data", instance.Name),
			component:   "main",
			size:        config.Size,
			accessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
		},
		{
			name:        fmt.Sprintf("%s-webhook-data", instance.Name),
			component:   "webhook",
			size:        "5Gi", // Smaller size for webhook
			accessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
		},
	}

	storageClassName := fmt.Sprintf("n8n-%s", config.StorageClass)

	for _, pvcConfig := range pvcConfigs {
		if err := m.createPersistentVolumeClaim(ctx, instance, pvcConfig.name, pvcConfig.component, pvcConfig.size, pvcConfig.accessModes, storageClassName); err != nil {
			return fmt.Errorf("failed to create PVC %s: %w", pvcConfig.name, err)
		}
	}

	logger.Info("Persistent volume claims created successfully")
	return nil
}

// createPersistentVolumeClaim creates a single PVC
func (m *S3Manager) createPersistentVolumeClaim(ctx context.Context, instance *n8nv1alpha1.N8nInstance, name, component, size string, accessModes []corev1.PersistentVolumeAccessMode, storageClassName string) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Creating PVC", "name", name, "component", component, "size", size)

	// Parse size
	quantity, err := resource.ParseQuantity(size)
	if err != nil {
		return fmt.Errorf("invalid size format: %s", size)
	}

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  component,
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
			Annotations: map[string]string{
				"n8n.io/storage-type":      "ebs-csi",
				"n8n.io/component":         component,
				"n8n.io/auto-expansion":    strconv.FormatBool(true),
				"volume.beta.kubernetes.io/storage-provisioner": "ebs.csi.aws.com",
			},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: accessModes,
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: quantity,
				},
			},
			StorageClassName: &storageClassName,
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, pvc, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Check if PVC already exists
	existingPVC := &corev1.PersistentVolumeClaim{}
	pvcKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      name,
	}

	if err := m.client.Get(ctx, pvcKey, existingPVC); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing PVC: %w", err)
		}
		// PVC doesn't exist, create it
		if err := m.client.Create(ctx, pvc); err != nil {
			return fmt.Errorf("failed to create PVC: %w", err)
		}
		logger.Info("PVC created successfully", "name", name)
	} else {
		// PVC exists, check if expansion is needed
		if err := m.checkAndExpandPVC(ctx, existingPVC, quantity); err != nil {
			return fmt.Errorf("failed to expand PVC: %w", err)
		}
		logger.Info("PVC already exists", "name", name)
	}

	return nil
}

// checkAndExpandPVC checks if PVC needs expansion and performs it if necessary
func (m *S3Manager) checkAndExpandPVC(ctx context.Context, pvc *corev1.PersistentVolumeClaim, newSize resource.Quantity) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	
	currentSize := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	
	// Check if expansion is needed
	if newSize.Cmp(currentSize) > 0 {
		logger.Info("Expanding PVC", "name", pvc.Name, "currentSize", currentSize.String(), "newSize", newSize.String())
		
		// Update PVC with new size
		pvc.Spec.Resources.Requests[corev1.ResourceStorage] = newSize
		
		if err := m.client.Update(ctx, pvc); err != nil {
			return fmt.Errorf("failed to update PVC for expansion: %w", err)
		}
		
		logger.Info("PVC expansion initiated", "name", pvc.Name)
	}
	
	return nil
}

// configureSnapshotPolicies configures EBS snapshot policies for backup
func (m *S3Manager) configureSnapshotPolicies(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config PersistentStorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring snapshot policies")

	// Create VolumeSnapshotClass
	if err := m.createVolumeSnapshotClass(ctx, instance); err != nil {
		return fmt.Errorf("failed to create volume snapshot class: %w", err)
	}

	// Create snapshot schedule (using CronJob)
	if err := m.createSnapshotSchedule(ctx, instance, config); err != nil {
		return fmt.Errorf("failed to create snapshot schedule: %w", err)
	}

	logger.Info("Snapshot policies configured successfully")
	return nil
}

// createVolumeSnapshotClass creates a VolumeSnapshotClass for EBS snapshots
func (m *S3Manager) createVolumeSnapshotClass(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Creating VolumeSnapshotClass")

	// Note: VolumeSnapshotClass is part of the snapshot.storage.k8s.io API
	// This is a simplified representation - in a real implementation you would import the proper types
	
	snapshotClassName := fmt.Sprintf("%s-ebs-snapshots", instance.Name)
	
	// Create a ConfigMap to store snapshot configuration for now
	// In a real implementation, you would create actual VolumeSnapshotClass resources
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-snapshot-config", instance.Name),
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "snapshot",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Data: map[string]string{
			"snapshot-class": snapshotClassName,
			"driver":         "ebs.csi.aws.com",
			"deletion-policy": "Delete",
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, configMap, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update ConfigMap
	existingConfigMap := &corev1.ConfigMap{}
	configMapKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      configMap.Name,
	}

	if err := m.client.Get(ctx, configMapKey, existingConfigMap); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing ConfigMap: %w", err)
		}
		// ConfigMap doesn't exist, create it
		if err := m.client.Create(ctx, configMap); err != nil {
			return fmt.Errorf("failed to create snapshot ConfigMap: %w", err)
		}
		logger.Info("Snapshot ConfigMap created successfully")
	} else {
		// ConfigMap exists, update it
		existingConfigMap.Data = configMap.Data
		if err := m.client.Update(ctx, existingConfigMap); err != nil {
			return fmt.Errorf("failed to update snapshot ConfigMap: %w", err)
		}
		logger.Info("Snapshot ConfigMap updated successfully")
	}

	return nil
}

// createSnapshotSchedule creates a CronJob for automated snapshots
func (m *S3Manager) createSnapshotSchedule(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config PersistentStorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Creating snapshot schedule", "schedule", config.SnapshotPolicy.Schedule)

	// Create a ConfigMap with snapshot schedule configuration
	scheduleConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-snapshot-schedule", instance.Name),
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "snapshot-schedule",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Data: map[string]string{
			"schedule":  config.SnapshotPolicy.Schedule,
			"retention": config.SnapshotPolicy.Retention,
			"enabled":   strconv.FormatBool(config.SnapshotPolicy.Enabled),
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, scheduleConfigMap, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update ConfigMap
	existingConfigMap := &corev1.ConfigMap{}
	configMapKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      scheduleConfigMap.Name,
	}

	if err := m.client.Get(ctx, configMapKey, existingConfigMap); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing schedule ConfigMap: %w", err)
		}
		// ConfigMap doesn't exist, create it
		if err := m.client.Create(ctx, scheduleConfigMap); err != nil {
			return fmt.Errorf("failed to create schedule ConfigMap: %w", err)
		}
		logger.Info("Snapshot schedule ConfigMap created successfully")
	} else {
		// ConfigMap exists, update it
		existingConfigMap.Data = scheduleConfigMap.Data
		if err := m.client.Update(ctx, existingConfigMap); err != nil {
			return fmt.Errorf("failed to update schedule ConfigMap: %w", err)
		}
		logger.Info("Snapshot schedule ConfigMap updated successfully")
	}

	return nil
}

// configureVolumeExpansionMonitoring configures monitoring for automatic volume expansion
func (m *S3Manager) configureVolumeExpansionMonitoring(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config PersistentStorageConfig) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Configuring volume expansion monitoring")

	// Create a ConfigMap with expansion monitoring configuration
	monitoringConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-volume-monitoring", instance.Name),
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "volume-monitoring",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Data: map[string]string{
			"auto-expansion":     strconv.FormatBool(config.AutoExpansion),
			"expansion-threshold": "80", // Expand when 80% full
			"expansion-increment": "20", // Expand by 20% each time
			"max-size":           "1Ti", // Maximum size limit
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, monitoringConfigMap, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update ConfigMap
	existingConfigMap := &corev1.ConfigMap{}
	configMapKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      monitoringConfigMap.Name,
	}

	if err := m.client.Get(ctx, configMapKey, existingConfigMap); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing monitoring ConfigMap: %w", err)
		}
		// ConfigMap doesn't exist, create it
		if err := m.client.Create(ctx, monitoringConfigMap); err != nil {
			return fmt.Errorf("failed to create monitoring ConfigMap: %w", err)
		}
		logger.Info("Volume monitoring ConfigMap created successfully")
	} else {
		// ConfigMap exists, update it
		existingConfigMap.Data = monitoringConfigMap.Data
		if err := m.client.Update(ctx, existingConfigMap); err != nil {
			return fmt.Errorf("failed to update monitoring ConfigMap: %w", err)
		}
		logger.Info("Volume monitoring ConfigMap updated successfully")
	}

	return nil
}

// getVolumeMetrics retrieves metrics for persistent volumes
func (m *S3Manager) getVolumeMetrics(ctx context.Context, instance *n8nv1alpha1.N8nInstance) (map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Retrieving volume metrics")

	metrics := make(map[string]interface{})

	// List PVCs for this instance
	pvcList := &corev1.PersistentVolumeClaimList{}
	listOptions := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels{
			"app.kubernetes.io/instance": instance.Name,
		},
	}

	if err := m.client.List(ctx, pvcList, listOptions...); err != nil {
		return nil, fmt.Errorf("failed to list PVCs: %w", err)
	}

	pvcMetrics := make([]map[string]interface{}, 0, len(pvcList.Items))
	
	for _, pvc := range pvcList.Items {
		pvcMetric := map[string]interface{}{
			"name":      pvc.Name,
			"component": pvc.Labels["app.kubernetes.io/component"],
			"phase":     string(pvc.Status.Phase),
		}

		// Add capacity information
		if pvc.Status.Capacity != nil {
			if storage, exists := pvc.Status.Capacity[corev1.ResourceStorage]; exists {
				pvcMetric["capacity"] = storage.String()
			}
		}

		// Add requested size
		if pvc.Spec.Resources.Requests != nil {
			if storage, exists := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; exists {
				pvcMetric["requested"] = storage.String()
			}
		}

		// Add storage class
		if pvc.Spec.StorageClassName != nil {
			pvcMetric["storage_class"] = *pvc.Spec.StorageClassName
		}

		// Add access modes
		pvcMetric["access_modes"] = pvc.Spec.AccessModes

		pvcMetrics = append(pvcMetrics, pvcMetric)
	}

	metrics["pvcs"] = pvcMetrics
	metrics["pvc_count"] = len(pvcList.Items)

	logger.Info("Volume metrics retrieved", "pvcCount", len(pvcList.Items))
	return metrics, nil
}

// cleanupOrphanedVolumes cleans up orphaned volumes that are no longer needed
func (m *S3Manager) cleanupOrphanedVolumes(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("S3Manager")
	logger.Info("Cleaning up orphaned volumes")

	// List all PVCs for this instance
	pvcList := &corev1.PersistentVolumeClaimList{}
	listOptions := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels{
			"app.kubernetes.io/instance": instance.Name,
		},
	}

	if err := m.client.List(ctx, pvcList, listOptions...); err != nil {
		return fmt.Errorf("failed to list PVCs: %w", err)
	}

	// Define expected PVCs
	expectedPVCs := map[string]bool{
		fmt.Sprintf("%s-main-data", instance.Name):    true,
		fmt.Sprintf("%s-webhook-data", instance.Name): true,
	}

	// Check for orphaned PVCs
	for _, pvc := range pvcList.Items {
		if !expectedPVCs[pvc.Name] {
			logger.Info("Found orphaned PVC", "name", pvc.Name)
			
			// Check if PVC is safe to delete (not bound to a running pod)
			if pvc.Status.Phase == corev1.ClaimBound {
				logger.Warn("Orphaned PVC is bound, skipping deletion", "name", pvc.Name)
				continue
			}

			// Delete orphaned PVC
			if err := m.client.Delete(ctx, &pvc); err != nil {
				logger.Error(err, "Failed to delete orphaned PVC", "name", pvc.Name)
				continue
			}
			
			logger.Info("Deleted orphaned PVC", "name", pvc.Name)
		}
	}

	logger.Info("Orphaned volumes cleanup completed")
	return nil
}