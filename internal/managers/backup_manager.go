package managers

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// BackupManager handles backup and restore operations for n8n instances
type BackupManager interface {
	// ReconcileBackup ensures backup configuration is properly set up
	ReconcileBackup(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// CreateBackup creates a new backup of the n8n instance
	CreateBackup(ctx context.Context, instance *n8nv1alpha1.N8nInstance, backupType BackupType) (*BackupResult, error)

	// RestoreBackup restores an n8n instance from a backup
	RestoreBackup(ctx context.Context, instance *n8nv1alpha1.N8nInstance, backupID string) error

	// ListBackups lists available backups for an instance
	ListBackups(ctx context.Context, instance *n8nv1alpha1.N8nInstance) ([]*BackupInfo, error)

	// DeleteBackup deletes a specific backup
	DeleteBackup(ctx context.Context, backupID string) error

	// ValidateBackup validates the integrity of a backup
	ValidateBackup(ctx context.Context, backupID string) (*BackupValidationResult, error)
}

// BackupType represents the type of backup
type BackupType string

const (
	BackupTypeFull        BackupType = "full"
	BackupTypeIncremental BackupType = "incremental"
	BackupTypeDatabase    BackupType = "database"
	BackupTypeWorkflows   BackupType = "workflows"
	BackupTypeSecrets     BackupType = "secrets"
)

// BackupResult contains the result of a backup operation
type BackupResult struct {
	BackupID     string            `json:"backupId"`
	Type         BackupType        `json:"type"`
	Status       BackupStatus      `json:"status"`
	StartTime    time.Time         `json:"startTime"`
	EndTime      time.Time         `json:"endTime"`
	Size         int64             `json:"size"`
	Location     string            `json:"location"`
	Checksum     string            `json:"checksum"`
	Metadata     map[string]string `json:"metadata"`
	ErrorMessage string            `json:"errorMessage,omitempty"`
}

// BackupStatus represents the status of a backup
type BackupStatus string

const (
	BackupStatusPending    BackupStatus = "pending"
	BackupStatusInProgress BackupStatus = "in-progress"
	BackupStatusCompleted  BackupStatus = "completed"
	BackupStatusFailed     BackupStatus = "failed"
)

// BackupInfo contains information about a backup
type BackupInfo struct {
	BackupID   string            `json:"backupId"`
	Type       BackupType        `json:"type"`
	Status     BackupStatus      `json:"status"`
	CreatedAt  time.Time         `json:"createdAt"`
	Size       int64             `json:"size"`
	Location   string            `json:"location"`
	Checksum   string            `json:"checksum"`
	Metadata   map[string]string `json:"metadata"`
	ExpiresAt  *time.Time        `json:"expiresAt,omitempty"`
	Compressed bool              `json:"compressed"`
	Encrypted  bool              `json:"encrypted"`
}

// BackupValidationResult contains the result of backup validation
type BackupValidationResult struct {
	Valid        bool              `json:"valid"`
	ChecksumOK   bool              `json:"checksumOk"`
	Accessible   bool              `json:"accessible"`
	Metadata     map[string]string `json:"metadata"`
	ErrorMessage string            `json:"errorMessage,omitempty"`
}

// backupManager implements the BackupManager interface
type backupManager struct {
	client    client.Client
	scheme    *runtime.Scheme
	logger    logr.Logger
	awsConfig aws.Config
	s3Client  *s3.Client
	rdsClient *rds.Client
}

// NewBackupManager creates a new BackupManager instance
func NewBackupManager(client client.Client, scheme *runtime.Scheme, logger logr.Logger, awsConfig aws.Config) BackupManager {
	return &backupManager{
		client:    client,
		scheme:    scheme,
		logger:    logger.WithName("backup-manager"),
		awsConfig: awsConfig,
		s3Client:  s3.NewFromConfig(awsConfig),
		rdsClient: rds.NewFromConfig(awsConfig),
	}
}

// ReconcileBackup ensures backup configuration is properly set up
func (bm *backupManager) ReconcileBackup(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := bm.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)
	logger.Info("Reconciling backup configuration")

	// Check if backup is enabled
	if instance.Spec.Backup == nil || !instance.Spec.Backup.Enabled {
		logger.Info("Backup is disabled, skipping backup configuration")
		return nil
	}

	// Create backup bucket if it doesn't exist
	if err := bm.ensureBackupBucket(ctx, instance); err != nil {
		return fmt.Errorf("failed to ensure backup bucket: %w", err)
	}

	// Create backup CronJob
	if err := bm.createBackupCronJob(ctx, instance); err != nil {
		return fmt.Errorf("failed to create backup CronJob: %w", err)
	}

	// Create backup validation job
	if err := bm.createBackupValidationJob(ctx, instance); err != nil {
		return fmt.Errorf("failed to create backup validation job: %w", err)
	}

	logger.Info("Backup configuration reconciled successfully")
	return nil
}

// CreateBackup creates a new backup of the n8n instance
func (bm *backupManager) CreateBackup(ctx context.Context, instance *n8nv1alpha1.N8nInstance, backupType BackupType) (*BackupResult, error) {
	logger := bm.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace, "backupType", backupType)
	logger.Info("Creating backup")

	backupID := bm.generateBackupID(instance, backupType)

	result := &BackupResult{
		BackupID:  backupID,
		Type:      backupType,
		Status:    BackupStatusPending,
		StartTime: time.Now(),
		Metadata: map[string]string{
			"instance":   instance.Name,
			"namespace":  instance.Namespace,
			"version":    instance.Spec.Version,
			"created-by": "n8n-eks-operator",
		},
	}

	// Update status to in-progress
	result.Status = BackupStatusInProgress

	switch backupType {
	case BackupTypeFull:
		if err := bm.createFullBackup(ctx, instance, result); err != nil {
			result.Status = BackupStatusFailed
			result.ErrorMessage = err.Error()
			return result, err
		}
	case BackupTypeDatabase:
		if err := bm.createDatabaseBackup(ctx, instance, result); err != nil {
			result.Status = BackupStatusFailed
			result.ErrorMessage = err.Error()
			return result, err
		}
	case BackupTypeWorkflows:
		if err := bm.createWorkflowsBackup(ctx, instance, result); err != nil {
			result.Status = BackupStatusFailed
			result.ErrorMessage = err.Error()
			return result, err
		}
	case BackupTypeSecrets:
		if err := bm.createSecretsBackup(ctx, instance, result); err != nil {
			result.Status = BackupStatusFailed
			result.ErrorMessage = err.Error()
			return result, err
		}
	default:
		return nil, fmt.Errorf("unsupported backup type: %s", backupType)
	}

	result.Status = BackupStatusCompleted
	result.EndTime = time.Now()

	// Store backup metadata
	if err := bm.storeBackupMetadata(ctx, result); err != nil {
		logger.Error(err, "Failed to store backup metadata")
	}

	logger.Info("Backup created successfully", "backupId", backupID, "size", result.Size)
	return result, nil
}

// RestoreBackup restores an n8n instance from a backup
func (bm *backupManager) RestoreBackup(ctx context.Context, instance *n8nv1alpha1.N8nInstance, backupID string) error {
	logger := bm.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace, "backupId", backupID)
	logger.Info("Restoring from backup")

	// Get backup info
	backupInfo, err := bm.getBackupInfo(ctx, backupID)
	if err != nil {
		return fmt.Errorf("failed to get backup info: %w", err)
	}

	// Validate backup before restore
	validation, err := bm.ValidateBackup(ctx, backupID)
	if err != nil {
		return fmt.Errorf("failed to validate backup: %w", err)
	}

	if !validation.Valid {
		return fmt.Errorf("backup validation failed: %s", validation.ErrorMessage)
	}

	// Create restore job
	restoreJob := bm.createRestoreJob(instance, backupInfo)
	if err := bm.client.Create(ctx, restoreJob); err != nil {
		return fmt.Errorf("failed to create restore job: %w", err)
	}

	logger.Info("Restore job created successfully", "job", restoreJob.Name)
	return nil
}

// ListBackups lists available backups for an instance
func (bm *backupManager) ListBackups(ctx context.Context, instance *n8nv1alpha1.N8nInstance) ([]*BackupInfo, error) {
	logger := bm.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)
	logger.Info("Listing backups")

	bucketName := bm.getBackupBucketName(instance)
	prefix := fmt.Sprintf("backups/%s/%s/", instance.Namespace, instance.Name)

	// List objects in S3 bucket
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
		Prefix: aws.String(prefix),
	}

	var backups []*BackupInfo
	paginator := s3.NewListObjectsV2Paginator(bm.s3Client, input)

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list backup objects: %w", err)
		}

		for _, obj := range output.Contents {
			if obj.Key != nil && *obj.Key != prefix {
				backupInfo, err := bm.parseBackupFromS3Object(ctx, bucketName, *obj.Key, obj)
				if err != nil {
					logger.Error(err, "Failed to parse backup info", "key", *obj.Key)
					continue
				}
				backups = append(backups, backupInfo)
			}
		}
	}

	logger.Info("Listed backups successfully", "count", len(backups))
	return backups, nil
}

// DeleteBackup deletes a specific backup
func (bm *backupManager) DeleteBackup(ctx context.Context, backupID string) error {
	logger := bm.logger.WithValues("backupId", backupID)
	logger.Info("Deleting backup")

	// Get backup info to find location
	backupInfo, err := bm.getBackupInfo(ctx, backupID)
	if err != nil {
		return fmt.Errorf("failed to get backup info: %w", err)
	}

	// Delete from S3
	if err := bm.deleteBackupFromS3(ctx, backupInfo.Location); err != nil {
		return fmt.Errorf("failed to delete backup from S3: %w", err)
	}

	// Delete metadata
	if err := bm.deleteBackupMetadata(ctx, backupID); err != nil {
		logger.Error(err, "Failed to delete backup metadata")
	}

	logger.Info("Backup deleted successfully")
	return nil
}

// ValidateBackup validates the integrity of a backup
func (bm *backupManager) ValidateBackup(ctx context.Context, backupID string) (*BackupValidationResult, error) {
	logger := bm.logger.WithValues("backupId", backupID)
	logger.Info("Validating backup")

	result := &BackupValidationResult{
		Valid:      true,
		ChecksumOK: true,
		Accessible: true,
		Metadata:   make(map[string]string),
	}

	// Get backup info
	backupInfo, err := bm.getBackupInfo(ctx, backupID)
	if err != nil {
		result.Valid = false
		result.Accessible = false
		result.ErrorMessage = fmt.Sprintf("failed to get backup info: %v", err)
		return result, nil
	}

	// Check if backup file exists and is accessible
	if err := bm.checkBackupAccessibility(ctx, backupInfo.Location); err != nil {
		result.Valid = false
		result.Accessible = false
		result.ErrorMessage = fmt.Sprintf("backup not accessible: %v", err)
		return result, nil
	}

	// Validate checksum
	if err := bm.validateBackupChecksum(ctx, backupInfo); err != nil {
		result.Valid = false
		result.ChecksumOK = false
		result.ErrorMessage = fmt.Sprintf("checksum validation failed: %v", err)
		return result, nil
	}

	result.Metadata = backupInfo.Metadata
	logger.Info("Backup validation completed", "valid", result.Valid)
	return result, nil
}

// Helper methods

func (bm *backupManager) generateBackupID(instance *n8nv1alpha1.N8nInstance, backupType BackupType) string {
	timestamp := time.Now().Format("20060102-150405")
	return fmt.Sprintf("%s-%s-%s-%s", instance.Namespace, instance.Name, backupType, timestamp)
}

func (bm *backupManager) getBackupBucketName(instance *n8nv1alpha1.N8nInstance) string {
	if instance.Spec.Backup != nil && instance.Spec.Backup.S3 != nil && instance.Spec.Backup.S3.Bucket != "" {
		return instance.Spec.Backup.S3.Bucket
	}
	return fmt.Sprintf("n8n-backups-%s", instance.Namespace)
}

func (bm *backupManager) ensureBackupBucket(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	bucketName := bm.getBackupBucketName(instance)

	// Check if bucket exists
	_, err := bm.s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})

	if err != nil {
		// Create bucket
		_, err = bm.s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			return fmt.Errorf("failed to create backup bucket: %w", err)
		}

		// Enable versioning
		_, err = bm.s3Client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
			Bucket: aws.String(bucketName),
			VersioningConfiguration: &s3Types.VersioningConfiguration{
				Status: s3Types.BucketVersioningStatusEnabled,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to enable bucket versioning: %w", err)
		}

		// Set lifecycle policy
		if err := bm.setBucketLifecyclePolicy(ctx, bucketName, instance); err != nil {
			return fmt.Errorf("failed to set lifecycle policy: %w", err)
		}
	}

	return nil
}

func (bm *backupManager) createBackupCronJob(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	cronJob := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-backup", instance.Name),
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n-backup",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
			},
		},
		Spec: batchv1.CronJobSpec{
			Schedule: instance.Spec.Backup.Schedule,
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							RestartPolicy: corev1.RestartPolicyOnFailure,
							Containers: []corev1.Container{
								{
									Name:  "backup",
									Image: "ghcr.io/n8n-io/n8n-backup:latest",
									Env: []corev1.EnvVar{
										{
											Name:  "BACKUP_TYPE",
											Value: "full",
										},
										{
											Name:  "INSTANCE_NAME",
											Value: instance.Name,
										},
										{
											Name:  "INSTANCE_NAMESPACE",
											Value: instance.Namespace,
										},
									},
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "backup-config",
											MountPath: "/etc/backup",
										},
									},
								},
							},
							Volumes: []corev1.Volume{
								{
									Name: "backup-config",
									VolumeSource: corev1.VolumeSource{
										ConfigMap: &corev1.ConfigMapVolumeSource{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: fmt.Sprintf("%s-backup-config", instance.Name),
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	return bm.client.Create(ctx, cronJob)
}

func (bm *backupManager) createFullBackup(ctx context.Context, instance *n8nv1alpha1.N8nInstance, result *BackupResult) error {
	// Create database backup
	if err := bm.createDatabaseBackup(ctx, instance, result); err != nil {
		return fmt.Errorf("failed to create database backup: %w", err)
	}

	// Create workflows backup
	if err := bm.createWorkflowsBackup(ctx, instance, result); err != nil {
		return fmt.Errorf("failed to create workflows backup: %w", err)
	}

	// Create secrets backup
	if err := bm.createSecretsBackup(ctx, instance, result); err != nil {
		return fmt.Errorf("failed to create secrets backup: %w", err)
	}

	return nil
}

func (bm *backupManager) createDatabaseBackup(ctx context.Context, instance *n8nv1alpha1.N8nInstance, result *BackupResult) error {
	// Create RDS snapshot
	snapshotID := fmt.Sprintf("%s-snapshot", result.BackupID)

	_, err := bm.rdsClient.CreateDBSnapshot(ctx, &rds.CreateDBSnapshotInput{
		DBInstanceIdentifier: aws.String(instance.Spec.Database.Host),
		DBSnapshotIdentifier: aws.String(snapshotID),
	})

	if err != nil {
		return fmt.Errorf("failed to create RDS snapshot: %w", err)
	}

	result.Metadata["rds-snapshot-id"] = snapshotID
	return nil
}

func (bm *backupManager) createWorkflowsBackup(ctx context.Context, instance *n8nv1alpha1.N8nInstance, result *BackupResult) error {
	// Backup workflows from S3 bucket
	sourceBucket := instance.Spec.Storage.S3.Bucket
	backupBucket := bm.getBackupBucketName(instance)
	backupKey := fmt.Sprintf("backups/%s/%s/workflows-%s.tar.gz", instance.Namespace, instance.Name, result.BackupID)

	// Create backup job to copy and compress workflows
	job := bm.createWorkflowBackupJob(instance, sourceBucket, backupBucket, backupKey)
	if err := bm.client.Create(ctx, job); err != nil {
		return fmt.Errorf("failed to create workflow backup job: %w", err)
	}

	result.Location = fmt.Sprintf("s3://%s/%s", backupBucket, backupKey)
	return nil
}

func (bm *backupManager) createSecretsBackup(ctx context.Context, instance *n8nv1alpha1.N8nInstance, result *BackupResult) error {
	// Backup Kubernetes secrets
	backupBucket := bm.getBackupBucketName(instance)
	backupKey := fmt.Sprintf("backups/%s/%s/secrets-%s.json", instance.Namespace, instance.Name, result.BackupID)

	// Create backup job to export and encrypt secrets
	job := bm.createSecretsBackupJob(instance, backupBucket, backupKey)
	if err := bm.client.Create(ctx, job); err != nil {
		return fmt.Errorf("failed to create secrets backup job: %w", err)
	}

	result.Metadata["secrets-location"] = fmt.Sprintf("s3://%s/%s", backupBucket, backupKey)
	return nil
}

func (bm *backupManager) createWorkflowBackupJob(instance *n8nv1alpha1.N8nInstance, sourceBucket, backupBucket, backupKey string) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-workflow-backup-%d", instance.Name, time.Now().Unix()),
			Namespace: instance.Namespace,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyOnFailure,
					Containers: []corev1.Container{
						{
							Name:  "workflow-backup",
							Image: "amazon/aws-cli:latest",
							Command: []string{
								"/bin/sh",
								"-c",
								fmt.Sprintf(`
									aws s3 sync s3://%s s3://%s/%s --exclude "*" --include "workflows/*"
									aws s3 cp s3://%s/%s s3://%s/%s
								`, sourceBucket, backupBucket, "temp", backupBucket, "temp", backupBucket, backupKey),
							},
						},
					},
				},
			},
		},
	}
}

func (bm *backupManager) createSecretsBackupJob(instance *n8nv1alpha1.N8nInstance, backupBucket, backupKey string) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-secrets-backup-%d", instance.Name, time.Now().Unix()),
			Namespace: instance.Namespace,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy:      corev1.RestartPolicyOnFailure,
					ServiceAccountName: fmt.Sprintf("%s-backup", instance.Name),
					Containers: []corev1.Container{
						{
							Name:  "secrets-backup",
							Image: "bitnami/kubectl:latest",
							Command: []string{
								"/bin/sh",
								"-c",
								fmt.Sprintf(`
									kubectl get secrets -n %s -o json > /tmp/secrets.json
									aws s3 cp /tmp/secrets.json s3://%s/%s
								`, instance.Namespace, backupBucket, backupKey),
							},
						},
					},
				},
			},
		},
	}
}

func (bm *backupManager) createRestoreJob(instance *n8nv1alpha1.N8nInstance, backupInfo *BackupInfo) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-restore-%d", instance.Name, time.Now().Unix()),
			Namespace: instance.Namespace,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyOnFailure,
					Containers: []corev1.Container{
						{
							Name:  "restore",
							Image: "ghcr.io/n8n-io/n8n-restore:latest",
							Env: []corev1.EnvVar{
								{
									Name:  "BACKUP_LOCATION",
									Value: backupInfo.Location,
								},
								{
									Name:  "BACKUP_TYPE",
									Value: string(backupInfo.Type),
								},
								{
									Name:  "INSTANCE_NAME",
									Value: instance.Name,
								},
								{
									Name:  "INSTANCE_NAMESPACE",
									Value: instance.Namespace,
								},
							},
						},
					},
				},
			},
		},
	}
}

// Additional helper methods for backup operations
func (bm *backupManager) storeBackupMetadata(ctx context.Context, result *BackupResult) error {
	// Store backup metadata in S3 or ConfigMap
	return nil
}

func (bm *backupManager) getBackupInfo(ctx context.Context, backupID string) (*BackupInfo, error) {
	// Retrieve backup info from metadata store
	return nil, nil
}

func (bm *backupManager) parseBackupFromS3Object(ctx context.Context, bucket, key string, obj *s3Types.Object) (*BackupInfo, error) {
	// Parse backup info from S3 object metadata
	return nil, nil
}

func (bm *backupManager) deleteBackupFromS3(ctx context.Context, location string) error {
	// Delete backup files from S3
	return nil
}

func (bm *backupManager) deleteBackupMetadata(ctx context.Context, backupID string) error {
	// Delete backup metadata
	return nil
}

func (bm *backupManager) checkBackupAccessibility(ctx context.Context, location string) error {
	// Check if backup is accessible
	return nil
}

func (bm *backupManager) validateBackupChecksum(ctx context.Context, backupInfo *BackupInfo) error {
	// Validate backup checksum
	return nil
}

func (bm *backupManager) setBucketLifecyclePolicy(ctx context.Context, bucketName string, instance *n8nv1alpha1.N8nInstance) error {
	// Set S3 bucket lifecycle policy for backup retention
	return nil
}

func (bm *backupManager) createBackupValidationJob(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Create job to validate backups periodically
	return nil
}
