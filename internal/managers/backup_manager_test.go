package managers

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// MockBackupManager is a mock implementation of BackupManager
type MockBackupManager struct {
	mock.Mock
}

func (m *MockBackupManager) ReconcileBackup(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	args := m.Called(ctx, instance)
	return args.Error(0)
}

func (m *MockBackupManager) CreateBackup(ctx context.Context, instance *n8nv1alpha1.N8nInstance, backupType BackupType) (*BackupResult, error) {
	args := m.Called(ctx, instance, backupType)
	return args.Get(0).(*BackupResult), args.Error(1)
}

func (m *MockBackupManager) RestoreBackup(ctx context.Context, instance *n8nv1alpha1.N8nInstance, backupID string) error {
	args := m.Called(ctx, instance, backupID)
	return args.Error(0)
}

func (m *MockBackupManager) ListBackups(ctx context.Context, instance *n8nv1alpha1.N8nInstance) ([]*BackupInfo, error) {
	args := m.Called(ctx, instance)
	return args.Get(0).([]*BackupInfo), args.Error(1)
}

func (m *MockBackupManager) DeleteBackup(ctx context.Context, backupID string) error {
	args := m.Called(ctx, backupID)
	return args.Error(0)
}

func (m *MockBackupManager) ValidateBackup(ctx context.Context, backupID string) (*BackupValidationResult, error) {
	args := m.Called(ctx, backupID)
	return args.Get(0).(*BackupValidationResult), args.Error(1)
}

func TestNewBackupManager(t *testing.T) {
	scheme := runtime.NewScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	logger := logr.Discard()
	awsConfig := aws.Config{}

	manager := NewBackupManager(client, scheme, logger, awsConfig)
	assert.NotNil(t, manager)
}

func TestBackupManager_ReconcileBackup(t *testing.T) {
	tests := []struct {
		name     string
		instance *n8nv1alpha1.N8nInstance
		wantErr  bool
	}{
		{
			name: "backup disabled",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-n8n",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Backup: &n8nv1alpha1.BackupSpec{
						Enabled: false,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "backup enabled",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-n8n",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Backup: &n8nv1alpha1.BackupSpec{
						Enabled:  true,
						Schedule: "0 2 * * *",
						S3: &n8nv1alpha1.S3BackupSpec{
							Bucket: "test-backup-bucket",
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, batchv1.AddToScheme(scheme))
			require.NoError(t, corev1.AddToScheme(scheme))

			client := fake.NewClientBuilder().WithScheme(scheme).Build()
			logger := logr.Discard()
			awsConfig := aws.Config{}

			bm := &backupManager{
				client:    client,
				scheme:    scheme,
				logger:    logger,
				awsConfig: awsConfig,
			}

			err := bm.ReconcileBackup(context.TODO(), tt.instance)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBackupManager_CreateBackup(t *testing.T) {
	tests := []struct {
		name       string
		instance   *n8nv1alpha1.N8nInstance
		backupType BackupType
		wantErr    bool
	}{
		{
			name: "create full backup",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-n8n",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Version: "1.0.0",
					Database: n8nv1alpha1.DatabaseSpec{
						Host: "test-db-host",
					},
					Storage: n8nv1alpha1.StorageSpec{
						S3: &n8nv1alpha1.S3StorageSpec{
							Bucket: "test-storage-bucket",
						},
					},
				},
			},
			backupType: BackupTypeFull,
			wantErr:    false,
		},
		{
			name: "create database backup",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-n8n",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Version: "1.0.0",
					Database: n8nv1alpha1.DatabaseSpec{
						Host: "test-db-host",
					},
				},
			},
			backupType: BackupTypeDatabase,
			wantErr:    false,
		},
		{
			name: "unsupported backup type",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-n8n",
					Namespace: "default",
				},
			},
			backupType: BackupType("unsupported"),
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, batchv1.AddToScheme(scheme))
			require.NoError(t, corev1.AddToScheme(scheme))

			client := fake.NewClientBuilder().WithScheme(scheme).Build()
			logger := logr.Discard()
			awsConfig := aws.Config{}

			bm := &backupManager{
				client:    client,
				scheme:    scheme,
				logger:    logger,
				awsConfig: awsConfig,
			}

			result, err := bm.CreateBackup(context.TODO(), tt.instance, tt.backupType)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.backupType, result.Type)
				assert.NotEmpty(t, result.BackupID)
				assert.Equal(t, tt.instance.Name, result.Metadata["instance"])
				assert.Equal(t, tt.instance.Namespace, result.Metadata["namespace"])
			}
		})
	}
}

func TestBackupManager_GenerateBackupID(t *testing.T) {
	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-n8n",
			Namespace: "default",
		},
	}

	bm := &backupManager{}
	backupID := bm.generateBackupID(instance, BackupTypeFull)

	assert.Contains(t, backupID, "default")
	assert.Contains(t, backupID, "test-n8n")
	assert.Contains(t, backupID, "full")
	assert.Regexp(t, `\d{8}-\d{6}`, backupID)
}

func TestBackupManager_GetBackupBucketName(t *testing.T) {
	tests := []struct {
		name     string
		instance *n8nv1alpha1.N8nInstance
		expected string
	}{
		{
			name: "custom bucket specified",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-n8n",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Backup: &n8nv1alpha1.BackupSpec{
						S3: &n8nv1alpha1.S3BackupSpec{
							Bucket: "custom-backup-bucket",
						},
					},
				},
			},
			expected: "custom-backup-bucket",
		},
		{
			name: "default bucket name",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-n8n",
					Namespace: "production",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{},
			},
			expected: "n8n-backups-production",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bm := &backupManager{}
			result := bm.getBackupBucketName(tt.instance)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBackupManager_CreateBackupCronJob(t *testing.T) {
	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-n8n",
			Namespace: "default",
		},
		Spec: n8nv1alpha1.N8nInstanceSpec{
			Backup: &n8nv1alpha1.BackupSpec{
				Enabled:  true,
				Schedule: "0 2 * * *",
			},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, batchv1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	logger := logr.Discard()

	bm := &backupManager{
		client: client,
		scheme: scheme,
		logger: logger,
	}

	err := bm.createBackupCronJob(context.TODO(), instance)
	assert.NoError(t, err)

	// Verify CronJob was created
	cronJob := &batchv1.CronJob{}
	err = client.Get(context.TODO(), client.ObjectKey{
		Name:      "test-n8n-backup",
		Namespace: "default",
	}, cronJob)
	assert.NoError(t, err)
	assert.Equal(t, "0 2 * * *", cronJob.Spec.Schedule)
}

func TestBackupManager_CreateWorkflowBackupJob(t *testing.T) {
	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-n8n",
			Namespace: "default",
		},
	}

	bm := &backupManager{}
	job := bm.createWorkflowBackupJob(instance, "source-bucket", "backup-bucket", "backup-key")

	assert.NotNil(t, job)
	assert.Equal(t, "default", job.Namespace)
	assert.Contains(t, job.Name, "test-n8n-workflow-backup")
	assert.Equal(t, corev1.RestartPolicyOnFailure, job.Spec.Template.Spec.RestartPolicy)
	assert.Len(t, job.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, "workflow-backup", job.Spec.Template.Spec.Containers[0].Name)
}

func TestBackupManager_CreateSecretsBackupJob(t *testing.T) {
	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-n8n",
			Namespace: "default",
		},
	}

	bm := &backupManager{}
	job := bm.createSecretsBackupJob(instance, "backup-bucket", "backup-key")

	assert.NotNil(t, job)
	assert.Equal(t, "default", job.Namespace)
	assert.Contains(t, job.Name, "test-n8n-secrets-backup")
	assert.Equal(t, corev1.RestartPolicyOnFailure, job.Spec.Template.Spec.RestartPolicy)
	assert.Equal(t, "test-n8n-backup", job.Spec.Template.Spec.ServiceAccountName)
	assert.Len(t, job.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, "secrets-backup", job.Spec.Template.Spec.Containers[0].Name)
}

func TestBackupManager_CreateRestoreJob(t *testing.T) {
	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-n8n",
			Namespace: "default",
		},
	}

	backupInfo := &BackupInfo{
		BackupID: "test-backup-id",
		Type:     BackupTypeFull,
		Location: "s3://backup-bucket/backup-key",
	}

	bm := &backupManager{}
	job := bm.createRestoreJob(instance, backupInfo)

	assert.NotNil(t, job)
	assert.Equal(t, "default", job.Namespace)
	assert.Contains(t, job.Name, "test-n8n-restore")
	assert.Equal(t, corev1.RestartPolicyOnFailure, job.Spec.Template.Spec.RestartPolicy)
	assert.Len(t, job.Spec.Template.Spec.Containers, 1)

	container := job.Spec.Template.Spec.Containers[0]
	assert.Equal(t, "restore", container.Name)
	assert.Equal(t, "ghcr.io/n8n-io/n8n-restore:latest", container.Image)

	// Check environment variables
	envVars := make(map[string]string)
	for _, env := range container.Env {
		envVars[env.Name] = env.Value
	}
	assert.Equal(t, "s3://backup-bucket/backup-key", envVars["BACKUP_LOCATION"])
	assert.Equal(t, "full", envVars["BACKUP_TYPE"])
	assert.Equal(t, "test-n8n", envVars["INSTANCE_NAME"])
	assert.Equal(t, "default", envVars["INSTANCE_NAMESPACE"])
}

func TestBackupResult(t *testing.T) {
	result := &BackupResult{
		BackupID:  "test-backup-123",
		Type:      BackupTypeFull,
		Status:    BackupStatusCompleted,
		StartTime: time.Now().Add(-1 * time.Hour),
		EndTime:   time.Now(),
		Size:      1024 * 1024 * 100, // 100MB
		Location:  "s3://backup-bucket/backup-key",
		Checksum:  "sha256:abcd1234",
		Metadata: map[string]string{
			"instance":  "test-n8n",
			"namespace": "default",
			"version":   "1.0.0",
		},
	}

	assert.Equal(t, "test-backup-123", result.BackupID)
	assert.Equal(t, BackupTypeFull, result.Type)
	assert.Equal(t, BackupStatusCompleted, result.Status)
	assert.True(t, result.EndTime.After(result.StartTime))
	assert.Equal(t, int64(1024*1024*100), result.Size)
	assert.Equal(t, "s3://backup-bucket/backup-key", result.Location)
	assert.Equal(t, "sha256:abcd1234", result.Checksum)
	assert.Equal(t, "test-n8n", result.Metadata["instance"])
}

func TestBackupInfo(t *testing.T) {
	createdAt := time.Now().Add(-24 * time.Hour)
	expiresAt := time.Now().Add(30 * 24 * time.Hour) // 30 days from now

	info := &BackupInfo{
		BackupID:   "test-backup-456",
		Type:       BackupTypeDatabase,
		Status:     BackupStatusCompleted,
		CreatedAt:  createdAt,
		Size:       1024 * 1024 * 50, // 50MB
		Location:   "s3://backup-bucket/db-backup-key",
		Checksum:   "sha256:efgh5678",
		ExpiresAt:  &expiresAt,
		Compressed: true,
		Encrypted:  true,
		Metadata: map[string]string{
			"database-version": "14.9",
			"backup-method":    "snapshot",
		},
	}

	assert.Equal(t, "test-backup-456", info.BackupID)
	assert.Equal(t, BackupTypeDatabase, info.Type)
	assert.Equal(t, BackupStatusCompleted, info.Status)
	assert.Equal(t, createdAt, info.CreatedAt)
	assert.Equal(t, int64(1024*1024*50), info.Size)
	assert.True(t, info.Compressed)
	assert.True(t, info.Encrypted)
	assert.NotNil(t, info.ExpiresAt)
	assert.Equal(t, "14.9", info.Metadata["database-version"])
}

func TestBackupValidationResult(t *testing.T) {
	result := &BackupValidationResult{
		Valid:      true,
		ChecksumOK: true,
		Accessible: true,
		Metadata: map[string]string{
			"validation-time": time.Now().Format(time.RFC3339),
			"validator":       "n8n-eks-operator",
		},
	}

	assert.True(t, result.Valid)
	assert.True(t, result.ChecksumOK)
	assert.True(t, result.Accessible)
	assert.Empty(t, result.ErrorMessage)
	assert.Equal(t, "n8n-eks-operator", result.Metadata["validator"])
}

func TestBackupValidationResult_Invalid(t *testing.T) {
	result := &BackupValidationResult{
		Valid:        false,
		ChecksumOK:   false,
		Accessible:   true,
		ErrorMessage: "Checksum mismatch detected",
		Metadata: map[string]string{
			"expected-checksum": "sha256:abcd1234",
			"actual-checksum":   "sha256:efgh5678",
		},
	}

	assert.False(t, result.Valid)
	assert.False(t, result.ChecksumOK)
	assert.True(t, result.Accessible)
	assert.Equal(t, "Checksum mismatch detected", result.ErrorMessage)
	assert.Equal(t, "sha256:abcd1234", result.Metadata["expected-checksum"])
}

// Benchmark tests
func BenchmarkGenerateBackupID(b *testing.B) {
	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-n8n",
			Namespace: "default",
		},
	}

	bm := &backupManager{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bm.generateBackupID(instance, BackupTypeFull)
	}
}

func BenchmarkGetBackupBucketName(b *testing.B) {
	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-n8n",
			Namespace: "default",
		},
		Spec: n8nv1alpha1.N8nInstanceSpec{
			Backup: &n8nv1alpha1.BackupSpec{
				S3: &n8nv1alpha1.S3BackupSpec{
					Bucket: "custom-backup-bucket",
				},
			},
		},
	}

	bm := &backupManager{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bm.getBackupBucketName(instance)
	}
}
