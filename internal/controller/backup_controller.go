package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
	"github.com/lxhiguera/n8n-eks-operator/internal/managers"
)

// BackupReconciler reconciles backup operations for N8nInstance resources
type BackupReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Logger        logr.Logger
	BackupManager managers.BackupManager
}

// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles backup-related reconciliation for N8nInstance resources
func (r *BackupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Logger.WithValues("backup", req.NamespacedName)
	logger.Info("Starting backup reconciliation")

	// Fetch the N8nInstance
	var instance n8nv1alpha1.N8nInstance
	if err := r.Get(ctx, req.NamespacedName, &instance); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("N8nInstance not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get N8nInstance")
		return ctrl.Result{}, err
	}

	// Check if backup is enabled
	if instance.Spec.Backup == nil || !instance.Spec.Backup.Enabled {
		logger.Info("Backup is disabled for this instance")
		return ctrl.Result{}, nil
	}

	// Handle backup reconciliation
	if err := r.reconcileBackup(ctx, &instance); err != nil {
		logger.Error(err, "Failed to reconcile backup")
		r.recordEvent(&instance, corev1.EventTypeWarning, "BackupReconciliationFailed", err.Error())
		return ctrl.Result{RequeueAfter: time.Minute * 5}, err
	}

	// Handle backup cleanup
	if err := r.reconcileBackupCleanup(ctx, &instance); err != nil {
		logger.Error(err, "Failed to reconcile backup cleanup")
		r.recordEvent(&instance, corev1.EventTypeWarning, "BackupCleanupFailed", err.Error())
		return ctrl.Result{RequeueAfter: time.Minute * 10}, err
	}

	// Handle backup validation
	if err := r.reconcileBackupValidation(ctx, &instance); err != nil {
		logger.Error(err, "Failed to reconcile backup validation")
		r.recordEvent(&instance, corev1.EventTypeWarning, "BackupValidationFailed", err.Error())
		return ctrl.Result{RequeueAfter: time.Minute * 15}, err
	}

	logger.Info("Backup reconciliation completed successfully")
	r.recordEvent(&instance, corev1.EventTypeNormal, "BackupReconciled", "Backup configuration reconciled successfully")

	// Requeue for periodic validation
	return ctrl.Result{RequeueAfter: time.Hour}, nil
}

// reconcileBackup handles the main backup reconciliation logic
func (r *BackupReconciler) reconcileBackup(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := r.Logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)

	// Reconcile backup configuration
	if err := r.BackupManager.ReconcileBackup(ctx, instance); err != nil {
		return fmt.Errorf("failed to reconcile backup configuration: %w", err)
	}

	// Create backup ServiceAccount if needed
	if err := r.reconcileBackupServiceAccount(ctx, instance); err != nil {
		return fmt.Errorf("failed to reconcile backup service account: %w", err)
	}

	// Create backup ConfigMap
	if err := r.reconcileBackupConfigMap(ctx, instance); err != nil {
		return fmt.Errorf("failed to reconcile backup config map: %w", err)
	}

	// Update instance status
	if err := r.updateBackupStatus(ctx, instance); err != nil {
		return fmt.Errorf("failed to update backup status: %w", err)
	}

	logger.Info("Backup reconciliation completed")
	return nil
}

// reconcileBackupServiceAccount creates or updates the backup service account
func (r *BackupReconciler) reconcileBackupServiceAccount(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-backup", instance.Name),
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n-backup",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"app.kubernetes.io/component":  "backup",
			},
		},
	}

	// Set owner reference
	if err := controllerutil.SetControllerReference(instance, serviceAccount, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update service account
	if err := r.Client.Create(ctx, serviceAccount); err != nil {
		if !errors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create backup service account: %w", err)
		}
		// Update existing service account
		existing := &corev1.ServiceAccount{}
		if err := r.Get(ctx, types.NamespacedName{Name: serviceAccount.Name, Namespace: serviceAccount.Namespace}, existing); err != nil {
			return fmt.Errorf("failed to get existing service account: %w", err)
		}
		existing.Labels = serviceAccount.Labels
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update backup service account: %w", err)
		}
	}

	return nil
}

// reconcileBackupConfigMap creates or updates the backup configuration
func (r *BackupReconciler) reconcileBackupConfigMap(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	configData := r.generateBackupConfig(instance)

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-backup-config", instance.Name),
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n-backup",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"app.kubernetes.io/component":  "backup",
			},
		},
		Data: configData,
	}

	// Set owner reference
	if err := controllerutil.SetControllerReference(instance, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update config map
	if err := r.Client.Create(ctx, configMap); err != nil {
		if !errors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create backup config map: %w", err)
		}
		// Update existing config map
		existing := &corev1.ConfigMap{}
		if err := r.Get(ctx, types.NamespacedName{Name: configMap.Name, Namespace: configMap.Namespace}, existing); err != nil {
			return fmt.Errorf("failed to get existing config map: %w", err)
		}
		existing.Data = configMap.Data
		existing.Labels = configMap.Labels
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update backup config map: %w", err)
		}
	}

	return nil
}

// generateBackupConfig generates the backup configuration data
func (r *BackupReconciler) generateBackupConfig(instance *n8nv1alpha1.N8nInstance) map[string]string {
	config := map[string]string{
		"backup.yaml": fmt.Sprintf(`
backup:
  enabled: %t
  schedule: "%s"
  retention:
    daily: %d
    weekly: %d
    monthly: %d
    yearly: %d
  s3:
    bucket: "%s"
    region: "%s"
    prefix: "backups/%s/%s"
    encryption: "%s"
  compression:
    enabled: %t
    algorithm: "gzip"
  validation:
    enabled: %t
    schedule: "0 4 * * *"
database:
  type: "%s"
  host: "%s"
  port: %d
  name: "%s"
storage:
  s3:
    bucket: "%s"
    region: "%s"
`,
			instance.Spec.Backup.Enabled,
			instance.Spec.Backup.Schedule,
			getRetentionDays(instance.Spec.Backup.Retention, "daily", 7),
			getRetentionDays(instance.Spec.Backup.Retention, "weekly", 4),
			getRetentionDays(instance.Spec.Backup.Retention, "monthly", 12),
			getRetentionDays(instance.Spec.Backup.Retention, "yearly", 5),
			getBackupS3Bucket(instance),
			getBackupS3Region(instance),
			instance.Namespace,
			instance.Name,
			getBackupEncryption(instance),
			true, // compression enabled by default
			true, // validation enabled by default
			instance.Spec.Database.Type,
			instance.Spec.Database.Host,
			instance.Spec.Database.Port,
			instance.Spec.Database.Name,
			instance.Spec.Storage.S3.Bucket,
			instance.Spec.Storage.S3.Region,
		),
	}

	// Add backup script
	config["backup.sh"] = `#!/bin/bash
set -euo pipefail

# Load configuration
source /etc/backup/backup.yaml

# Create backup directory
BACKUP_DIR="/tmp/backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to create database backup
backup_database() {
    log "Creating database backup..."
    pg_dump -h "$DATABASE_HOST" -p "$DATABASE_PORT" -U "$DATABASE_USER" -d "$DATABASE_NAME" \
        --no-password --verbose --format=custom --compress=9 \
        > "$BACKUP_DIR/database.dump"
    log "Database backup completed"
}

# Function to backup workflows
backup_workflows() {
    log "Creating workflows backup..."
    aws s3 sync "s3://$STORAGE_S3_BUCKET" "$BACKUP_DIR/workflows" \
        --exclude "*" --include "workflows/*"
    tar -czf "$BACKUP_DIR/workflows.tar.gz" -C "$BACKUP_DIR" workflows/
    rm -rf "$BACKUP_DIR/workflows"
    log "Workflows backup completed"
}

# Function to backup secrets
backup_secrets() {
    log "Creating secrets backup..."
    kubectl get secrets -n "$INSTANCE_NAMESPACE" -o json > "$BACKUP_DIR/secrets.json"
    log "Secrets backup completed"
}

# Function to upload backup to S3
upload_backup() {
    log "Uploading backup to S3..."
    BACKUP_KEY="$S3_PREFIX/$(basename $BACKUP_DIR).tar.gz"
    tar -czf "/tmp/$(basename $BACKUP_DIR).tar.gz" -C "/tmp" "$(basename $BACKUP_DIR)"
    aws s3 cp "/tmp/$(basename $BACKUP_DIR).tar.gz" "s3://$S3_BUCKET/$BACKUP_KEY"
    
    # Calculate and store checksum
    CHECKSUM=$(sha256sum "/tmp/$(basename $BACKUP_DIR).tar.gz" | cut -d' ' -f1)
    echo "$CHECKSUM" | aws s3 cp - "s3://$S3_BUCKET/$BACKUP_KEY.sha256"
    
    log "Backup uploaded successfully: s3://$S3_BUCKET/$BACKUP_KEY"
}

# Function to cleanup old backups
cleanup_old_backups() {
    log "Cleaning up old backups..."
    # Implementation for cleanup based on retention policy
    log "Cleanup completed"
}

# Main backup process
main() {
    log "Starting backup process for $INSTANCE_NAME"
    
    case "${BACKUP_TYPE:-full}" in
        "full")
            backup_database
            backup_workflows
            backup_secrets
            ;;
        "database")
            backup_database
            ;;
        "workflows")
            backup_workflows
            ;;
        "secrets")
            backup_secrets
            ;;
        *)
            log "Unknown backup type: $BACKUP_TYPE"
            exit 1
            ;;
    esac
    
    upload_backup
    cleanup_old_backups
    
    # Cleanup local files
    rm -rf "$BACKUP_DIR" "/tmp/$(basename $BACKUP_DIR).tar.gz"
    
    log "Backup process completed successfully"
}

# Run main function
main "$@"
`

	return config
}

// reconcileBackupCleanup handles cleanup of old backups
func (r *BackupReconciler) reconcileBackupCleanup(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := r.Logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)

	// Get list of backups
	backups, err := r.BackupManager.ListBackups(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to list backups: %w", err)
	}

	// Apply retention policy
	if err := r.applyRetentionPolicy(ctx, instance, backups); err != nil {
		return fmt.Errorf("failed to apply retention policy: %w", err)
	}

	logger.Info("Backup cleanup completed", "totalBackups", len(backups))
	return nil
}

// applyRetentionPolicy removes backups that exceed the retention policy
func (r *BackupReconciler) applyRetentionPolicy(ctx context.Context, instance *n8nv1alpha1.N8nInstance, backups []*managers.BackupInfo) error {
	if instance.Spec.Backup.Retention == nil {
		return nil // No retention policy defined
	}

	retention := instance.Spec.Backup.Retention
	now := time.Now()

	for _, backup := range backups {
		shouldDelete := false
		age := now.Sub(backup.CreatedAt)

		// Check retention based on backup age
		switch {
		case age > time.Duration(retention.Yearly)*365*24*time.Hour:
			shouldDelete = true
		case age > time.Duration(retention.Monthly)*30*24*time.Hour && retention.Monthly > 0:
			// Keep if it's a monthly backup and within monthly retention
			if backup.CreatedAt.Day() != 1 {
				shouldDelete = true
			}
		case age > time.Duration(retention.Weekly)*7*24*time.Hour && retention.Weekly > 0:
			// Keep if it's a weekly backup and within weekly retention
			if backup.CreatedAt.Weekday() != time.Sunday {
				shouldDelete = true
			}
		case age > time.Duration(retention.Daily)*24*time.Hour && retention.Daily > 0:
			shouldDelete = true
		}

		if shouldDelete {
			if err := r.BackupManager.DeleteBackup(ctx, backup.BackupID); err != nil {
				r.Logger.Error(err, "Failed to delete expired backup", "backupId", backup.BackupID)
				continue
			}
			r.Logger.Info("Deleted expired backup", "backupId", backup.BackupID, "age", age)
		}
	}

	return nil
}

// reconcileBackupValidation handles validation of existing backups
func (r *BackupReconciler) reconcileBackupValidation(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := r.Logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)

	// Get list of backups
	backups, err := r.BackupManager.ListBackups(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to list backups: %w", err)
	}

	// Validate recent backups
	validationCount := 0
	for _, backup := range backups {
		// Only validate backups from the last 7 days
		if time.Since(backup.CreatedAt) > 7*24*time.Hour {
			continue
		}

		result, err := r.BackupManager.ValidateBackup(ctx, backup.BackupID)
		if err != nil {
			logger.Error(err, "Failed to validate backup", "backupId", backup.BackupID)
			continue
		}

		if !result.Valid {
			logger.Error(fmt.Errorf("backup validation failed"), "Backup is invalid",
				"backupId", backup.BackupID, "error", result.ErrorMessage)
			r.recordEvent(instance, corev1.EventTypeWarning, "BackupValidationFailed",
				fmt.Sprintf("Backup %s validation failed: %s", backup.BackupID, result.ErrorMessage))
		} else {
			logger.Info("Backup validation successful", "backupId", backup.BackupID)
		}

		validationCount++
	}

	logger.Info("Backup validation completed", "validatedBackups", validationCount)
	return nil
}

// updateBackupStatus updates the backup status in the N8nInstance
func (r *BackupReconciler) updateBackupStatus(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Get recent backup information
	backups, err := r.BackupManager.ListBackups(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to list backups for status update: %w", err)
	}

	// Find the most recent successful backup
	var lastSuccessfulBackup *managers.BackupInfo
	for _, backup := range backups {
		if backup.Status == managers.BackupStatusCompleted {
			if lastSuccessfulBackup == nil || backup.CreatedAt.After(lastSuccessfulBackup.CreatedAt) {
				lastSuccessfulBackup = backup
			}
		}
	}

	// Update instance status
	instance.Status.Backup = &n8nv1alpha1.BackupStatus{
		Enabled: instance.Spec.Backup.Enabled,
	}

	if lastSuccessfulBackup != nil {
		instance.Status.Backup.LastBackup = &n8nv1alpha1.LastBackupInfo{
			BackupID:  lastSuccessfulBackup.BackupID,
			Timestamp: metav1.NewTime(lastSuccessfulBackup.CreatedAt),
			Size:      lastSuccessfulBackup.Size,
			Type:      string(lastSuccessfulBackup.Type),
		}
	}

	// Count backups by status
	statusCounts := make(map[managers.BackupStatus]int)
	for _, backup := range backups {
		statusCounts[backup.Status]++
	}

	instance.Status.Backup.TotalBackups = len(backups)
	instance.Status.Backup.SuccessfulBackups = statusCounts[managers.BackupStatusCompleted]
	instance.Status.Backup.FailedBackups = statusCounts[managers.BackupStatusFailed]

	return r.Status().Update(ctx, instance)
}

// recordEvent records an event for the N8nInstance
func (r *BackupReconciler) recordEvent(instance *n8nv1alpha1.N8nInstance, eventType, reason, message string) {
	r.Logger.Info("Recording event", "type", eventType, "reason", reason, "message", message)
	// Event recording implementation would go here
}

// SetupWithManager sets up the controller with the Manager
func (r *BackupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&n8nv1alpha1.N8nInstance{}).
		Owns(&batchv1.CronJob{}).
		Owns(&batchv1.Job{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.ServiceAccount{}).
		Watches(
			&source.Kind{Type: &batchv1.Job{}},
			handler.EnqueueRequestsFromMapFunc(r.findN8nInstanceForJob),
		).
		Complete(r)
}

// findN8nInstanceForJob finds the N8nInstance that owns a Job
func (r *BackupReconciler) findN8nInstanceForJob(obj client.Object) []reconcile.Request {
	job, ok := obj.(*batchv1.Job)
	if !ok {
		return nil
	}

	// Check if this is a backup-related job
	if !isBackupJob(job) {
		return nil
	}

	// Find the owning N8nInstance
	for _, owner := range job.GetOwnerReferences() {
		if owner.Kind == "N8nInstance" {
			return []reconcile.Request{
				{
					NamespacedName: types.NamespacedName{
						Name:      owner.Name,
						Namespace: job.GetNamespace(),
					},
				},
			}
		}
	}

	return nil
}

// isBackupJob checks if a Job is related to backup operations
func isBackupJob(job *batchv1.Job) bool {
	labels := job.GetLabels()
	if labels == nil {
		return false
	}

	component, exists := labels["app.kubernetes.io/component"]
	return exists && component == "backup"
}

// Helper functions

func getRetentionDays(retention *n8nv1alpha1.BackupRetentionSpec, period string, defaultValue int) int {
	if retention == nil {
		return defaultValue
	}

	switch period {
	case "daily":
		return retention.Daily
	case "weekly":
		return retention.Weekly
	case "monthly":
		return retention.Monthly
	case "yearly":
		return retention.Yearly
	default:
		return defaultValue
	}
}

func getBackupS3Bucket(instance *n8nv1alpha1.N8nInstance) string {
	if instance.Spec.Backup != nil && instance.Spec.Backup.S3 != nil && instance.Spec.Backup.S3.Bucket != "" {
		return instance.Spec.Backup.S3.Bucket
	}
	return fmt.Sprintf("n8n-backups-%s", instance.Namespace)
}

func getBackupS3Region(instance *n8nv1alpha1.N8nInstance) string {
	if instance.Spec.Backup != nil && instance.Spec.Backup.S3 != nil && instance.Spec.Backup.S3.Region != "" {
		return instance.Spec.Backup.S3.Region
	}
	if instance.Spec.Storage.S3 != nil && instance.Spec.Storage.S3.Region != "" {
		return instance.Spec.Storage.S3.Region
	}
	return "us-west-2" // default region
}

func getBackupEncryption(instance *n8nv1alpha1.N8nInstance) string {
	if instance.Spec.Backup != nil && instance.Spec.Backup.S3 != nil && instance.Spec.Backup.S3.Encryption != "" {
		return instance.Spec.Backup.S3.Encryption
	}
	return "AES256" // default encryption
}
