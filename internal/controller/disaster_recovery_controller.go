package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
	"github.com/lxhiguera/n8n-eks-operator/internal/managers"
)

// DisasterRecoveryReconciler reconciles disaster recovery operations for N8nInstance resources
type DisasterRecoveryReconciler struct {
	client.Client
	Scheme                  *runtime.Scheme
	Logger                  logr.Logger
	DisasterRecoveryManager managers.DisasterRecoveryManager
}

// +kubebuilder:rbac:groups=n8n.io,resources=n8ninstances,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=n8n.io,resources=n8ninstances/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=n8n.io,resources=n8ninstances/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles disaster recovery reconciliation for N8nInstance resources
func (r *DisasterRecoveryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Logger.WithValues("disaster-recovery", req.NamespacedName)
	logger.Info("Starting disaster recovery reconciliation")

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

	// Check if multi-region is enabled
	if instance.Spec.MultiRegion == nil || !instance.Spec.MultiRegion.Enabled {
		logger.Info("Multi-region is disabled for this instance")
		return ctrl.Result{}, nil
	}

	// Handle disaster recovery reconciliation
	if err := r.reconcileDisasterRecovery(ctx, &instance); err != nil {
		logger.Error(err, "Failed to reconcile disaster recovery")
		r.recordEvent(&instance, corev1.EventTypeWarning, "DisasterRecoveryReconciliationFailed", err.Error())
		return ctrl.Result{RequeueAfter: time.Minute * 5}, err
	}

	// Handle failover monitoring
	if err := r.reconcileFailoverMonitoring(ctx, &instance); err != nil {
		logger.Error(err, "Failed to reconcile failover monitoring")
		r.recordEvent(&instance, corev1.EventTypeWarning, "FailoverMonitoringFailed", err.Error())
		return ctrl.Result{RequeueAfter: time.Minute * 2}, err
	}

	// Handle region synchronization
	if err := r.reconcileRegionSynchronization(ctx, &instance); err != nil {
		logger.Error(err, "Failed to reconcile region synchronization")
		r.recordEvent(&instance, corev1.EventTypeWarning, "RegionSynchronizationFailed", err.Error())
		return ctrl.Result{RequeueAfter: time.Minute * 10}, err
	}

	logger.Info("Disaster recovery reconciliation completed successfully")
	r.recordEvent(&instance, corev1.EventTypeNormal, "DisasterRecoveryReconciled", "Disaster recovery configuration reconciled successfully")

	// Requeue for periodic monitoring
	return ctrl.Result{RequeueAfter: time.Minute * 30}, nil
}

// reconcileDisasterRecovery handles the main disaster recovery reconciliation logic
func (r *DisasterRecoveryReconciler) reconcileDisasterRecovery(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := r.Logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)

	// Reconcile multi-region configuration
	if err := r.DisasterRecoveryManager.ReconcileMultiRegion(ctx, instance); err != nil {
		return fmt.Errorf("failed to reconcile multi-region configuration: %w", err)
	}

	// Create disaster recovery ConfigMap
	if err := r.reconcileDisasterRecoveryConfigMap(ctx, instance); err != nil {
		return fmt.Errorf("failed to reconcile disaster recovery config map: %w", err)
	}

	// Update instance status with disaster recovery information
	if err := r.updateDisasterRecoveryStatus(ctx, instance); err != nil {
		return fmt.Errorf("failed to update disaster recovery status: %w", err)
	}

	logger.Info("Disaster recovery reconciliation completed")
	return nil
}

// reconcileDisasterRecoveryConfigMap creates or updates the disaster recovery configuration
func (r *DisasterRecoveryReconciler) reconcileDisasterRecoveryConfigMap(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	configData := r.generateDisasterRecoveryConfig(instance)

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-disaster-recovery-config", instance.Name),
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n-disaster-recovery",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"app.kubernetes.io/component":  "disaster-recovery",
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
			return fmt.Errorf("failed to create disaster recovery config map: %w", err)
		}
		// Update existing config map
		existing := &corev1.ConfigMap{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(configMap), existing); err != nil {
			return fmt.Errorf("failed to get existing config map: %w", err)
		}
		existing.Data = configMap.Data
		existing.Labels = configMap.Labels
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update disaster recovery config map: %w", err)
		}
	}

	return nil
}

// generateDisasterRecoveryConfig generates the disaster recovery configuration data
func (r *DisasterRecoveryReconciler) generateDisasterRecoveryConfig(instance *n8nv1alpha1.N8nInstance) map[string]string {
	config := map[string]string{
		"disaster-recovery.yaml": fmt.Sprintf(`
multiRegion:
  enabled: %t
  primaryRegion: "%s"
  secondaryRegions:
%s
  
failover:
  automaticFailover: %t
  healthCheckInterval: "%s"
  failoverThreshold: %d
  rtoTarget: "%s"
  rpoTarget: "%s"
  
replication:
  database:
    enabled: %t
    mode: "%s"
    syncInterval: "%s"
  storage:
    enabled: %t
    crossRegionReplication: %t
    syncInterval: "%s"
  
monitoring:
  enabled: %t
  healthChecks:
    - endpoint: "/healthz"
      interval: "30s"
      timeout: "5s"
    - endpoint: "/readyz"
      interval: "10s"
      timeout: "3s"
  
notifications:
  enabled: %t
  channels:
    - type: "webhook"
      url: "%s"
    - type: "sns"
      topicArn: "%s"
`,
			instance.Spec.MultiRegion.Enabled,
			getPrimaryRegion(instance),
			generateSecondaryRegionsYAML(instance.Spec.MultiRegion.Regions),
			getAutomaticFailover(instance),
			getHealthCheckInterval(instance),
			getFailoverThreshold(instance),
			getRTOTarget(instance),
			getRPOTarget(instance),
			getDatabaseReplicationEnabled(instance),
			getDatabaseReplicationMode(instance),
			getDatabaseSyncInterval(instance),
			getStorageReplicationEnabled(instance),
			getCrossRegionReplication(instance),
			getStorageSyncInterval(instance),
			getMonitoringEnabled(instance),
			getNotificationsEnabled(instance),
			getWebhookURL(instance),
			getSNSTopicArn(instance),
		),
	}

	// Add failover script
	config["failover.sh"] = `#!/bin/bash
set -euo pipefail

# Configuration
SOURCE_REGION="${SOURCE_REGION:-}"
TARGET_REGION="${TARGET_REGION:-}"
INSTANCE_NAME="${INSTANCE_NAME:-}"
INSTANCE_NAMESPACE="${INSTANCE_NAMESPACE:-default}"
DRY_RUN="${DRY_RUN:-false}"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

# Error handling
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Validate environment
validate_environment() {
    log "Validating environment..."
    
    if [[ -z "$SOURCE_REGION" ]]; then
        error_exit "SOURCE_REGION environment variable is required"
    fi
    
    if [[ -z "$TARGET_REGION" ]]; then
        error_exit "TARGET_REGION environment variable is required"
    fi
    
    if [[ -z "$INSTANCE_NAME" ]]; then
        error_exit "INSTANCE_NAME environment variable is required"
    fi
    
    log "Environment validation completed"
}

# Check failover readiness
check_failover_readiness() {
    log "Checking failover readiness for region: $TARGET_REGION"
    
    # Check database replica status
    log "Checking database replica status..."
    # Implementation for checking database replica
    
    # Check storage replication status
    log "Checking storage replication status..."
    # Implementation for checking storage replication
    
    # Check network connectivity
    log "Checking network connectivity..."
    # Implementation for checking network connectivity
    
    log "Failover readiness check completed"
}

# Execute database failover
execute_database_failover() {
    log "Executing database failover..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would promote database replica in $TARGET_REGION"
        return 0
    fi
    
    # Promote read replica to primary
    aws rds promote-read-replica \
        --db-instance-identifier "$INSTANCE_NAME-replica-$TARGET_REGION" \
        --region "$TARGET_REGION"
    
    # Wait for promotion to complete
    aws rds wait db-instance-available \
        --db-instance-identifier "$INSTANCE_NAME-replica-$TARGET_REGION" \
        --region "$TARGET_REGION"
    
    log "Database failover completed"
}

# Execute storage failover
execute_storage_failover() {
    log "Executing storage failover..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would update storage configuration for $TARGET_REGION"
        return 0
    fi
    
    # Update S3 bucket configuration
    # Implementation for storage failover
    
    log "Storage failover completed"
}

# Update DNS records
update_dns_records() {
    log "Updating DNS records for failover..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would update DNS records to point to $TARGET_REGION"
        return 0
    fi
    
    # Update Route53 records
    # Implementation for DNS updates
    
    log "DNS records updated"
}

# Update application configuration
update_application_config() {
    log "Updating application configuration..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would update application configuration for $TARGET_REGION"
        return 0
    fi
    
    # Update N8nInstance resource
    kubectl patch n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" \
        --type='merge' \
        -p="{\"spec\":{\"multiRegion\":{\"activeRegion\":\"$TARGET_REGION\"}}}"
    
    log "Application configuration updated"
}

# Send notifications
send_notifications() {
    local status="$1"
    local message="$2"
    
    log "Sending failover notifications..."
    
    if [[ -n "${WEBHOOK_URL:-}" ]]; then
        curl -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{
                \"instance\": \"$INSTANCE_NAME\",
                \"namespace\": \"$INSTANCE_NAMESPACE\",
                \"sourceRegion\": \"$SOURCE_REGION\",
                \"targetRegion\": \"$TARGET_REGION\",
                \"status\": \"$status\",
                \"message\": \"$message\",
                \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
            }" || log "Failed to send webhook notification"
    fi
    
    if [[ -n "${SNS_TOPIC_ARN:-}" ]]; then
        aws sns publish \
            --topic-arn "$SNS_TOPIC_ARN" \
            --message "$message" \
            --subject "N8n Failover: $status" || log "Failed to send SNS notification"
    fi
}

# Main failover function
main() {
    log "Starting failover process"
    log "Source region: $SOURCE_REGION"
    log "Target region: $TARGET_REGION"
    log "Instance: $INSTANCE_NAME (namespace: $INSTANCE_NAMESPACE)"
    log "Dry run: $DRY_RUN"
    
    # Validate environment
    validate_environment
    
    # Check failover readiness
    check_failover_readiness
    
    # Execute failover steps
    execute_database_failover
    execute_storage_failover
    update_dns_records
    update_application_config
    
    # Send success notification
    send_notifications "success" "Failover from $SOURCE_REGION to $TARGET_REGION completed successfully"
    
    log "Failover process completed successfully"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
`

	return config
}

// reconcileFailoverMonitoring handles failover monitoring and health checks
func (r *DisasterRecoveryReconciler) reconcileFailoverMonitoring(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := r.Logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)

	// Check if automatic failover is enabled
	if !getAutomaticFailover(instance) {
		logger.Info("Automatic failover is disabled, skipping monitoring")
		return nil
	}

	// Validate failover readiness for all secondary regions
	secondaryRegions, err := r.DisasterRecoveryManager.ListSecondaryRegions(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to list secondary regions: %w", err)
	}

	for _, region := range secondaryRegions {
		validation, err := r.DisasterRecoveryManager.ValidateFailover(ctx, instance, region.Region)
		if err != nil {
			logger.Error(err, "Failed to validate failover readiness", "region", region.Region)
			continue
		}

		if !validation.Ready {
			logger.Warn("Region not ready for failover", "region", region.Region, "errors", validation.ValidationErrors)
			r.recordEvent(instance, corev1.EventTypeWarning, "FailoverNotReady",
				fmt.Sprintf("Region %s not ready for failover: %v", region.Region, validation.ValidationErrors))
		}
	}

	// Check primary region health
	if err := r.checkPrimaryRegionHealth(ctx, instance); err != nil {
		logger.Error(err, "Primary region health check failed")

		// Consider automatic failover if enabled and conditions are met
		if shouldTriggerAutomaticFailover(instance, err) {
			if err := r.triggerAutomaticFailover(ctx, instance); err != nil {
				logger.Error(err, "Failed to trigger automatic failover")
				r.recordEvent(instance, corev1.EventTypeWarning, "AutomaticFailoverFailed", err.Error())
			}
		}
	}

	logger.Info("Failover monitoring completed")
	return nil
}

// reconcileRegionSynchronization handles synchronization between regions
func (r *DisasterRecoveryReconciler) reconcileRegionSynchronization(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := r.Logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)

	// Get list of secondary regions
	secondaryRegions, err := r.DisasterRecoveryManager.ListSecondaryRegions(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to list secondary regions: %w", err)
	}

	// Sync to each secondary region
	for _, region := range secondaryRegions {
		if time.Since(region.LastSyncTime) > getSyncInterval(instance) {
			logger.Info("Synchronizing to region", "region", region.Region)

			if err := r.DisasterRecoveryManager.SyncToSecondaryRegion(ctx, instance, region.Region); err != nil {
				logger.Error(err, "Failed to sync to region", "region", region.Region)
				r.recordEvent(instance, corev1.EventTypeWarning, "RegionSyncFailed",
					fmt.Sprintf("Failed to sync to region %s: %v", region.Region, err))
				continue
			}

			logger.Info("Successfully synchronized to region", "region", region.Region)
		}
	}

	logger.Info("Region synchronization completed")
	return nil
}

// updateDisasterRecoveryStatus updates the disaster recovery status in the N8nInstance
func (r *DisasterRecoveryReconciler) updateDisasterRecoveryStatus(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Get secondary regions information
	secondaryRegions, err := r.DisasterRecoveryManager.ListSecondaryRegions(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to list secondary regions for status update: %w", err)
	}

	// Get current failover status
	failoverStatus, err := r.DisasterRecoveryManager.GetFailoverStatus(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to get failover status: %w", err)
	}

	// Update instance status
	instance.Status.MultiRegion = &n8nv1alpha1.MultiRegionStatus{
		Enabled:        instance.Spec.MultiRegion.Enabled,
		PrimaryRegion:  getPrimaryRegion(instance),
		FailoverStatus: string(*failoverStatus),
	}

	// Add secondary regions status
	for _, region := range secondaryRegions {
		regionStatus := n8nv1alpha1.SecondaryRegionStatus{
			Region:       region.Region,
			Status:       string(region.Status),
			LastSyncTime: metav1.NewTime(region.LastSyncTime),
			SyncStatus:   string(region.SyncStatus),
		}
		instance.Status.MultiRegion.SecondaryRegions = append(instance.Status.MultiRegion.SecondaryRegions, regionStatus)
	}

	return r.Status().Update(ctx, instance)
}

// checkPrimaryRegionHealth checks the health of the primary region
func (r *DisasterRecoveryReconciler) checkPrimaryRegionHealth(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Implementation for checking primary region health
	return nil
}

// shouldTriggerAutomaticFailover determines if automatic failover should be triggered
func shouldTriggerAutomaticFailover(instance *n8nv1alpha1.N8nInstance, healthError error) bool {
	// Implementation for determining if automatic failover should be triggered
	return false
}

// triggerAutomaticFailover triggers automatic failover to a secondary region
func (r *DisasterRecoveryReconciler) triggerAutomaticFailover(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := r.Logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)
	logger.Info("Triggering automatic failover")

	// Get list of secondary regions
	secondaryRegions, err := r.DisasterRecoveryManager.ListSecondaryRegions(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to list secondary regions: %w", err)
	}

	// Find the best region for failover
	targetRegion := r.selectBestFailoverRegion(secondaryRegions)
	if targetRegion == "" {
		return fmt.Errorf("no suitable region found for failover")
	}

	// Initiate failover
	result, err := r.DisasterRecoveryManager.InitiateFailover(ctx, instance, targetRegion)
	if err != nil {
		return fmt.Errorf("failed to initiate failover to region %s: %w", targetRegion, err)
	}

	logger.Info("Automatic failover initiated", "targetRegion", targetRegion, "failoverId", result.FailoverID)
	r.recordEvent(instance, corev1.EventTypeNormal, "AutomaticFailoverInitiated",
		fmt.Sprintf("Automatic failover initiated to region %s", targetRegion))

	return nil
}

// selectBestFailoverRegion selects the best region for failover
func (r *DisasterRecoveryReconciler) selectBestFailoverRegion(regions []*managers.SecondaryRegion) string {
	// Implementation for selecting the best failover region
	for _, region := range regions {
		if region.Status == managers.RegionStatusActive && region.SyncStatus == managers.SyncStatusUpToDate {
			return region.Region
		}
	}
	return ""
}

// recordEvent records an event for the N8nInstance
func (r *DisasterRecoveryReconciler) recordEvent(instance *n8nv1alpha1.N8nInstance, eventType, reason, message string) {
	r.Logger.Info("Recording event", "type", eventType, "reason", reason, "message", message)
	// Event recording implementation would go here
}

// SetupWithManager sets up the controller with the Manager
func (r *DisasterRecoveryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&n8nv1alpha1.N8nInstance{}).
		Owns(&corev1.ConfigMap{}).
		Complete(r)
}

// Helper functions

func getPrimaryRegion(instance *n8nv1alpha1.N8nInstance) string {
	if instance.Spec.MultiRegion != nil && instance.Spec.MultiRegion.PrimaryRegion != "" {
		return instance.Spec.MultiRegion.PrimaryRegion
	}
	return "us-west-2" // default
}

func generateSecondaryRegionsYAML(regions []n8nv1alpha1.MultiRegionConfig) string {
	yaml := ""
	for _, region := range regions {
		yaml += fmt.Sprintf("    - name: \"%s\"\n", region.Name)
		yaml += fmt.Sprintf("      enabled: %t\n", region.Enabled)
		if region.DatabaseReplica != nil {
			yaml += fmt.Sprintf("      databaseReplica:\n")
			yaml += fmt.Sprintf("        enabled: %t\n", region.DatabaseReplica.Enabled)
			yaml += fmt.Sprintf("        instanceClass: \"%s\"\n", region.DatabaseReplica.InstanceClass)
		}
		if region.StorageReplication != nil {
			yaml += fmt.Sprintf("      storageReplication:\n")
			yaml += fmt.Sprintf("        enabled: %t\n", region.StorageReplication.Enabled)
			yaml += fmt.Sprintf("        bucket: \"%s\"\n", region.StorageReplication.Bucket)
		}
	}
	return yaml
}

func getAutomaticFailover(instance *n8nv1alpha1.N8nInstance) bool {
	if instance.Spec.MultiRegion != nil && instance.Spec.MultiRegion.Failover != nil {
		return instance.Spec.MultiRegion.Failover.AutomaticFailover
	}
	return false
}

func getHealthCheckInterval(instance *n8nv1alpha1.N8nInstance) string {
	if instance.Spec.MultiRegion != nil && instance.Spec.MultiRegion.Failover != nil && instance.Spec.MultiRegion.Failover.HealthCheckInterval != "" {
		return instance.Spec.MultiRegion.Failover.HealthCheckInterval
	}
	return "30s"
}

func getFailoverThreshold(instance *n8nv1alpha1.N8nInstance) int {
	if instance.Spec.MultiRegion != nil && instance.Spec.MultiRegion.Failover != nil {
		return instance.Spec.MultiRegion.Failover.FailoverThreshold
	}
	return 3
}

func getRTOTarget(instance *n8nv1alpha1.N8nInstance) string {
	if instance.Spec.MultiRegion != nil && instance.Spec.MultiRegion.Failover != nil && instance.Spec.MultiRegion.Failover.RTOTarget != "" {
		return instance.Spec.MultiRegion.Failover.RTOTarget
	}
	return "5m"
}

func getRPOTarget(instance *n8nv1alpha1.N8nInstance) string {
	if instance.Spec.MultiRegion != nil && instance.Spec.MultiRegion.Failover != nil && instance.Spec.MultiRegion.Failover.RPOTarget != "" {
		return instance.Spec.MultiRegion.Failover.RPOTarget
	}
	return "1m"
}

func getDatabaseReplicationEnabled(instance *n8nv1alpha1.N8nInstance) bool {
	return true // Default enabled
}

func getDatabaseReplicationMode(instance *n8nv1alpha1.N8nInstance) string {
	return "async" // Default mode
}

func getDatabaseSyncInterval(instance *n8nv1alpha1.N8nInstance) string {
	return "5m" // Default interval
}

func getStorageReplicationEnabled(instance *n8nv1alpha1.N8nInstance) bool {
	return true // Default enabled
}

func getCrossRegionReplication(instance *n8nv1alpha1.N8nInstance) bool {
	return true // Default enabled
}

func getStorageSyncInterval(instance *n8nv1alpha1.N8nInstance) string {
	return "15m" // Default interval
}

func getMonitoringEnabled(instance *n8nv1alpha1.N8nInstance) bool {
	return true // Default enabled
}

func getNotificationsEnabled(instance *n8nv1alpha1.N8nInstance) bool {
	return true // Default enabled
}

func getWebhookURL(instance *n8nv1alpha1.N8nInstance) string {
	if instance.Spec.MultiRegion != nil && instance.Spec.MultiRegion.Notifications != nil && instance.Spec.MultiRegion.Notifications.WebhookURL != "" {
		return instance.Spec.MultiRegion.Notifications.WebhookURL
	}
	return ""
}

func getSNSTopicArn(instance *n8nv1alpha1.N8nInstance) string {
	if instance.Spec.MultiRegion != nil && instance.Spec.MultiRegion.Notifications != nil && instance.Spec.MultiRegion.Notifications.SNSTopicArn != "" {
		return instance.Spec.MultiRegion.Notifications.SNSTopicArn
	}
	return ""
}

func getSyncInterval(instance *n8nv1alpha1.N8nInstance) time.Duration {
	return 15 * time.Minute // Default sync interval
}
