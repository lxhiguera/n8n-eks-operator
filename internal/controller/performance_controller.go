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

// PerformanceReconciler reconciles performance optimization for N8nInstance resources
type PerformanceReconciler struct {
	client.Client
	Scheme             *runtime.Scheme
	Logger             logr.Logger
	PerformanceManager managers.PerformanceManager
}

// +kubebuilder:rbac:groups=n8n.io,resources=n8ninstances,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=n8n.io,resources=n8ninstances/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=autoscaling,resources=horizontalpodautoscalers,verbs=get;list;watch;create;update;patch;delete

// Reconcile handles performance optimization reconciliation for N8nInstance resources
func (r *PerformanceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Logger.WithValues("performance", req.NamespacedName)
	logger.Info("Starting performance reconciliation")

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

	// Check if performance optimization is enabled
	if !r.isPerformanceOptimizationEnabled(&instance) {
		logger.Info("Performance optimization is disabled for this instance")
		return ctrl.Result{}, nil
	}

	// Handle performance reconciliation
	if err := r.reconcilePerformance(ctx, &instance); err != nil {
		logger.Error(err, "Failed to reconcile performance")
		r.recordEvent(&instance, corev1.EventTypeWarning, "PerformanceReconciliationFailed", err.Error())
		return ctrl.Result{RequeueAfter: time.Minute * 5}, err
	}

	// Handle performance monitoring
	if err := r.reconcilePerformanceMonitoring(ctx, &instance); err != nil {
		logger.Error(err, "Failed to reconcile performance monitoring")
		r.recordEvent(&instance, corev1.EventTypeWarning, "PerformanceMonitoringFailed", err.Error())
		return ctrl.Result{RequeueAfter: time.Minute * 2}, err
	}

	// Handle auto-tuning if enabled
	if r.isAutoTuningEnabled(&instance) {
		if err := r.reconcileAutoTuning(ctx, &instance); err != nil {
			logger.Error(err, "Failed to reconcile auto-tuning")
			r.recordEvent(&instance, corev1.EventTypeWarning, "AutoTuningFailed", err.Error())
			return ctrl.Result{RequeueAfter: time.Minute * 10}, err
		}
	}

	logger.Info("Performance reconciliation completed successfully")
	r.recordEvent(&instance, corev1.EventTypeNormal, "PerformanceReconciled", "Performance optimization reconciled successfully")

	// Requeue for periodic optimization
	return ctrl.Result{RequeueAfter: time.Minute * 15}, nil
}

// reconcilePerformance handles the main performance reconciliation logic
func (r *PerformanceReconciler) reconcilePerformance(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := r.Logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)

	// Reconcile performance optimizations
	if err := r.PerformanceManager.ReconcilePerformance(ctx, instance); err != nil {
		return fmt.Errorf("failed to reconcile performance optimizations: %w", err)
	}

	// Create performance configuration ConfigMap
	if err := r.reconcilePerformanceConfigMap(ctx, instance); err != nil {
		return fmt.Errorf("failed to reconcile performance config map: %w", err)
	}

	// Update instance status with performance information
	if err := r.updatePerformanceStatus(ctx, instance); err != nil {
		return fmt.Errorf("failed to update performance status: %w", err)
	}

	logger.Info("Performance reconciliation completed")
	return nil
}

// reconcilePerformanceConfigMap creates or updates the performance configuration
func (r *PerformanceReconciler) reconcilePerformanceConfigMap(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	configData := r.generatePerformanceConfig(instance)

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-performance-config", instance.Name),
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n-performance",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"app.kubernetes.io/component":  "performance",
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
			return fmt.Errorf("failed to create performance config map: %w", err)
		}
		// Update existing config map
		existing := &corev1.ConfigMap{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(configMap), existing); err != nil {
			return fmt.Errorf("failed to get existing config map: %w", err)
		}
		existing.Data = configMap.Data
		existing.Labels = configMap.Labels
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update performance config map: %w", err)
		}
	}

	return nil
}

// generatePerformanceConfig generates the performance configuration data
func (r *PerformanceReconciler) generatePerformanceConfig(instance *n8nv1alpha1.N8nInstance) map[string]string {
	config := map[string]string{
		"performance.yaml": fmt.Sprintf(`
performance:
  optimization:
    enabled: %t
    mode: "%s"
    aggressiveness: "%s"
    autoTuning: %t
  
  monitoring:
    enabled: %t
    interval: "%s"
    retention: "%s"
    
    metrics:
      cpu:
        enabled: true
        thresholds:
          warning: 70
          critical: 85
      memory:
        enabled: true
        thresholds:
          warning: 75
          critical: 90
      network:
        enabled: true
        thresholds:
          latency_warning: 100
          latency_critical: 500
      storage:
        enabled: true
        thresholds:
          utilization_warning: 80
          utilization_critical: 95
      database:
        enabled: true
        thresholds:
          connection_warning: 80
          connection_critical: 95
          query_latency_warning: 500
          query_latency_critical: 2000
      cache:
        enabled: true
        thresholds:
          hit_rate_warning: 80
          hit_rate_critical: 60
  
  tuning:
    resources:
      cpu:
        autoScale: %t
        minCores: %s
        maxCores: %s
        targetUtilization: %d
      memory:
        autoScale: %t
        minMemory: "%s"
        maxMemory: "%s"
        targetUtilization: %d
    
    database:
      connectionPool:
        autoTune: %t
        minConnections: %d
        maxConnections: %d
        targetUtilization: %d
      queryOptimization:
        enabled: %t
        slowQueryThreshold: "%s"
    
    cache:
      autoTune: %t
      ttlOptimization: %t
      memoryManagement: %t
      evictionPolicy: "%s"
  
  alerts:
    enabled: %t
    channels:
      webhook:
        enabled: %t
        url: "%s"
      slack:
        enabled: %t
        channel: "%s"
`,
			r.getOptimizationEnabled(instance),
			r.getOptimizationMode(instance),
			r.getAggressivenessLevel(instance),
			r.isAutoTuningEnabled(instance),
			r.getMonitoringEnabled(instance),
			r.getMonitoringInterval(instance),
			r.getMonitoringRetention(instance),
			r.getCPUAutoScale(instance),
			r.getMinCPU(instance),
			r.getMaxCPU(instance),
			r.getCPUTargetUtilization(instance),
			r.getMemoryAutoScale(instance),
			r.getMinMemory(instance),
			r.getMaxMemory(instance),
			r.getMemoryTargetUtilization(instance),
			r.getDatabaseAutoTune(instance),
			r.getMinConnections(instance),
			r.getMaxConnections(instance),
			r.getConnectionTargetUtilization(instance),
			r.getQueryOptimizationEnabled(instance),
			r.getSlowQueryThreshold(instance),
			r.getCacheAutoTune(instance),
			r.getTTLOptimization(instance),
			r.getMemoryManagement(instance),
			r.getEvictionPolicy(instance),
			r.getAlertsEnabled(instance),
			r.getWebhookEnabled(instance),
			r.getWebhookURL(instance),
			r.getSlackEnabled(instance),
			r.getSlackChannel(instance),
		),
	}

	// Add performance tuning script
	config["tune-performance.sh"] = `#!/bin/bash
set -euo pipefail

# Performance tuning script for n8n instances
INSTANCE_NAME="${INSTANCE_NAME:-}"
INSTANCE_NAMESPACE="${INSTANCE_NAMESPACE:-default}"
OPTIMIZATION_TYPE="${OPTIMIZATION_TYPE:-auto}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

# Get current resource usage
get_resource_usage() {
    log "Getting current resource usage..."
    
    # CPU usage
    CPU_USAGE=$(kubectl top pods -n "$INSTANCE_NAMESPACE" -l "app.kubernetes.io/instance=$INSTANCE_NAME" \
        --no-headers | awk '{sum+=$2} END {print sum}' | sed 's/m//')
    
    # Memory usage
    MEMORY_USAGE=$(kubectl top pods -n "$INSTANCE_NAMESPACE" -l "app.kubernetes.io/instance=$INSTANCE_NAME" \
        --no-headers | awk '{sum+=$3} END {print sum}' | sed 's/Mi//')
    
    log "Current CPU usage: ${CPU_USAGE}m"
    log "Current memory usage: ${MEMORY_USAGE}Mi"
}

# Optimize CPU resources
optimize_cpu() {
    log "Optimizing CPU resources..."
    
    if [[ $CPU_USAGE -gt 800 ]]; then
        log "High CPU usage detected, scaling up..."
        kubectl patch n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" \
            --type='merge' \
            -p='{"spec":{"components":{"main":{"resources":{"requests":{"cpu":"500m"},"limits":{"cpu":"2000m"}}}}}}'
    elif [[ $CPU_USAGE -lt 200 ]]; then
        log "Low CPU usage detected, scaling down..."
        kubectl patch n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" \
            --type='merge' \
            -p='{"spec":{"components":{"main":{"resources":{"requests":{"cpu":"200m"},"limits":{"cpu":"1000m"}}}}}}'
    fi
}

# Optimize memory resources
optimize_memory() {
    log "Optimizing memory resources..."
    
    if [[ $MEMORY_USAGE -gt 1500 ]]; then
        log "High memory usage detected, scaling up..."
        kubectl patch n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" \
            --type='merge' \
            -p='{"spec":{"components":{"main":{"resources":{"requests":{"memory":"1Gi"},"limits":{"memory":"4Gi"}}}}}}'
    elif [[ $MEMORY_USAGE -lt 500 ]]; then
        log "Low memory usage detected, scaling down..."
        kubectl patch n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" \
            --type='merge' \
            -p='{"spec":{"components":{"main":{"resources":{"requests":{"memory":"512Mi"},"limits":{"memory":"2Gi"}}}}}}'
    fi
}

# Optimize database connections
optimize_database() {
    log "Optimizing database connections..."
    
    # Get current connection count
    DB_CONNECTIONS=$(kubectl exec -n "$INSTANCE_NAMESPACE" \
        deployment/"$INSTANCE_NAME"-main -- \
        psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
        -t -c "SELECT count(*) FROM pg_stat_activity;" 2>/dev/null || echo "0")
    
    log "Current database connections: $DB_CONNECTIONS"
    
    if [[ $DB_CONNECTIONS -gt 80 ]]; then
        log "High database connection usage, optimizing pool..."
        # Implementation for database optimization
    fi
}

# Main optimization function
main() {
    log "Starting performance optimization for $INSTANCE_NAME"
    
    get_resource_usage
    
    case "$OPTIMIZATION_TYPE" in
        "cpu")
            optimize_cpu
            ;;
        "memory")
            optimize_memory
            ;;
        "database")
            optimize_database
            ;;
        "auto")
            optimize_cpu
            optimize_memory
            optimize_database
            ;;
        *)
            log "Unknown optimization type: $OPTIMIZATION_TYPE"
            exit 1
            ;;
    esac
    
    log "Performance optimization completed"
}

# Run main function
main "$@"
`

	return config
}

// reconcilePerformanceMonitoring handles performance monitoring setup
func (r *PerformanceReconciler) reconcilePerformanceMonitoring(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := r.Logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)

	// Get current performance metrics
	metrics, err := r.PerformanceManager.GetPerformanceMetrics(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to get performance metrics: %w", err)
	}

	// Analyze performance and generate alerts if needed
	analysis, err := r.PerformanceManager.AnalyzePerformance(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to analyze performance: %w", err)
	}

	// Check for performance issues and create alerts
	if err := r.checkPerformanceAlerts(ctx, instance, metrics, analysis); err != nil {
		logger.Error(err, "Failed to check performance alerts")
	}

	logger.Info("Performance monitoring reconciliation completed")
	return nil
}

// reconcileAutoTuning handles auto-tuning operations
func (r *PerformanceReconciler) reconcileAutoTuning(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := r.Logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)

	// Check if it's time for auto-tuning
	if !r.shouldPerformAutoTuning(instance) {
		logger.Info("Auto-tuning not scheduled at this time")
		return nil
	}

	// Perform resource optimization
	result, err := r.PerformanceManager.OptimizeResources(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to optimize resources: %w", err)
	}

	// Perform configuration tuning
	if err := r.PerformanceManager.TuneConfiguration(ctx, instance); err != nil {
		return fmt.Errorf("failed to tune configuration: %w", err)
	}

	logger.Info("Auto-tuning completed", "optimizations", result.AppliedCount)
	r.recordEvent(instance, corev1.EventTypeNormal, "AutoTuningCompleted",
		fmt.Sprintf("Auto-tuning completed with %d optimizations applied", result.AppliedCount))

	return nil
}

// updatePerformanceStatus updates the performance status in the N8nInstance
func (r *PerformanceReconciler) updatePerformanceStatus(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Get current performance metrics
	metrics, err := r.PerformanceManager.GetPerformanceMetrics(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to get performance metrics for status update: %w", err)
	}

	// Get performance analysis
	analysis, err := r.PerformanceManager.AnalyzePerformance(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to get performance analysis for status update: %w", err)
	}

	// Update instance status
	instance.Status.Performance = &n8nv1alpha1.PerformanceStatus{
		Enabled:           r.isPerformanceOptimizationEnabled(instance),
		OverallScore:      analysis.OverallScore,
		LastOptimized:     metav1.NewTime(time.Now()),
		OptimizationCount: len(analysis.Recommendations),
	}

	// Add component scores
	for component, score := range analysis.ComponentScores {
		componentStatus := n8nv1alpha1.ComponentPerformanceStatus{
			Component: component,
			Score:     score,
			Status:    r.getComponentStatus(score),
		}
		instance.Status.Performance.ComponentScores = append(instance.Status.Performance.ComponentScores, componentStatus)
	}

	return r.Status().Update(ctx, instance)
}

// checkPerformanceAlerts checks for performance issues and creates alerts
func (r *PerformanceReconciler) checkPerformanceAlerts(ctx context.Context, instance *n8nv1alpha1.N8nInstance, metrics *managers.PerformanceMetrics, analysis *managers.PerformanceAnalysis) error {
	// Check CPU alerts
	if metrics.CPU != nil && metrics.CPU.Utilization > 85 {
		r.recordEvent(instance, corev1.EventTypeWarning, "HighCPUUsage",
			fmt.Sprintf("CPU utilization is high: %.1f%%", metrics.CPU.Utilization))
	}

	// Check memory alerts
	if metrics.Memory != nil && metrics.Memory.Utilization > 90 {
		r.recordEvent(instance, corev1.EventTypeWarning, "HighMemoryUsage",
			fmt.Sprintf("Memory utilization is high: %.1f%%", metrics.Memory.Utilization))
	}

	// Check database alerts
	if metrics.Database != nil && metrics.Database.QueryLatency > 2000 {
		r.recordEvent(instance, corev1.EventTypeWarning, "HighDatabaseLatency",
			fmt.Sprintf("Database query latency is high: %.1fms", metrics.Database.QueryLatency))
	}

	// Check overall performance score
	if analysis.OverallScore < 50 {
		r.recordEvent(instance, corev1.EventTypeWarning, "LowPerformanceScore",
			fmt.Sprintf("Overall performance score is low: %.1f", analysis.OverallScore))
	}

	return nil
}

// Helper methods

func (r *PerformanceReconciler) isPerformanceOptimizationEnabled(instance *n8nv1alpha1.N8nInstance) bool {
	if instance.Spec.Performance != nil {
		return instance.Spec.Performance.Enabled
	}
	return true // Default to enabled
}

func (r *PerformanceReconciler) isAutoTuningEnabled(instance *n8nv1alpha1.N8nInstance) bool {
	if instance.Spec.Performance != nil && instance.Spec.Performance.AutoTuning != nil {
		return instance.Spec.Performance.AutoTuning.Enabled
	}
	return false // Default to disabled
}

func (r *PerformanceReconciler) shouldPerformAutoTuning(instance *n8nv1alpha1.N8nInstance) bool {
	// Check if enough time has passed since last optimization
	if instance.Status.Performance != nil && !instance.Status.Performance.LastOptimized.IsZero() {
		timeSinceLastOptimization := time.Since(instance.Status.Performance.LastOptimized.Time)
		if timeSinceLastOptimization < 30*time.Minute {
			return false
		}
	}
	return true
}

func (r *PerformanceReconciler) getComponentStatus(score float64) string {
	if score >= 80 {
		return "excellent"
	} else if score >= 60 {
		return "good"
	} else if score >= 40 {
		return "fair"
	} else {
		return "poor"
	}
}

func (r *PerformanceReconciler) recordEvent(instance *n8nv1alpha1.N8nInstance, eventType, reason, message string) {
	r.Logger.Info("Recording event", "type", eventType, "reason", reason, "message", message)
	// Event recording implementation would go here
}

// SetupWithManager sets up the controller with the Manager
func (r *PerformanceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&n8nv1alpha1.N8nInstance{}).
		Owns(&corev1.ConfigMap{}).
		Complete(r)
}

// Configuration helper methods
func (r *PerformanceReconciler) getOptimizationEnabled(instance *n8nv1alpha1.N8nInstance) bool {
	return r.isPerformanceOptimizationEnabled(instance)
}

func (r *PerformanceReconciler) getOptimizationMode(instance *n8nv1alpha1.N8nInstance) string {
	if instance.Spec.Performance != nil && instance.Spec.Performance.AutoTuning != nil && instance.Spec.Performance.AutoTuning.Mode != "" {
		return instance.Spec.Performance.AutoTuning.Mode
	}
	return "balanced"
}

func (r *PerformanceReconciler) getAggressivenessLevel(instance *n8nv1alpha1.N8nInstance) string {
	if instance.Spec.Performance != nil && instance.Spec.Performance.AutoTuning != nil && instance.Spec.Performance.AutoTuning.Aggressiveness != "" {
		return instance.Spec.Performance.AutoTuning.Aggressiveness
	}
	return "medium"
}

func (r *PerformanceReconciler) getMonitoringEnabled(instance *n8nv1alpha1.N8nInstance) bool {
	return true // Default enabled
}

func (r *PerformanceReconciler) getMonitoringInterval(instance *n8nv1alpha1.N8nInstance) string {
	return "30s"
}

func (r *PerformanceReconciler) getMonitoringRetention(instance *n8nv1alpha1.N8nInstance) string {
	return "7d"
}

func (r *PerformanceReconciler) getCPUAutoScale(instance *n8nv1alpha1.N8nInstance) bool {
	return true
}

func (r *PerformanceReconciler) getMinCPU(instance *n8nv1alpha1.N8nInstance) string {
	return "100m"
}

func (r *PerformanceReconciler) getMaxCPU(instance *n8nv1alpha1.N8nInstance) string {
	return "2000m"
}

func (r *PerformanceReconciler) getCPUTargetUtilization(instance *n8nv1alpha1.N8nInstance) int {
	return 70
}

func (r *PerformanceReconciler) getMemoryAutoScale(instance *n8nv1alpha1.N8nInstance) bool {
	return true
}

func (r *PerformanceReconciler) getMinMemory(instance *n8nv1alpha1.N8nInstance) string {
	return "256Mi"
}

func (r *PerformanceReconciler) getMaxMemory(instance *n8nv1alpha1.N8nInstance) string {
	return "4Gi"
}

func (r *PerformanceReconciler) getMemoryTargetUtilization(instance *n8nv1alpha1.N8nInstance) int {
	return 75
}

func (r *PerformanceReconciler) getDatabaseAutoTune(instance *n8nv1alpha1.N8nInstance) bool {
	return true
}

func (r *PerformanceReconciler) getMinConnections(instance *n8nv1alpha1.N8nInstance) int {
	return 5
}

func (r *PerformanceReconciler) getMaxConnections(instance *n8nv1alpha1.N8nInstance) int {
	return 50
}

func (r *PerformanceReconciler) getConnectionTargetUtilization(instance *n8nv1alpha1.N8nInstance) int {
	return 80
}

func (r *PerformanceReconciler) getQueryOptimizationEnabled(instance *n8nv1alpha1.N8nInstance) bool {
	return true
}

func (r *PerformanceReconciler) getSlowQueryThreshold(instance *n8nv1alpha1.N8nInstance) string {
	return "1s"
}

func (r *PerformanceReconciler) getCacheAutoTune(instance *n8nv1alpha1.N8nInstance) bool {
	return true
}

func (r *PerformanceReconciler) getTTLOptimization(instance *n8nv1alpha1.N8nInstance) bool {
	return true
}

func (r *PerformanceReconciler) getMemoryManagement(instance *n8nv1alpha1.N8nInstance) bool {
	return true
}

func (r *PerformanceReconciler) getEvictionPolicy(instance *n8nv1alpha1.N8nInstance) string {
	return "allkeys-lru"
}

func (r *PerformanceReconciler) getAlertsEnabled(instance *n8nv1alpha1.N8nInstance) bool {
	return true
}

func (r *PerformanceReconciler) getWebhookEnabled(instance *n8nv1alpha1.N8nInstance) bool {
	return false
}

func (r *PerformanceReconciler) getWebhookURL(instance *n8nv1alpha1.N8nInstance) string {
	return ""
}

func (r *PerformanceReconciler) getSlackEnabled(instance *n8nv1alpha1.N8nInstance) bool {
	return false
}

func (r *PerformanceReconciler) getSlackChannel(instance *n8nv1alpha1.N8nInstance) string {
	return ""
}
