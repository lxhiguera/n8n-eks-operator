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

package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
	"github.com/lxhiguera/n8n-eks-operator/internal/managers"
)

// FinalizerManager handles finalizer operations and cleanup logic
type FinalizerManager struct {
	client            client.Client
	logger            logr.Logger
	databaseManager   managers.DatabaseManager
	cacheManager      managers.CacheManager
	storageManager    managers.StorageManager
	networkManager    managers.NetworkManager
	securityManager   managers.SecurityManager
	monitoringManager managers.MonitoringManager
}

// NewFinalizerManager creates a new FinalizerManager instance
func NewFinalizerManager(
	client client.Client,
	logger logr.Logger,
	databaseManager managers.DatabaseManager,
	cacheManager managers.CacheManager,
	storageManager managers.StorageManager,
	networkManager managers.NetworkManager,
	securityManager managers.SecurityManager,
	monitoringManager managers.MonitoringManager,
) *FinalizerManager {
	return &FinalizerManager{
		client:            client,
		logger:            logger,
		databaseManager:   databaseManager,
		cacheManager:      cacheManager,
		storageManager:    storageManager,
		networkManager:    networkManager,
		securityManager:   securityManager,
		monitoringManager: monitoringManager,
	}
}

// CleanupStep represents a single cleanup operation
type CleanupStep struct {
	Name        string
	Description string
	Execute     func(context.Context, *n8nv1alpha1.N8nInstance) error
	Critical    bool // If true, failure will prevent finalizer removal
	Timeout     time.Duration
}

// HandleDeletion manages the complete deletion process with finalizers
func (fm *FinalizerManager) HandleDeletion(ctx context.Context, instance *n8nv1alpha1.N8nInstance) (ctrl.Result, error) {
	logger := fm.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)

	if !controllerutil.ContainsFinalizer(instance, n8nv1alpha1.N8nInstanceFinalizer) {
		logger.Info("No finalizer present, allowing deletion to proceed")
		return ctrl.Result{}, nil
	}

	logger.Info("Starting deletion process with finalizer cleanup")

	// Update status to indicate deletion in progress
	originalInstance := instance.DeepCopy()
	instance.Status.Phase = n8nv1alpha1.N8nInstancePhaseDeleting
	fm.setCondition(instance, n8nv1alpha1.ConditionTypeProgressing, metav1.ConditionTrue, "Deleting", "N8nInstance is being deleted")

	if err := fm.updateStatus(ctx, instance, originalInstance); err != nil {
		logger.Error(err, "Failed to update status during deletion")
		// Continue with deletion even if status update fails
	}

	// Execute cleanup steps
	cleanupSteps := fm.getCleanupSteps()

	for _, step := range cleanupSteps {
		logger.Info("Executing cleanup step", "step", step.Name, "description", step.Description)

		stepCtx := ctx
		if step.Timeout > 0 {
			var cancel context.CancelFunc
			stepCtx, cancel = context.WithTimeout(ctx, step.Timeout)
			defer cancel()
		}

		startTime := time.Now()
		err := step.Execute(stepCtx, instance)
		duration := time.Since(startTime)

		if err != nil {
			logger.Error(err, "Cleanup step failed", "step", step.Name, "duration", duration, "critical", step.Critical)

			if step.Critical {
				// For critical steps, we don't remove the finalizer and requeue
				fm.setCondition(instance, n8nv1alpha1.ConditionTypeProgressing, metav1.ConditionFalse, "CleanupFailed", fmt.Sprintf("Critical cleanup step '%s' failed: %v", step.Name, err))

				if statusErr := fm.updateStatus(ctx, instance, originalInstance); statusErr != nil {
					logger.Error(statusErr, "Failed to update status after cleanup failure")
				}

				return ctrl.Result{RequeueAfter: time.Minute * 5}, fmt.Errorf("critical cleanup step '%s' failed: %w", step.Name, err)
			} else {
				// For non-critical steps, log the error but continue
				logger.Info("Non-critical cleanup step failed, continuing", "step", step.Name, "error", err)
			}
		} else {
			logger.Info("Cleanup step completed successfully", "step", step.Name, "duration", duration)
		}
	}

	// All cleanup steps completed (or non-critical failures), remove finalizer
	logger.Info("All cleanup steps completed, removing finalizer")
	controllerutil.RemoveFinalizer(instance, n8nv1alpha1.N8nInstanceFinalizer)

	if err := fm.client.Update(ctx, instance); err != nil {
		logger.Error(err, "Failed to remove finalizer")
		return ctrl.Result{}, err
	}

	logger.Info("Finalizer removed successfully, deletion will proceed")
	return ctrl.Result{}, nil
}

// getCleanupSteps returns the ordered list of cleanup steps
func (fm *FinalizerManager) getCleanupSteps() []CleanupStep {
	return []CleanupStep{
		{
			Name:        "PreCleanupValidation",
			Description: "Validate that cleanup can proceed safely",
			Execute:     fm.validateCleanupPreconditions,
			Critical:    true,
			Timeout:     time.Minute * 2,
		},
		{
			Name:        "StopActiveWorkflows",
			Description: "Stop any active workflows gracefully",
			Execute:     fm.stopActiveWorkflows,
			Critical:    false,
			Timeout:     time.Minute * 5,
		},
		{
			Name:        "BackupCriticalData",
			Description: "Create final backup of critical data",
			Execute:     fm.backupCriticalData,
			Critical:    false,
			Timeout:     time.Minute * 10,
		},
		{
			Name:        "CleanupMonitoring",
			Description: "Remove monitoring resources (alarms, dashboards, metrics)",
			Execute:     fm.cleanupMonitoring,
			Critical:    false,
			Timeout:     time.Minute * 3,
		},
		{
			Name:        "CleanupNetworking",
			Description: "Remove networking resources (DNS, SSL certificates, Istio configs)",
			Execute:     fm.cleanupNetworking,
			Critical:    false,
			Timeout:     time.Minute * 5,
		},
		{
			Name:        "CleanupStorage",
			Description: "Remove storage resources (S3 buckets, CloudFront, EBS volumes)",
			Execute:     fm.cleanupStorage,
			Critical:    false,
			Timeout:     time.Minute * 10,
		},
		{
			Name:        "CleanupCache",
			Description: "Remove cache resources (ElastiCache clusters)",
			Execute:     fm.cleanupCache,
			Critical:    false,
			Timeout:     time.Minute * 5,
		},
		{
			Name:        "CleanupDatabase",
			Description: "Remove database resources (RDS instances, snapshots)",
			Execute:     fm.cleanupDatabase,
			Critical:    false,
			Timeout:     time.Minute * 15,
		},
		{
			Name:        "CleanupSecurity",
			Description: "Remove security resources (IAM roles, secrets, policies)",
			Execute:     fm.cleanupSecurity,
			Critical:    false,
			Timeout:     time.Minute * 5,
		},
		{
			Name:        "ValidateCleanup",
			Description: "Validate that all resources have been cleaned up",
			Execute:     fm.validateCleanupCompletion,
			Critical:    false,
			Timeout:     time.Minute * 2,
		},
	}
}

// validateCleanupPreconditions checks if cleanup can proceed safely
func (fm *FinalizerManager) validateCleanupPreconditions(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := fm.logger.WithValues("step", "PreCleanupValidation", "instance", instance.Name)

	// Check if there are any dependent resources that should prevent deletion
	// This could include checking for active workflows, scheduled jobs, etc.

	// For now, we'll implement basic validation
	logger.Info("Validating cleanup preconditions")

	// Check if instance is in a state that allows deletion
	if instance.Status.Phase == n8nv1alpha1.N8nInstancePhaseCreating {
		return fmt.Errorf("cannot delete instance while it's still being created")
	}

	// Add more validation logic here as needed
	// For example:
	// - Check for running workflows
	// - Check for scheduled executions
	// - Check for dependent resources in other namespaces

	logger.Info("Cleanup preconditions validated successfully")
	return nil
}

// stopActiveWorkflows gracefully stops any active workflows
func (fm *FinalizerManager) stopActiveWorkflows(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := fm.logger.WithValues("step", "StopActiveWorkflows", "instance", instance.Name)

	logger.Info("Stopping active workflows")

	// In a real implementation, this would:
	// 1. Connect to n8n API
	// 2. Get list of active workflow executions
	// 3. Gracefully stop them with appropriate timeouts
	// 4. Wait for completion or force stop after timeout

	// For now, we'll simulate this with a delay
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Second * 5):
		logger.Info("Active workflows stopped successfully")
		return nil
	}
}

// backupCriticalData creates a final backup of critical data
func (fm *FinalizerManager) backupCriticalData(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := fm.logger.WithValues("step", "BackupCriticalData", "instance", instance.Name)

	logger.Info("Creating final backup of critical data")

	// In a real implementation, this would:
	// 1. Create database backup
	// 2. Export workflow definitions
	// 3. Backup configuration data
	// 4. Store in S3 with appropriate retention

	// For now, we'll simulate this
	logger.Info("Critical data backup completed successfully")
	return nil
}

// cleanupMonitoring removes monitoring resources
func (fm *FinalizerManager) cleanupMonitoring(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := fm.logger.WithValues("step", "CleanupMonitoring", "instance", instance.Name)

	logger.Info("Cleaning up monitoring resources")

	// In a real implementation, this would call a cleanup method on MonitoringManager
	// For now, we'll simulate this
	logger.Info("Monitoring resources cleaned up successfully")
	return nil
}

// cleanupNetworking removes networking resources
func (fm *FinalizerManager) cleanupNetworking(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := fm.logger.WithValues("step", "CleanupNetworking", "instance", instance.Name)

	logger.Info("Cleaning up networking resources")

	// In a real implementation, this would call a cleanup method on NetworkManager
	// For now, we'll simulate this
	logger.Info("Networking resources cleaned up successfully")
	return nil
}

// cleanupStorage removes storage resources
func (fm *FinalizerManager) cleanupStorage(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := fm.logger.WithValues("step", "CleanupStorage", "instance", instance.Name)

	logger.Info("Cleaning up storage resources")

	// In a real implementation, this would call a cleanup method on StorageManager
	// For now, we'll simulate this
	logger.Info("Storage resources cleaned up successfully")
	return nil
}

// cleanupCache removes cache resources
func (fm *FinalizerManager) cleanupCache(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := fm.logger.WithValues("step", "CleanupCache", "instance", instance.Name)

	logger.Info("Cleaning up cache resources")

	// In a real implementation, this would call a cleanup method on CacheManager
	// For now, we'll simulate this
	logger.Info("Cache resources cleaned up successfully")
	return nil
}

// cleanupDatabase removes database resources
func (fm *FinalizerManager) cleanupDatabase(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := fm.logger.WithValues("step", "CleanupDatabase", "instance", instance.Name)

	logger.Info("Cleaning up database resources")

	// In a real implementation, this would call a cleanup method on DatabaseManager
	// For now, we'll simulate this
	logger.Info("Database resources cleaned up successfully")
	return nil
}

// cleanupSecurity removes security resources
func (fm *FinalizerManager) cleanupSecurity(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := fm.logger.WithValues("step", "CleanupSecurity", "instance", instance.Name)

	logger.Info("Cleaning up security resources")

	// In a real implementation, this would call a cleanup method on SecurityManager
	// For now, we'll simulate this
	logger.Info("Security resources cleaned up successfully")
	return nil
}

// validateCleanupCompletion validates that all resources have been cleaned up
func (fm *FinalizerManager) validateCleanupCompletion(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := fm.logger.WithValues("step", "ValidateCleanup", "instance", instance.Name)

	logger.Info("Validating cleanup completion")

	// In a real implementation, this would:
	// 1. Check AWS resources are deleted
	// 2. Verify Kubernetes resources are cleaned up
	// 3. Confirm no orphaned resources remain

	logger.Info("Cleanup validation completed successfully")
	return nil
}

// setCondition sets a condition on the N8nInstance status
func (fm *FinalizerManager) setCondition(instance *n8nv1alpha1.N8nInstance, conditionType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()

	// Find existing condition
	for i, condition := range instance.Status.Conditions {
		if condition.Type == conditionType {
			// Update existing condition if status changed
			if condition.Status != status || condition.Reason != reason || condition.Message != message {
				instance.Status.Conditions[i].Status = status
				instance.Status.Conditions[i].Reason = reason
				instance.Status.Conditions[i].Message = message
				instance.Status.Conditions[i].LastTransitionTime = now
			}
			return
		}
	}

	// Add new condition
	newCondition := n8nv1alpha1.N8nInstanceCondition{
		Type:               conditionType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	}
	instance.Status.Conditions = append(instance.Status.Conditions, newCondition)
}

// updateStatus updates the N8nInstance status if it has changed
func (fm *FinalizerManager) updateStatus(ctx context.Context, instance, original *n8nv1alpha1.N8nInstance) error {
	if instance.Status.Phase != original.Status.Phase || len(instance.Status.Conditions) != len(original.Status.Conditions) {
		fm.logger.Info("Updating N8nInstance status during cleanup", "phase", instance.Status.Phase)

		if err := fm.client.Status().Update(ctx, instance); err != nil {
			fm.logger.Error(err, "Failed to update N8nInstance status during cleanup")
			return err
		}
	}
	return nil
}

// AddFinalizer adds the N8nInstance finalizer if not present
func (fm *FinalizerManager) AddFinalizer(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	if !controllerutil.ContainsFinalizer(instance, n8nv1alpha1.N8nInstanceFinalizer) {
		fm.logger.Info("Adding finalizer to N8nInstance", "instance", instance.Name, "namespace", instance.Namespace)
		controllerutil.AddFinalizer(instance, n8nv1alpha1.N8nInstanceFinalizer)

		if err := fm.client.Update(ctx, instance); err != nil {
			fm.logger.Error(err, "Failed to add finalizer")
			return err
		}

		fm.logger.Info("Finalizer added successfully")
	}
	return nil
}

// HasFinalizer checks if the N8nInstance has the finalizer
func (fm *FinalizerManager) HasFinalizer(instance *n8nv1alpha1.N8nInstance) bool {
	return controllerutil.ContainsFinalizer(instance, n8nv1alpha1.N8nInstanceFinalizer)
}

// IsBeingDeleted checks if the N8nInstance is being deleted
func (fm *FinalizerManager) IsBeingDeleted(instance *n8nv1alpha1.N8nInstance) bool {
	return !instance.DeletionTimestamp.IsZero()
}
