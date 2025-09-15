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
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/log"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// StructuredLogger provides structured logging utilities for the controller
type StructuredLogger struct {
	logger logr.Logger
}

// NewStructuredLogger creates a new structured logger
func NewStructuredLogger(ctx context.Context) *StructuredLogger {
	return &StructuredLogger{
		logger: log.FromContext(ctx),
	}
}

// LogReconciliationStart logs the start of a reconciliation cycle
func (sl *StructuredLogger) LogReconciliationStart(instance *n8nv1alpha1.N8nInstance, generation int64) {
	sl.logger.Info("Starting reconciliation cycle",
		"instance", instance.Name,
		"namespace", instance.Namespace,
		"generation", generation,
		"observedGeneration", instance.Status.ObservedGeneration,
		"phase", instance.Status.Phase,
		"resourceVersion", instance.ResourceVersion,
	)
}

// LogReconciliationEnd logs the end of a reconciliation cycle
func (sl *StructuredLogger) LogReconciliationEnd(instance *n8nv1alpha1.N8nInstance, duration time.Duration, result string) {
	sl.logger.Info("Reconciliation cycle completed",
		"instance", instance.Name,
		"namespace", instance.Namespace,
		"duration", duration,
		"result", result,
		"finalPhase", instance.Status.Phase,
		"conditionsCount", len(instance.Status.Conditions),
	)
}

// LogComponentReconciliation logs component reconciliation details
func (sl *StructuredLogger) LogComponentReconciliation(component string, instance *n8nv1alpha1.N8nInstance, duration time.Duration, success bool, err error) {
	logEntry := sl.logger.WithValues(
		"component", component,
		"instance", instance.Name,
		"namespace", instance.Namespace,
		"duration", duration,
		"success", success,
	)

	if success {
		logEntry.Info("Component reconciliation successful")
	} else {
		logEntry.Error(err, "Component reconciliation failed")
	}
}

// LogPhaseTransition logs phase transitions with context
func (sl *StructuredLogger) LogPhaseTransition(instance *n8nv1alpha1.N8nInstance, fromPhase, toPhase n8nv1alpha1.N8nInstancePhase, reason string) {
	sl.logger.Info("Phase transition",
		"instance", instance.Name,
		"namespace", instance.Namespace,
		"fromPhase", fromPhase,
		"toPhase", toPhase,
		"reason", reason,
		"generation", instance.Generation,
	)
}

// LogConditionUpdate logs condition updates
func (sl *StructuredLogger) LogConditionUpdate(instance *n8nv1alpha1.N8nInstance, conditionType string, status string, reason string) {
	sl.logger.Info("Condition updated",
		"instance", instance.Name,
		"namespace", instance.Namespace,
		"conditionType", conditionType,
		"status", status,
		"reason", reason,
	)
}

// LogResourceOperation logs Kubernetes resource operations
func (sl *StructuredLogger) LogResourceOperation(operation string, resourceType string, resourceName string, namespace string, success bool, err error) {
	logEntry := sl.logger.WithValues(
		"operation", operation,
		"resourceType", resourceType,
		"resourceName", resourceName,
		"namespace", namespace,
		"success", success,
	)

	if success {
		logEntry.Info("Resource operation successful")
	} else {
		logEntry.Error(err, "Resource operation failed")
	}
}

// LogAWSOperation logs AWS service operations
func (sl *StructuredLogger) LogAWSOperation(service string, operation string, resourceId string, success bool, duration time.Duration, err error) {
	logEntry := sl.logger.WithValues(
		"awsService", service,
		"operation", operation,
		"resourceId", resourceId,
		"success", success,
		"duration", duration,
	)

	if success {
		logEntry.Info("AWS operation successful")
	} else {
		logEntry.Error(err, "AWS operation failed")
	}
}

// LogCircuitBreakerEvent logs circuit breaker state changes
func (sl *StructuredLogger) LogCircuitBreakerEvent(serviceName string, event string, state CircuitBreakerState, failureCount int) {
	sl.logger.Info("Circuit breaker event",
		"serviceName", serviceName,
		"event", event,
		"state", state,
		"failureCount", failureCount,
	)
}

// LogRetryAttempt logs retry attempts with backoff information
func (sl *StructuredLogger) LogRetryAttempt(component string, attempt int, maxRetries int, retryAfter time.Duration, errorType ErrorType) {
	sl.logger.Info("Scheduling retry attempt",
		"component", component,
		"attempt", attempt,
		"maxRetries", maxRetries,
		"retryAfter", retryAfter,
		"errorType", errorType,
	)
}

// LogHealthCheck logs health check results
func (sl *StructuredLogger) LogHealthCheck(component string, instance *n8nv1alpha1.N8nInstance, healthy bool, details string) {
	logEntry := sl.logger.WithValues(
		"component", component,
		"instance", instance.Name,
		"namespace", instance.Namespace,
		"healthy", healthy,
		"details", details,
	)

	if healthy {
		logEntry.Info("Health check passed")
	} else {
		logEntry.Info("Health check failed")
	}
}

// LogEndpointUpdate logs endpoint discovery and updates
func (sl *StructuredLogger) LogEndpointUpdate(instance *n8nv1alpha1.N8nInstance, endpointType string, endpoint string, success bool) {
	sl.logger.Info("Endpoint update",
		"instance", instance.Name,
		"namespace", instance.Namespace,
		"endpointType", endpointType,
		"endpoint", endpoint,
		"success", success,
	)
}

// LogCleanupOperation logs cleanup operations during deletion
func (sl *StructuredLogger) LogCleanupOperation(instance *n8nv1alpha1.N8nInstance, cleanupType string, success bool, duration time.Duration, err error) {
	logEntry := sl.logger.WithValues(
		"instance", instance.Name,
		"namespace", instance.Namespace,
		"cleanupType", cleanupType,
		"success", success,
		"duration", duration,
	)

	if success {
		logEntry.Info("Cleanup operation successful")
	} else {
		logEntry.Error(err, "Cleanup operation failed")
	}
}

// LogMetricsPublication logs metrics publication to monitoring systems
func (sl *StructuredLogger) LogMetricsPublication(system string, metricsCount int, success bool, err error) {
	logEntry := sl.logger.WithValues(
		"system", system,
		"metricsCount", metricsCount,
		"success", success,
	)

	if success {
		logEntry.Info("Metrics published successfully")
	} else {
		logEntry.Error(err, "Failed to publish metrics")
	}
}

// LogConfigurationValidation logs configuration validation results
func (sl *StructuredLogger) LogConfigurationValidation(instance *n8nv1alpha1.N8nInstance, component string, valid bool, issues []string) {
	logEntry := sl.logger.WithValues(
		"instance", instance.Name,
		"namespace", instance.Namespace,
		"component", component,
		"valid", valid,
		"issuesCount", len(issues),
	)

	if valid {
		logEntry.Info("Configuration validation passed")
	} else {
		logEntry.Info("Configuration validation failed", "issues", issues)
	}
}
