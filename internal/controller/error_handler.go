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
	"math"
	"net"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// ErrorType represents different categories of errors
type ErrorType string

const (
	// ErrorTypeTransient represents temporary errors that should be retried
	ErrorTypeTransient ErrorType = "Transient"
	// ErrorTypePermanent represents permanent errors that should not be retried
	ErrorTypePermanent ErrorType = "Permanent"
	// ErrorTypeConfiguration represents configuration errors that need user intervention
	ErrorTypeConfiguration ErrorType = "Configuration"
	// ErrorTypeResource represents resource-related errors (quota, limits, etc.)
	ErrorTypeResource ErrorType = "Resource"
	// ErrorTypeNetwork represents network-related errors
	ErrorTypeNetwork ErrorType = "Network"
	// ErrorTypeAWS represents AWS service errors
	ErrorTypeAWS ErrorType = "AWS"
)

// ErrorSeverity represents the severity level of an error
type ErrorSeverity string

const (
	ErrorSeverityLow      ErrorSeverity = "Low"
	ErrorSeverityMedium   ErrorSeverity = "Medium"
	ErrorSeverityHigh     ErrorSeverity = "High"
	ErrorSeverityCritical ErrorSeverity = "Critical"
)

// ErrorInfo contains detailed information about an error
type ErrorInfo struct {
	Type        ErrorType
	Severity    ErrorSeverity
	Component   string
	Message     string
	Cause       error
	Retryable   bool
	RetryAfter  time.Duration
	MaxRetries  int
	Suggestions []string
}

// ErrorHandler handles error classification, retry logic, and circuit breaking
type ErrorHandler struct {
	logger           logr.Logger
	cloudWatchClient *cloudwatch.Client
	circuitBreakers  map[string]*CircuitBreaker
}

// CircuitBreaker implements circuit breaker pattern for external services
type CircuitBreaker struct {
	name             string
	failureCount     int
	lastFailure      time.Time
	state            CircuitBreakerState
	failureThreshold int
	timeout          time.Duration
	halfOpenMaxCalls int
	halfOpenCalls    int
}

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState string

const (
	CircuitBreakerStateClosed   CircuitBreakerState = "Closed"
	CircuitBreakerStateOpen     CircuitBreakerState = "Open"
	CircuitBreakerStateHalfOpen CircuitBreakerState = "HalfOpen"
)

// NewErrorHandler creates a new ErrorHandler instance
func NewErrorHandler(logger logr.Logger, cloudWatchClient *cloudwatch.Client) *ErrorHandler {
	return &ErrorHandler{
		logger:           logger,
		cloudWatchClient: cloudWatchClient,
		circuitBreakers:  make(map[string]*CircuitBreaker),
	}
}

// ClassifyError analyzes an error and returns detailed error information
func (eh *ErrorHandler) ClassifyError(err error, component string) *ErrorInfo {
	if err == nil {
		return nil
	}

	errorInfo := &ErrorInfo{
		Component: component,
		Cause:     err,
		Message:   err.Error(),
	}

	// Classify Kubernetes API errors
	if errors.IsNotFound(err) {
		errorInfo.Type = ErrorTypeTransient
		errorInfo.Severity = ErrorSeverityLow
		errorInfo.Retryable = true
		errorInfo.RetryAfter = time.Second * 30
		errorInfo.MaxRetries = 5
		errorInfo.Suggestions = []string{"Resource will be created on next reconciliation"}
		return errorInfo
	}

	if errors.IsConflict(err) {
		errorInfo.Type = ErrorTypeTransient
		errorInfo.Severity = ErrorSeverityMedium
		errorInfo.Retryable = true
		errorInfo.RetryAfter = time.Second * 10
		errorInfo.MaxRetries = 10
		errorInfo.Suggestions = []string{"Resource conflict, will retry with updated resource version"}
		return errorInfo
	}

	if errors.IsTooManyRequests(err) {
		errorInfo.Type = ErrorTypeTransient
		errorInfo.Severity = ErrorSeverityMedium
		errorInfo.Retryable = true
		errorInfo.RetryAfter = time.Minute * 2
		errorInfo.MaxRetries = 5
		errorInfo.Suggestions = []string{"Rate limited, will retry with exponential backoff"}
		return errorInfo
	}

	if errors.IsServerTimeout(err) || errors.IsTimeout(err) {
		errorInfo.Type = ErrorTypeTransient
		errorInfo.Severity = ErrorSeverityHigh
		errorInfo.Retryable = true
		errorInfo.RetryAfter = time.Minute * 1
		errorInfo.MaxRetries = 3
		errorInfo.Suggestions = []string{"Server timeout, check cluster health"}
		return errorInfo
	}

	if errors.IsForbidden(err) || errors.IsUnauthorized(err) {
		errorInfo.Type = ErrorTypeConfiguration
		errorInfo.Severity = ErrorSeverityCritical
		errorInfo.Retryable = false
		errorInfo.Suggestions = []string{
			"Check RBAC permissions for the operator",
			"Verify ServiceAccount and ClusterRole configuration",
			"Check AWS IAM permissions if using IRSA",
		}
		return errorInfo
	}

	if errors.IsInvalid(err) || errors.IsBadRequest(err) {
		errorInfo.Type = ErrorTypeConfiguration
		errorInfo.Severity = ErrorSeverityHigh
		errorInfo.Retryable = false
		errorInfo.Suggestions = []string{
			"Check N8nInstance specification for invalid values",
			"Validate required fields are properly set",
			"Review API documentation for correct field formats",
		}
		return errorInfo
	}

	// Classify network errors
	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			errorInfo.Type = ErrorTypeNetwork
			errorInfo.Severity = ErrorSeverityMedium
			errorInfo.Retryable = true
			errorInfo.RetryAfter = time.Second * 30
			errorInfo.MaxRetries = 5
			errorInfo.Suggestions = []string{"Network timeout, check connectivity to external services"}
		} else {
			errorInfo.Type = ErrorTypeNetwork
			errorInfo.Severity = ErrorSeverityHigh
			errorInfo.Retryable = true
			errorInfo.RetryAfter = time.Minute * 1
			errorInfo.MaxRetries = 3
			errorInfo.Suggestions = []string{"Network error, check network connectivity and DNS resolution"}
		}
		return errorInfo
	}

	// Classify AWS errors
	if eh.isAWSError(err) {
		return eh.classifyAWSError(err)
	}

	// Classify resource errors
	if eh.isResourceError(err) {
		errorInfo.Type = ErrorTypeResource
		errorInfo.Severity = ErrorSeverityHigh
		errorInfo.Retryable = false
		errorInfo.Suggestions = []string{
			"Check resource quotas and limits",
			"Verify cluster has sufficient capacity",
			"Review resource requests and limits in N8nInstance spec",
		}
		return errorInfo
	}

	// Default classification for unknown errors
	errorInfo.Type = ErrorTypeTransient
	errorInfo.Severity = ErrorSeverityMedium
	errorInfo.Retryable = true
	errorInfo.RetryAfter = time.Minute * 2
	errorInfo.MaxRetries = 3
	errorInfo.Suggestions = []string{"Unknown error, check logs for more details"}

	return errorInfo
}

// isAWSError checks if an error is from AWS services
func (eh *ErrorHandler) isAWSError(err error) bool {
	errStr := strings.ToLower(err.Error())
	awsIndicators := []string{
		"aws",
		"rds",
		"elasticache",
		"s3",
		"cloudfront",
		"route53",
		"acm",
		"secrets manager",
		"iam",
		"cloudwatch",
		"sns",
	}

	for _, indicator := range awsIndicators {
		if strings.Contains(errStr, indicator) {
			return true
		}
	}
	return false
}

// classifyAWSError classifies AWS-specific errors
func (eh *ErrorHandler) classifyAWSError(err error) *ErrorInfo {
	errStr := strings.ToLower(err.Error())

	errorInfo := &ErrorInfo{
		Type:      ErrorTypeAWS,
		Component: "AWS",
		Cause:     err,
		Message:   err.Error(),
	}

	// Throttling errors
	if strings.Contains(errStr, "throttl") || strings.Contains(errStr, "rate limit") {
		errorInfo.Severity = ErrorSeverityMedium
		errorInfo.Retryable = true
		errorInfo.RetryAfter = time.Minute * 2
		errorInfo.MaxRetries = 5
		errorInfo.Suggestions = []string{"AWS API throttling, will retry with exponential backoff"}
		return errorInfo
	}

	// Permission errors
	if strings.Contains(errStr, "access denied") || strings.Contains(errStr, "unauthorized") || strings.Contains(errStr, "forbidden") {
		errorInfo.Severity = ErrorSeverityCritical
		errorInfo.Retryable = false
		errorInfo.Suggestions = []string{
			"Check AWS IAM permissions for the operator",
			"Verify IRSA (IAM Roles for Service Accounts) configuration",
			"Ensure required AWS policies are attached to the role",
		}
		return errorInfo
	}

	// Resource not found errors
	if strings.Contains(errStr, "not found") || strings.Contains(errStr, "does not exist") {
		errorInfo.Severity = ErrorSeverityMedium
		errorInfo.Retryable = true
		errorInfo.RetryAfter = time.Second * 30
		errorInfo.MaxRetries = 3
		errorInfo.Suggestions = []string{
			"AWS resource not found, check if it exists in the correct region",
			"Verify resource ARNs and names in N8nInstance specification",
		}
		return errorInfo
	}

	// Service unavailable errors
	if strings.Contains(errStr, "service unavailable") || strings.Contains(errStr, "internal error") {
		errorInfo.Severity = ErrorSeverityHigh
		errorInfo.Retryable = true
		errorInfo.RetryAfter = time.Minute * 5
		errorInfo.MaxRetries = 3
		errorInfo.Suggestions = []string{"AWS service temporarily unavailable, will retry"}
		return errorInfo
	}

	// Default AWS error
	errorInfo.Severity = ErrorSeverityMedium
	errorInfo.Retryable = true
	errorInfo.RetryAfter = time.Minute * 1
	errorInfo.MaxRetries = 3
	errorInfo.Suggestions = []string{"AWS service error, check AWS service status"}

	return errorInfo
}

// isResourceError checks if an error is related to resource constraints
func (eh *ErrorHandler) isResourceError(err error) bool {
	errStr := strings.ToLower(err.Error())
	resourceIndicators := []string{
		"insufficient",
		"quota",
		"limit",
		"capacity",
		"out of",
		"no space",
		"resource exhausted",
	}

	for _, indicator := range resourceIndicators {
		if strings.Contains(errStr, indicator) {
			return true
		}
	}
	return false
}

// CalculateRetryDelay calculates the delay for the next retry using exponential backoff
func (eh *ErrorHandler) CalculateRetryDelay(attempt int, baseDelay time.Duration, maxDelay time.Duration) time.Duration {
	if attempt <= 0 {
		return baseDelay
	}

	// Exponential backoff with jitter
	delay := time.Duration(float64(baseDelay) * math.Pow(2, float64(attempt-1)))

	// Add jitter (±25%)
	jitter := time.Duration(float64(delay) * 0.25 * (2*math.Rand() - 1))
	delay += jitter

	// Cap at maximum delay
	if delay > maxDelay {
		delay = maxDelay
	}

	return delay
}

// GetCircuitBreaker gets or creates a circuit breaker for a service
func (eh *ErrorHandler) GetCircuitBreaker(serviceName string) *CircuitBreaker {
	if cb, exists := eh.circuitBreakers[serviceName]; exists {
		return cb
	}

	cb := &CircuitBreaker{
		name:             serviceName,
		state:            CircuitBreakerStateClosed,
		failureThreshold: 5,
		timeout:          time.Minute * 5,
		halfOpenMaxCalls: 3,
	}

	eh.circuitBreakers[serviceName] = cb
	return cb
}

// RecordSuccess records a successful operation for circuit breaker
func (cb *CircuitBreaker) RecordSuccess() {
	cb.failureCount = 0
	if cb.state == CircuitBreakerStateHalfOpen {
		cb.halfOpenCalls++
		if cb.halfOpenCalls >= cb.halfOpenMaxCalls {
			cb.state = CircuitBreakerStateClosed
			cb.halfOpenCalls = 0
		}
	}
}

// RecordFailure records a failed operation for circuit breaker
func (cb *CircuitBreaker) RecordFailure() {
	cb.failureCount++
	cb.lastFailure = time.Now()

	if cb.state == CircuitBreakerStateClosed && cb.failureCount >= cb.failureThreshold {
		cb.state = CircuitBreakerStateOpen
	} else if cb.state == CircuitBreakerStateHalfOpen {
		cb.state = CircuitBreakerStateOpen
		cb.halfOpenCalls = 0
	}
}

// CanExecute checks if an operation can be executed based on circuit breaker state
func (cb *CircuitBreaker) CanExecute() bool {
	switch cb.state {
	case CircuitBreakerStateClosed:
		return true
	case CircuitBreakerStateOpen:
		if time.Since(cb.lastFailure) > cb.timeout {
			cb.state = CircuitBreakerStateHalfOpen
			cb.halfOpenCalls = 0
			return true
		}
		return false
	case CircuitBreakerStateHalfOpen:
		return cb.halfOpenCalls < cb.halfOpenMaxCalls
	default:
		return false
	}
}

// HandleError processes an error and returns appropriate reconcile result
func (eh *ErrorHandler) HandleError(ctx context.Context, err error, instance *n8nv1alpha1.N8nInstance, component string, attempt int) (ctrl.Result, error) {
	if err == nil {
		return ctrl.Result{}, nil
	}

	errorInfo := eh.ClassifyError(err, component)

	// Log structured error information
	eh.logger.Error(err, "Error occurred during reconciliation",
		"component", component,
		"type", errorInfo.Type,
		"severity", errorInfo.Severity,
		"retryable", errorInfo.Retryable,
		"attempt", attempt,
		"suggestions", errorInfo.Suggestions,
	)

	// Record metrics if CloudWatch client is available
	if eh.cloudWatchClient != nil {
		eh.recordErrorMetrics(ctx, errorInfo, instance)
	}

	// Handle circuit breaker
	cb := eh.GetCircuitBreaker(component)
	cb.RecordFailure()

	// Determine if we should retry
	if !errorInfo.Retryable || attempt >= errorInfo.MaxRetries {
		eh.logger.Info("Error is not retryable or max retries exceeded",
			"component", component,
			"attempt", attempt,
			"maxRetries", errorInfo.MaxRetries,
		)
		return ctrl.Result{}, err
	}

	// Check circuit breaker
	if !cb.CanExecute() {
		eh.logger.Info("Circuit breaker is open, not retrying",
			"component", component,
			"state", cb.state,
		)
		return ctrl.Result{RequeueAfter: cb.timeout}, fmt.Errorf("circuit breaker open for %s: %w", component, err)
	}

	// Calculate retry delay
	retryDelay := eh.CalculateRetryDelay(attempt, errorInfo.RetryAfter, time.Minute*10)

	eh.logger.Info("Scheduling retry",
		"component", component,
		"attempt", attempt,
		"retryAfter", retryDelay,
	)

	return ctrl.Result{RequeueAfter: retryDelay}, nil
}

// recordErrorMetrics records error metrics to CloudWatch
func (eh *ErrorHandler) recordErrorMetrics(ctx context.Context, errorInfo *ErrorInfo, instance *n8nv1alpha1.N8nInstance) {
	metrics := []types.MetricDatum{
		{
			MetricName: aws.String("ErrorCount"),
			Dimensions: []types.Dimension{
				{
					Name:  aws.String("InstanceName"),
					Value: aws.String(instance.Name),
				},
				{
					Name:  aws.String("Component"),
					Value: aws.String(errorInfo.Component),
				},
				{
					Name:  aws.String("ErrorType"),
					Value: aws.String(string(errorInfo.Type)),
				},
				{
					Name:  aws.String("ErrorSeverity"),
					Value: aws.String(string(errorInfo.Severity)),
				},
			},
			Value:     aws.Float64(1.0),
			Unit:      types.StandardUnitCount,
			Timestamp: aws.Time(time.Now()),
		},
	}

	_, err := eh.cloudWatchClient.PutMetricData(ctx, &cloudwatch.PutMetricDataInput{
		Namespace:  aws.String("N8N/EKS/Errors"),
		MetricData: metrics,
	})

	if err != nil {
		eh.logger.Error(err, "Failed to record error metrics to CloudWatch")
	}
}
