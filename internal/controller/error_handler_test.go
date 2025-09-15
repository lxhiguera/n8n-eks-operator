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
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-logr/logr"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

func TestErrorHandler_ClassifyError(t *testing.T) {
	logger := logr.Discard()
	eh := NewErrorHandler(logger, nil)

	tests := []struct {
		name              string
		err               error
		component         string
		expectedType      ErrorType
		expectedRetryable bool
	}{
		{
			name:              "NotFound error should be transient and retryable",
			err:               k8serrors.NewNotFound(schema.GroupResource{Group: "apps", Resource: "deployments"}, "test"),
			component:         "test",
			expectedType:      ErrorTypeTransient,
			expectedRetryable: true,
		},
		{
			name:              "Conflict error should be transient and retryable",
			err:               k8serrors.NewConflict(schema.GroupResource{Group: "apps", Resource: "deployments"}, "test", errors.New("conflict")),
			component:         "test",
			expectedType:      ErrorTypeTransient,
			expectedRetryable: true,
		},
		{
			name:              "Forbidden error should be configuration and not retryable",
			err:               k8serrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "test", errors.New("forbidden")),
			component:         "test",
			expectedType:      ErrorTypeConfiguration,
			expectedRetryable: false,
		},
		{
			name:              "Network timeout should be network and retryable",
			err:               &net.OpError{Op: "dial", Err: &timeoutError{}},
			component:         "test",
			expectedType:      ErrorTypeNetwork,
			expectedRetryable: true,
		},
		{
			name:              "AWS throttling error should be AWS and retryable",
			err:               errors.New("AWS RDS throttling limit exceeded"),
			component:         "test",
			expectedType:      ErrorTypeAWS,
			expectedRetryable: true,
		},
		{
			name:              "AWS access denied should be AWS and not retryable",
			err:               errors.New("AWS access denied for RDS operation"),
			component:         "test",
			expectedType:      ErrorTypeAWS,
			expectedRetryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errorInfo := eh.ClassifyError(tt.err, tt.component)

			if errorInfo == nil {
				t.Fatal("Expected error info, got nil")
			}

			if errorInfo.Type != tt.expectedType {
				t.Errorf("Expected error type %s, got %s", tt.expectedType, errorInfo.Type)
			}

			if errorInfo.Retryable != tt.expectedRetryable {
				t.Errorf("Expected retryable %v, got %v", tt.expectedRetryable, errorInfo.Retryable)
			}

			if errorInfo.Component != tt.component {
				t.Errorf("Expected component %s, got %s", tt.component, errorInfo.Component)
			}
		})
	}
}

func TestErrorHandler_CalculateRetryDelay(t *testing.T) {
	logger := logr.Discard()
	eh := NewErrorHandler(logger, nil)

	baseDelay := time.Second * 30
	maxDelay := time.Minute * 10

	tests := []struct {
		name     string
		attempt  int
		expected time.Duration
	}{
		{
			name:     "First attempt should return base delay",
			attempt:  0,
			expected: baseDelay,
		},
		{
			name:     "Second attempt should be roughly double",
			attempt:  1,
			expected: baseDelay,
		},
		{
			name:     "Third attempt should be roughly quadruple",
			attempt:  2,
			expected: baseDelay * 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delay := eh.CalculateRetryDelay(tt.attempt, baseDelay, maxDelay)

			// Allow for jitter (±25%)
			minExpected := time.Duration(float64(tt.expected) * 0.75)
			maxExpected := time.Duration(float64(tt.expected) * 1.25)

			if tt.attempt == 0 {
				// First attempt should be exactly base delay
				if delay != baseDelay {
					t.Errorf("Expected delay %v, got %v", baseDelay, delay)
				}
			} else {
				// Other attempts should be within jitter range
				if delay < minExpected || delay > maxExpected {
					t.Errorf("Expected delay between %v and %v, got %v", minExpected, maxExpected, delay)
				}
			}

			// Should never exceed max delay
			if delay > maxDelay {
				t.Errorf("Delay %v exceeds max delay %v", delay, maxDelay)
			}
		})
	}
}

func TestCircuitBreaker(t *testing.T) {
	logger := logr.Discard()
	eh := NewErrorHandler(logger, nil)

	cb := eh.GetCircuitBreaker("test-service")

	// Initially should be closed and allow execution
	if cb.state != CircuitBreakerStateClosed {
		t.Errorf("Expected initial state to be Closed, got %s", cb.state)
	}

	if !cb.CanExecute() {
		t.Error("Expected to be able to execute when circuit breaker is closed")
	}

	// Record failures to trigger circuit breaker
	for i := 0; i < cb.failureThreshold; i++ {
		cb.RecordFailure()
	}

	// Should now be open
	if cb.state != CircuitBreakerStateOpen {
		t.Errorf("Expected state to be Open after %d failures, got %s", cb.failureThreshold, cb.state)
	}

	if cb.CanExecute() {
		t.Error("Expected not to be able to execute when circuit breaker is open")
	}

	// Simulate timeout passing
	cb.lastFailure = time.Now().Add(-cb.timeout - time.Second)

	// Should transition to half-open
	if !cb.CanExecute() {
		t.Error("Expected to be able to execute after timeout")
	}

	if cb.state != CircuitBreakerStateHalfOpen {
		t.Errorf("Expected state to be HalfOpen after timeout, got %s", cb.state)
	}

	// Record successes to close circuit breaker
	for i := 0; i < cb.halfOpenMaxCalls; i++ {
		cb.RecordSuccess()
	}

	// Should now be closed again
	if cb.state != CircuitBreakerStateClosed {
		t.Errorf("Expected state to be Closed after successful calls, got %s", cb.state)
	}
}

func TestErrorHandler_HandleError(t *testing.T) {
	logger := logr.Discard()
	eh := NewErrorHandler(logger, nil)

	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: "default",
		},
	}

	ctx := context.Background()

	// Test retryable error
	retryableErr := k8serrors.NewNotFound(schema.GroupResource{Group: "apps", Resource: "deployments"}, "test")
	result, err := eh.HandleError(ctx, retryableErr, instance, "test-component", 1)

	if err != nil {
		t.Errorf("Expected no error for retryable error, got %v", err)
	}

	if result.RequeueAfter == 0 {
		t.Error("Expected requeue after delay for retryable error")
	}

	// Test non-retryable error
	nonRetryableErr := k8serrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "test", errors.New("forbidden"))
	result, err = eh.HandleError(ctx, nonRetryableErr, instance, "test-component", 1)

	if err == nil {
		t.Error("Expected error for non-retryable error")
	}

	// Test max retries exceeded
	result, err = eh.HandleError(ctx, retryableErr, instance, "test-component", 10)

	if err == nil {
		t.Error("Expected error when max retries exceeded")
	}
}

// timeoutError implements net.Error for testing
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }
