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
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

func TestFinalizerManager_AddFinalizer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = n8nv1alpha1.AddToScheme(scheme)

	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: "default",
		},
		Spec: n8nv1alpha1.N8nInstanceSpec{
			Version: "1.0.0",
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(instance).Build()
	logger := logr.Discard()

	fm := NewFinalizerManager(fakeClient, logger, nil, nil, nil, nil, nil, nil)

	ctx := context.Background()

	// Test adding finalizer
	err := fm.AddFinalizer(ctx, instance)
	if err != nil {
		t.Errorf("AddFinalizer() error = %v", err)
	}

	// Verify finalizer was added
	if !fm.HasFinalizer(instance) {
		t.Error("Expected finalizer to be present after AddFinalizer()")
	}

	// Test adding finalizer again (should be idempotent)
	err = fm.AddFinalizer(ctx, instance)
	if err != nil {
		t.Errorf("AddFinalizer() second call error = %v", err)
	}
}

func TestFinalizerManager_HasFinalizer(t *testing.T) {
	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: "default",
		},
	}

	fm := NewFinalizerManager(nil, logr.Discard(), nil, nil, nil, nil, nil, nil)

	// Test without finalizer
	if fm.HasFinalizer(instance) {
		t.Error("Expected HasFinalizer() to return false for instance without finalizer")
	}

	// Add finalizer
	controllerutil.AddFinalizer(instance, n8nv1alpha1.N8nInstanceFinalizer)

	// Test with finalizer
	if !fm.HasFinalizer(instance) {
		t.Error("Expected HasFinalizer() to return true for instance with finalizer")
	}
}

func TestFinalizerManager_IsBeingDeleted(t *testing.T) {
	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: "default",
		},
	}

	fm := NewFinalizerManager(nil, logr.Discard(), nil, nil, nil, nil, nil, nil)

	// Test without deletion timestamp
	if fm.IsBeingDeleted(instance) {
		t.Error("Expected IsBeingDeleted() to return false for instance without deletion timestamp")
	}

	// Set deletion timestamp
	now := metav1.Now()
	instance.DeletionTimestamp = &now

	// Test with deletion timestamp
	if !fm.IsBeingDeleted(instance) {
		t.Error("Expected IsBeingDeleted() to return true for instance with deletion timestamp")
	}
}

func TestFinalizerManager_HandleDeletion(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = n8nv1alpha1.AddToScheme(scheme)

	tests := []struct {
		name          string
		instance      *n8nv1alpha1.N8nInstance
		expectError   bool
		expectRequeue bool
	}{
		{
			name: "instance without finalizer should proceed",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "test-instance",
					Namespace:         "default",
					DeletionTimestamp: &metav1.Time{Time: time.Now()},
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Version: "1.0.0",
				},
			},
			expectError:   false,
			expectRequeue: false,
		},
		{
			name: "instance with finalizer should execute cleanup",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "test-instance",
					Namespace:         "default",
					DeletionTimestamp: &metav1.Time{Time: time.Now()},
					Finalizers:        []string{n8nv1alpha1.N8nInstanceFinalizer},
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Version: "1.0.0",
				},
				Status: n8nv1alpha1.N8nInstanceStatus{
					Phase: n8nv1alpha1.N8nInstancePhaseReady,
				},
			},
			expectError:   false,
			expectRequeue: false,
		},
		{
			name: "instance in creating phase should fail validation",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "test-instance",
					Namespace:         "default",
					DeletionTimestamp: &metav1.Time{Time: time.Now()},
					Finalizers:        []string{n8nv1alpha1.N8nInstanceFinalizer},
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Version: "1.0.0",
				},
				Status: n8nv1alpha1.N8nInstanceStatus{
					Phase: n8nv1alpha1.N8nInstancePhaseCreating,
				},
			},
			expectError:   true,
			expectRequeue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.instance).Build()
			logger := logr.Discard()

			fm := NewFinalizerManager(fakeClient, logger, nil, nil, nil, nil, nil, nil)

			ctx := context.Background()
			result, err := fm.HandleDeletion(ctx, tt.instance)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if tt.expectRequeue && result.RequeueAfter == 0 {
				t.Error("Expected requeue but got none")
			}

			if !tt.expectRequeue && result.RequeueAfter > 0 {
				t.Errorf("Expected no requeue but got: %v", result.RequeueAfter)
			}
		})
	}
}

func TestFinalizerManager_CleanupSteps(t *testing.T) {
	fm := NewFinalizerManager(nil, logr.Discard(), nil, nil, nil, nil, nil, nil)

	steps := fm.getCleanupSteps()

	if len(steps) == 0 {
		t.Error("Expected cleanup steps to be defined")
	}

	// Verify that PreCleanupValidation is marked as critical
	found := false
	for _, step := range steps {
		if step.Name == "PreCleanupValidation" {
			found = true
			if !step.Critical {
				t.Error("Expected PreCleanupValidation to be marked as critical")
			}
			break
		}
	}

	if !found {
		t.Error("Expected PreCleanupValidation step to be present")
	}

	// Verify all steps have required fields
	for _, step := range steps {
		if step.Name == "" {
			t.Error("Step name should not be empty")
		}
		if step.Description == "" {
			t.Error("Step description should not be empty")
		}
		if step.Execute == nil {
			t.Error("Step execute function should not be nil")
		}
		if step.Timeout <= 0 {
			t.Errorf("Step %s should have a positive timeout", step.Name)
		}
	}
}

func TestFinalizerManager_ValidateCleanupPreconditions(t *testing.T) {
	fm := NewFinalizerManager(nil, logr.Discard(), nil, nil, nil, nil, nil, nil)
	ctx := context.Background()

	tests := []struct {
		name        string
		instance    *n8nv1alpha1.N8nInstance
		expectError bool
	}{
		{
			name: "ready instance should pass validation",
			instance: &n8nv1alpha1.N8nInstance{
				Status: n8nv1alpha1.N8nInstanceStatus{
					Phase: n8nv1alpha1.N8nInstancePhaseReady,
				},
			},
			expectError: false,
		},
		{
			name: "creating instance should fail validation",
			instance: &n8nv1alpha1.N8nInstance{
				Status: n8nv1alpha1.N8nInstanceStatus{
					Phase: n8nv1alpha1.N8nInstancePhaseCreating,
				},
			},
			expectError: true,
		},
		{
			name: "failed instance should pass validation",
			instance: &n8nv1alpha1.N8nInstance{
				Status: n8nv1alpha1.N8nInstanceStatus{
					Phase: n8nv1alpha1.N8nInstancePhaseFailed,
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fm.validateCleanupPreconditions(ctx, tt.instance)

			if tt.expectError && err == nil {
				t.Error("Expected validation error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no validation error but got: %v", err)
			}
		})
	}
}

func TestFinalizerManager_CleanupStepExecution(t *testing.T) {
	fm := NewFinalizerManager(nil, logr.Discard(), nil, nil, nil, nil, nil, nil)
	ctx := context.Background()

	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: "default",
		},
		Status: n8nv1alpha1.N8nInstanceStatus{
			Phase: n8nv1alpha1.N8nInstancePhaseReady,
		},
	}

	// Test individual cleanup steps
	cleanupFunctions := []struct {
		name string
		fn   func(context.Context, *n8nv1alpha1.N8nInstance) error
	}{
		{"stopActiveWorkflows", fm.stopActiveWorkflows},
		{"backupCriticalData", fm.backupCriticalData},
		{"cleanupMonitoring", fm.cleanupMonitoring},
		{"cleanupNetworking", fm.cleanupNetworking},
		{"cleanupStorage", fm.cleanupStorage},
		{"cleanupCache", fm.cleanupCache},
		{"cleanupDatabase", fm.cleanupDatabase},
		{"cleanupSecurity", fm.cleanupSecurity},
		{"validateCleanupCompletion", fm.validateCleanupCompletion},
	}

	for _, cleanup := range cleanupFunctions {
		t.Run(cleanup.name, func(t *testing.T) {
			err := cleanup.fn(ctx, instance)
			if err != nil {
				t.Errorf("Cleanup function %s failed: %v", cleanup.name, err)
			}
		})
	}
}
