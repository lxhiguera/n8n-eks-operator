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
	"reflect"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
	"github.com/lxhiguera/n8n-eks-operator/internal/managers"
)

// N8nInstanceReconciler reconciles a N8nInstance object
type N8nInstanceReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	DatabaseManager   managers.DatabaseManager
	CacheManager      managers.CacheManager
	StorageManager    managers.StorageManager
	NetworkManager    managers.NetworkManager
	SecurityManager   managers.SecurityManager
	DeploymentManager managers.DeploymentManager
	ServicesManager   managers.ServicesManager
	MonitoringManager managers.MonitoringManager
	ErrorHandler      *ErrorHandler
	FinalizerManager  *FinalizerManager
}

//+kubebuilder:rbac:groups=n8n.io,resources=n8ninstances,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=n8n.io,resources=n8ninstances/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=n8n.io,resources=n8ninstances/finalizers,verbs=update
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=autoscaling,resources=horizontalpodautoscalers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.istio.io,resources=gateways,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.istio.io,resources=virtualservices,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.istio.io,resources=destinationrules,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=security.istio.io,resources=authorizationpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *N8nInstanceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("n8ninstance", req.NamespacedName)

	logger.Info("Starting reconciliation")

	// Fetch the N8nInstance instance
	var instance n8nv1alpha1.N8nInstance
	if err := r.Get(ctx, req.NamespacedName, &instance); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("N8nInstance resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get N8nInstance")
		return ctrl.Result{}, err
	}

	// Create a copy for status updates
	originalInstance := instance.DeepCopy()

	// Initialize status if not set
	if instance.Status.Phase == "" {
		logger.Info("Initializing N8nInstance status")
		instance.Status.Phase = n8nv1alpha1.N8nInstancePhasePending
		instance.Status.Conditions = []n8nv1alpha1.N8nInstanceCondition{}
		r.setCondition(&instance, n8nv1alpha1.ConditionTypeProgressing, metav1.ConditionTrue, "Initializing", "N8nInstance is being initialized")

		if err := r.updateStatus(ctx, &instance, originalInstance); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Handle deletion
	if !instance.DeletionTimestamp.IsZero() {
		logger.Info("N8nInstance is being deleted")
		return r.handleDeletion(ctx, &instance)
	}

	// Add finalizer if not present
	if r.FinalizerManager != nil && !r.FinalizerManager.HasFinalizer(&instance) {
		logger.Info("Adding finalizer to N8nInstance using FinalizerManager")
		if err := r.FinalizerManager.AddFinalizer(ctx, &instance); err != nil {
			logger.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	} else if r.FinalizerManager == nil && !controllerutil.ContainsFinalizer(&instance, n8nv1alpha1.N8nInstanceFinalizer) {
		logger.Info("Adding finalizer to N8nInstance (fallback)")
		controllerutil.AddFinalizer(&instance, n8nv1alpha1.N8nInstanceFinalizer)
		if err := r.Update(ctx, &instance); err != nil {
			logger.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Detect if this is an update by comparing generation
	isUpdate := instance.Generation != instance.Status.ObservedGeneration
	if isUpdate {
		logger.Info("Detected spec change, updating N8nInstance", "generation", instance.Generation, "observedGeneration", instance.Status.ObservedGeneration)
		instance.Status.Phase = n8nv1alpha1.N8nInstancePhaseUpdating
		r.setCondition(&instance, n8nv1alpha1.ConditionTypeProgressing, metav1.ConditionTrue, "Updating", "N8nInstance is being updated")
	}

	// Transition to Creating phase if currently Pending
	if instance.Status.Phase == n8nv1alpha1.N8nInstancePhasePending {
		logger.Info("Transitioning to Creating phase")
		instance.Status.Phase = n8nv1alpha1.N8nInstancePhaseCreating
		r.setCondition(&instance, n8nv1alpha1.ConditionTypeProgressing, metav1.ConditionTrue, "Creating", "N8nInstance components are being created")

		if err := r.updateStatus(ctx, &instance, originalInstance); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Reconcile all components
	reconcileResult, err := r.reconcileComponents(ctx, &instance)
	if err != nil {
		logger.Error(err, "Failed to reconcile components")
		instance.Status.Phase = n8nv1alpha1.N8nInstancePhaseFailed
		r.setCondition(&instance, n8nv1alpha1.ConditionTypeProgressing, metav1.ConditionFalse, "ReconciliationFailed", fmt.Sprintf("Failed to reconcile components: %v", err))
		r.setCondition(&instance, n8nv1alpha1.ConditionTypeReady, metav1.ConditionFalse, "ComponentsNotReady", "One or more components failed to reconcile")

		if statusErr := r.updateStatus(ctx, &instance, originalInstance); statusErr != nil {
			logger.Error(statusErr, "Failed to update status after reconciliation failure")
		}

		// Return with exponential backoff for failures
		return ctrl.Result{RequeueAfter: time.Minute * 5}, err
	}

	// Check if all components are ready
	allReady, readyMessage := r.checkComponentsReady(ctx, &instance)

	if allReady {
		// All components are ready
		if instance.Status.Phase != n8nv1alpha1.N8nInstancePhaseReady {
			logger.Info("All components ready, transitioning to Ready phase")
			instance.Status.Phase = n8nv1alpha1.N8nInstancePhaseReady
		}

		r.setCondition(&instance, n8nv1alpha1.ConditionTypeProgressing, metav1.ConditionFalse, "ReconciliationComplete", "All components have been successfully reconciled")
		r.setCondition(&instance, n8nv1alpha1.ConditionTypeReady, metav1.ConditionTrue, "AllComponentsReady", readyMessage)

		// Update endpoints in status
		if err := r.updateEndpoints(ctx, &instance); err != nil {
			logger.Error(err, "Failed to update endpoints in status")
		}

	} else {
		// Some components are not ready yet
		if instance.Status.Phase == n8nv1alpha1.N8nInstancePhaseReady {
			instance.Status.Phase = n8nv1alpha1.N8nInstancePhaseUpdating
		}

		r.setCondition(&instance, n8nv1alpha1.ConditionTypeProgressing, metav1.ConditionTrue, "ComponentsNotReady", "Waiting for components to become ready")
		r.setCondition(&instance, n8nv1alpha1.ConditionTypeReady, metav1.ConditionFalse, "ComponentsNotReady", readyMessage)
	}

	// Update observed generation
	instance.Status.ObservedGeneration = instance.Generation

	// Update status if changed
	if err := r.updateStatus(ctx, &instance, originalInstance); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("Reconciliation completed successfully", "phase", instance.Status.Phase, "ready", allReady)

	// Return appropriate requeue interval based on reconcile result
	return reconcileResult, nil
}

// reconcileComponents reconciles all components of the N8nInstance
func (r *N8nInstanceReconciler) reconcileComponents(ctx context.Context, instance *n8nv1alpha1.N8nInstance) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Define reconciliation steps with dependencies
	reconciliationSteps := []struct {
		name    string
		manager func(context.Context, *n8nv1alpha1.N8nInstance) error
	}{
		{"Security", r.SecurityManager.ReconcileSecurity},
		{"Database", r.DatabaseManager.ReconcileDatabase},
		{"Cache", r.CacheManager.ReconcileCache},
		{"Storage", r.StorageManager.ReconcileStorage},
		{"Networking", r.NetworkManager.ReconcileNetworking},
		{"Deployments", r.DeploymentManager.ReconcileDeployments},
		{"Services", r.ServicesManager.ReconcileServices},
		{"Monitoring", r.MonitoringManager.ReconcileMonitoring},
	}

	// Get retry attempt from instance annotations
	attempt := r.getRetryAttempt(instance)

	// Execute reconciliation steps in order
	for i, step := range reconciliationSteps {
		logger.Info("Reconciling component", "component", step.name, "attempt", attempt)

		stepStartTime := time.Now()

		// Check circuit breaker before executing
		if r.ErrorHandler != nil {
			cb := r.ErrorHandler.GetCircuitBreaker(step.name)
			if !cb.CanExecute() {
				logger.Info("Circuit breaker is open, skipping component", "component", step.name, "state", cb.state)
				r.setCondition(instance, fmt.Sprintf("%sReady", step.name), metav1.ConditionFalse, "CircuitBreakerOpen", fmt.Sprintf("Circuit breaker is open for %s", step.name))
				continue
			}
		}

		err := step.manager(ctx, instance)
		stepDuration := time.Since(stepStartTime)

		if err != nil {
			logger.Error(err, "Failed to reconcile component", "component", step.name, "duration", stepDuration, "attempt", attempt)

			// Set component-specific condition
			r.setCondition(instance, fmt.Sprintf("%sReady", step.name), metav1.ConditionFalse, "ReconciliationFailed", fmt.Sprintf("Failed to reconcile %s: %v", step.name, err))

			// Use ErrorHandler to determine retry strategy
			if r.ErrorHandler != nil {
				result, handledErr := r.ErrorHandler.HandleError(ctx, err, instance, step.name, attempt)
				if handledErr != nil {
					// Error is not retryable or max retries exceeded
					return ctrl.Result{}, fmt.Errorf("failed to reconcile %s after %d attempts: %w", step.name, attempt, err)
				}

				// Update retry attempt in annotations
				r.updateRetryAttempt(instance, attempt+1)

				// Return with retry schedule
				return result, nil
			}

			// Fallback without ErrorHandler
			return ctrl.Result{RequeueAfter: time.Minute * 5}, fmt.Errorf("failed to reconcile %s: %w", step.name, err)
		}

		logger.Info("Successfully reconciled component", "component", step.name, "duration", stepDuration)

		// Record success in circuit breaker
		if r.ErrorHandler != nil {
			cb := r.ErrorHandler.GetCircuitBreaker(step.name)
			cb.RecordSuccess()
		}

		// Set component-specific condition as ready
		r.setCondition(instance, fmt.Sprintf("%sReady", step.name), metav1.ConditionTrue, "ReconciliationSuccessful", fmt.Sprintf("%s component reconciled successfully", step.name))
	}

	// Reset retry attempt on successful reconciliation
	r.resetRetryAttempt(instance)

	logger.Info("All components reconciled successfully")

	// Return with standard requeue interval for healthy instances
	return ctrl.Result{RequeueAfter: time.Minute * 10}, nil
}

// setCondition sets a condition on the N8nInstance status
func (r *N8nInstanceReconciler) setCondition(instance *n8nv1alpha1.N8nInstance, conditionType string, status metav1.ConditionStatus, reason, message string) {
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
func (r *N8nInstanceReconciler) updateStatus(ctx context.Context, instance, original *n8nv1alpha1.N8nInstance) error {
	if !reflect.DeepEqual(instance.Status, original.Status) {
		logger := log.FromContext(ctx)
		logger.Info("Updating N8nInstance status", "phase", instance.Status.Phase)

		if err := r.Status().Update(ctx, instance); err != nil {
			logger.Error(err, "Failed to update N8nInstance status")
			return err
		}
	}
	return nil
}

// checkComponentsReady checks if all components are ready
func (r *N8nInstanceReconciler) checkComponentsReady(ctx context.Context, instance *n8nv1alpha1.N8nInstance) (bool, string) {
	logger := log.FromContext(ctx)

	// Check main deployment
	mainReady, err := r.isDeploymentReady(ctx, instance, "main")
	if err != nil {
		logger.Error(err, "Failed to check main deployment readiness")
		return false, fmt.Sprintf("Failed to check main deployment: %v", err)
	}

	// Check webhook deployment
	webhookReady, err := r.isDeploymentReady(ctx, instance, "webhook")
	if err != nil {
		logger.Error(err, "Failed to check webhook deployment readiness")
		return false, fmt.Sprintf("Failed to check webhook deployment: %v", err)
	}

	// Check worker deployment
	workerReady, err := r.isDeploymentReady(ctx, instance, "worker")
	if err != nil {
		logger.Error(err, "Failed to check worker deployment readiness")
		return false, fmt.Sprintf("Failed to check worker deployment: %v", err)
	}

	if !mainReady {
		return false, "Main component is not ready"
	}
	if !webhookReady {
		return false, "Webhook component is not ready"
	}
	if !workerReady {
		return false, "Worker component is not ready"
	}

	return true, "All components are ready and available"
}

// isDeploymentReady checks if a specific deployment is ready
func (r *N8nInstanceReconciler) isDeploymentReady(ctx context.Context, instance *n8nv1alpha1.N8nInstance, component string) (bool, error) {
	deploymentName := fmt.Sprintf("%s-%s", instance.Name, component)

	var deployment appsv1.Deployment
	err := r.Get(ctx, types.NamespacedName{
		Name:      deploymentName,
		Namespace: instance.Namespace,
	}, &deployment)

	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil // Deployment doesn't exist yet
		}
		return false, err
	}

	// Check if deployment is ready
	if deployment.Status.ReadyReplicas == deployment.Status.Replicas &&
		deployment.Status.Replicas > 0 &&
		deployment.Status.UnavailableReplicas == 0 {
		return true, nil
	}

	return false, nil
}

// updateEndpoints updates the endpoints in the N8nInstance status
func (r *N8nInstanceReconciler) updateEndpoints(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx)

	if instance.Status.Endpoints == nil {
		instance.Status.Endpoints = &n8nv1alpha1.N8nInstanceEndpoints{}
	}

	// Get main service endpoint
	mainEndpoint, err := r.getServiceEndpoint(ctx, instance, "main")
	if err != nil {
		logger.Error(err, "Failed to get main service endpoint")
	} else {
		instance.Status.Endpoints.Main = mainEndpoint
	}

	// Get webhook service endpoint
	webhookEndpoint, err := r.getServiceEndpoint(ctx, instance, "webhook")
	if err != nil {
		logger.Error(err, "Failed to get webhook service endpoint")
	} else {
		instance.Status.Endpoints.Webhook = webhookEndpoint
	}

	// Set assets endpoint if CloudFront is configured
	if instance.Spec.Storage != nil && instance.Spec.Storage.Assets != nil &&
		instance.Spec.Storage.Assets.CloudFront != nil && instance.Spec.Storage.Assets.CloudFront.Enabled {
		if instance.Spec.Storage.Assets.CloudFront.CustomDomain != "" {
			instance.Status.Endpoints.Assets = fmt.Sprintf("https://%s", instance.Spec.Storage.Assets.CloudFront.CustomDomain)
		} else {
			// Would need to get CloudFront distribution domain from AWS
			instance.Status.Endpoints.Assets = "https://cloudfront-distribution.amazonaws.com"
		}
	}

	return nil
}

// getServiceEndpoint gets the external endpoint for a service
func (r *N8nInstanceReconciler) getServiceEndpoint(ctx context.Context, instance *n8nv1alpha1.N8nInstance, component string) (string, error) {
	serviceName := fmt.Sprintf("%s-%s", instance.Name, component)

	var service corev1.Service
	err := r.Get(ctx, types.NamespacedName{
		Name:      serviceName,
		Namespace: instance.Namespace,
	}, &service)

	if err != nil {
		return "", err
	}

	// For LoadBalancer services, get the external IP/hostname
	if service.Spec.Type == corev1.ServiceTypeLoadBalancer {
		if len(service.Status.LoadBalancer.Ingress) > 0 {
			ingress := service.Status.LoadBalancer.Ingress[0]
			if ingress.Hostname != "" {
				return fmt.Sprintf("https://%s", ingress.Hostname), nil
			}
			if ingress.IP != "" {
				return fmt.Sprintf("https://%s", ingress.IP), nil
			}
		}
	}

	// For other service types or if LoadBalancer is not ready, return cluster internal endpoint
	if len(service.Spec.Ports) > 0 {
		port := service.Spec.Ports[0].Port
		return fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", serviceName, instance.Namespace, port), nil
	}

	return "", fmt.Errorf("no ports found on service %s", serviceName)
}

// getRetryAttempt gets the current retry attempt from instance annotations
func (r *N8nInstanceReconciler) getRetryAttempt(instance *n8nv1alpha1.N8nInstance) int {
	if instance.Annotations == nil {
		return 0
	}

	attemptStr, exists := instance.Annotations["n8n.io/retry-attempt"]
	if !exists {
		return 0
	}

	attempt := 0
	if _, err := fmt.Sscanf(attemptStr, "%d", &attempt); err != nil {
		return 0
	}

	return attempt
}

// updateRetryAttempt updates the retry attempt in instance annotations
func (r *N8nInstanceReconciler) updateRetryAttempt(instance *n8nv1alpha1.N8nInstance, attempt int) {
	if instance.Annotations == nil {
		instance.Annotations = make(map[string]string)
	}

	instance.Annotations["n8n.io/retry-attempt"] = fmt.Sprintf("%d", attempt)
	instance.Annotations["n8n.io/last-retry"] = time.Now().Format(time.RFC3339)
}

// resetRetryAttempt resets the retry attempt annotations
func (r *N8nInstanceReconciler) resetRetryAttempt(instance *n8nv1alpha1.N8nInstance) {
	if instance.Annotations == nil {
		return
	}

	delete(instance.Annotations, "n8n.io/retry-attempt")
	delete(instance.Annotations, "n8n.io/last-retry")
}

// handleDeletion handles the deletion of N8nInstance
func (r *N8nInstanceReconciler) handleDeletion(ctx context.Context, instance *n8nv1alpha1.N8nInstance) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if r.FinalizerManager != nil {
		logger.Info("Using FinalizerManager for deletion handling")
		return r.FinalizerManager.HandleDeletion(ctx, instance)
	}

	// Fallback to simple deletion handling if FinalizerManager is not available
	logger.Info("FinalizerManager not available, using simple deletion handling")

	if controllerutil.ContainsFinalizer(instance, n8nv1alpha1.N8nInstanceFinalizer) {
		logger.Info("Removing finalizer for simple deletion")
		controllerutil.RemoveFinalizer(instance, n8nv1alpha1.N8nInstanceFinalizer)
		if err := r.Update(ctx, instance); err != nil {
			logger.Error(err, "Failed to remove finalizer")
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *N8nInstanceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&n8nv1alpha1.N8nInstance{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.PersistentVolumeClaim{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Owns(&autoscalingv1.HorizontalPodAutoscaler{}).
		Complete(r)
}
