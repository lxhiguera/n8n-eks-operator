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

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/lxhiguera/n8n-eks-operator/internal/managers"
)

// SetupManagersConfig holds configuration for setting up managers
type SetupManagersConfig struct {
	Client client.Client
	Scheme *runtime.Scheme
	Logger logr.Logger
}

// SetupManagers creates and configures all managers for the N8nInstance controller
func SetupManagers(cfg SetupManagersConfig) (*N8nInstanceReconciler, error) {
	logger := cfg.Logger.WithName("setup")

	// Initialize AWS config
	awsConfig, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		logger.Error(err, "Failed to load AWS config, some features may be disabled")
		// Continue without AWS clients - they will be nil and AWS features will be disabled
	}

	var cloudWatchClient *cloudwatch.Client
	if err == nil {
		cloudWatchClient = cloudwatch.NewFromConfig(awsConfig)
	}

	// Create managers
	databaseManager := managers.NewDatabaseManager(cfg.Client, cfg.Scheme, cfg.Logger.WithName("database"))
	cacheManager := managers.NewCacheManager(cfg.Client, cfg.Scheme, cfg.Logger.WithName("cache"))
	storageManager := managers.NewStorageManager(cfg.Client, cfg.Scheme, cfg.Logger.WithName("storage"))
	networkManager := managers.NewNetworkManager(cfg.Client, cfg.Scheme, cfg.Logger.WithName("network"))
	securityManager := managers.NewSecurityManager(cfg.Client, cfg.Scheme, cfg.Logger.WithName("security"))
	deploymentManager := managers.NewDeploymentManager(cfg.Client, cfg.Scheme, cfg.Logger.WithName("deployment"))
	servicesManager := managers.NewServicesManager(cfg.Client, cfg.Scheme, cfg.Logger.WithName("services"))
	monitoringManager := managers.NewMonitoringManager(cfg.Client, cfg.Scheme, cfg.Logger.WithName("monitoring"))

	// Create error handler
	errorHandler := NewErrorHandler(cfg.Logger.WithName("error-handler"), cloudWatchClient)

	// Create finalizer manager
	finalizerManager := NewFinalizerManager(
		cfg.Client,
		cfg.Logger.WithName("finalizer"),
		databaseManager,
		cacheManager,
		storageManager,
		networkManager,
		securityManager,
		monitoringManager,
	)

	// Create the reconciler
	reconciler := &N8nInstanceReconciler{
		Client:            cfg.Client,
		Scheme:            cfg.Scheme,
		DatabaseManager:   databaseManager,
		CacheManager:      cacheManager,
		StorageManager:    storageManager,
		NetworkManager:    networkManager,
		SecurityManager:   securityManager,
		DeploymentManager: deploymentManager,
		ServicesManager:   servicesManager,
		MonitoringManager: monitoringManager,
		ErrorHandler:      errorHandler,
		FinalizerManager:  finalizerManager,
	}

	logger.Info("All managers initialized successfully")
	return reconciler, nil
}

// SetupWithManager sets up the controller with the Manager
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
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 5, // Allow up to 5 concurrent reconciliations
		}).
		Complete(r)
}
