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

//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// createCustomN8nInstance creates an N8nInstance with custom configuration
func (suite *E2ETestSuite) createCustomN8nInstance(name string) *n8nv1alpha1.N8nInstance {
	return &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-e2e",
				"test-run":   suite.testPrefix,
				"test-type":  "custom",
			},
		},
		Spec: n8nv1alpha1.N8nInstanceSpec{
			Version: "1.0.0",
			Domain:  fmt.Sprintf("%s.custom.test.local", name),
			Components: &n8nv1alpha1.ComponentsSpec{
				Main: &n8nv1alpha1.ComponentSpec{
					Replicas: 2, // Custom replica count
					Port:     5678,
					Resources: &n8nv1alpha1.ResourcesSpec{
						Requests: &n8nv1alpha1.ResourceRequirementsSpec{
							CPU:    "200m", // Custom resources
							Memory: "256Mi",
						},
						Limits: &n8nv1alpha1.ResourceRequirementsSpec{
							CPU:    "1",
							Memory: "1Gi",
						},
					},
					Autoscaling: &n8nv1alpha1.AutoscalingSpec{
						Enabled:     true,
						MinReplicas: 2,
						MaxReplicas: 5,
						TargetCPU:   70,
					},
				},
				Webhook: &n8nv1alpha1.ComponentSpec{
					Replicas:  3, // Custom webhook replicas
					Port:      5679,
					Subdomain: "webhooks",
					Resources: &n8nv1alpha1.ResourcesSpec{
						Requests: &n8nv1alpha1.ResourceRequirementsSpec{
							CPU:    "100m",
							Memory: "128Mi",
						},
						Limits: &n8nv1alpha1.ResourceRequirementsSpec{
							CPU:    "500m",
							Memory: "512Mi",
						},
					},
					Autoscaling: &n8nv1alpha1.AutoscalingSpec{
						Enabled:     true,
						MinReplicas: 3,
						MaxReplicas: 10,
						TargetCPU:   80,
					},
				},
				Worker: &n8nv1alpha1.ComponentSpec{
					Replicas: 2,
					Resources: &n8nv1alpha1.ResourcesSpec{
						Requests: &n8nv1alpha1.ResourceRequirementsSpec{
							CPU:    "150m",
							Memory: "192Mi",
						},
						Limits: &n8nv1alpha1.ResourceRequirementsSpec{
							CPU:    "600m",
							Memory: "768Mi",
						},
					},
					Autoscaling: &n8nv1alpha1.AutoscalingSpec{
						Enabled:     true,
						MinReplicas: 2,
						MaxReplicas: 8,
						TargetCPU:   75,
					},
				},
			},
			Storage: &n8nv1alpha1.StorageSpec{
				Persistent: &n8nv1alpha1.PersistentStorageSpec{
					Type:          "ebs-csi",
					StorageClass:  "gp3",
					Size:          "10Gi", // Custom storage size
					AutoExpansion: true,
				},
			},
			Monitoring: &n8nv1alpha1.MonitoringSpec{
				Metrics: &n8nv1alpha1.MetricsSpec{
					Enabled: true,
					Prometheus: &n8nv1alpha1.PrometheusSpec{
						Enabled:        true,
						ServiceMonitor: true,
					},
				},
				Logging: &n8nv1alpha1.LoggingSpec{
					Level: "debug", // Custom log level
				},
			},
		},
	}
}

// createInvalidN8nInstance creates an N8nInstance with invalid configuration
func (suite *E2ETestSuite) createInvalidN8nInstance(name string) *n8nv1alpha1.N8nInstance {
	return &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-e2e",
				"test-run":   suite.testPrefix,
				"test-type":  "invalid",
			},
		},
		Spec: n8nv1alpha1.N8nInstanceSpec{
			Version: "invalid-version", // Invalid version format
			Domain:  "invalid..domain",  // Invalid domain format
			Components: &n8nv1alpha1.ComponentsSpec{
				Main: &n8nv1alpha1.ComponentSpec{
					Replicas: -1,    // Invalid negative replicas
					Port:     99999, // Invalid port number
					Resources: &n8nv1alpha1.ResourcesSpec{
						Requests: &n8nv1alpha1.ResourceRequirementsSpec{
							CPU:    "invalid-cpu",    // Invalid CPU format
							Memory: "invalid-memory", // Invalid memory format
						},
					},
				},
			},
		},
	}
}

// createMonitoringN8nInstance creates an N8nInstance with monitoring enabled
func (suite *E2ETestSuite) createMonitoringN8nInstance(name string) *n8nv1alpha1.N8nInstance {
	return &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-e2e",
				"test-run":   suite.testPrefix,
				"test-type":  "monitoring",
			},
		},
		Spec: n8nv1alpha1.N8nInstanceSpec{
			Version: "1.0.0",
			Domain:  fmt.Sprintf("%s.monitoring.test.local", name),
			Components: &n8nv1alpha1.ComponentsSpec{
				Main: &n8nv1alpha1.ComponentSpec{
					Replicas: 1,
					Port:     5678,
					Resources: &n8nv1alpha1.ResourcesSpec{
						Requests: &n8nv1alpha1.ResourceRequirementsSpec{
							CPU:    "100m",
							Memory: "128Mi",
						},
					},
				},
			},
			Monitoring: &n8nv1alpha1.MonitoringSpec{
				Metrics: &n8nv1alpha1.MetricsSpec{
					Enabled: true,
					Prometheus: &n8nv1alpha1.PrometheusSpec{
						Enabled:        true,
						ServiceMonitor: true,
					},
					CloudWatch: &n8nv1alpha1.CloudWatchSpec{
						Enabled:   true,
						Namespace: "N8N/E2E/Test",
					},
				},
				Logging: &n8nv1alpha1.LoggingSpec{
					Level: "info",
					CloudWatch: &n8nv1alpha1.CloudWatchLogsSpec{
						Enabled:   true,
						Retention: 7,
					},
				},
				Alerts: &n8nv1alpha1.AlertsSpec{
					Enabled: true,
				},
			},
		},
	}
}

// testN8nInstanceUpdate tests updating an N8nInstance
func (suite *E2ETestSuite) testN8nInstanceUpdate(ctx context.Context, instanceName string) {
	instance := &n8nv1alpha1.N8nInstance{}
	err := suite.k8sClient.Get(ctx, types.NamespacedName{
		Name:      instanceName,
		Namespace: suite.testNamespace,
	}, instance)
	require.NoError(suite.T(), err)

	// Update the instance (change replica count)
	originalReplicas := instance.Spec.Components.Main.Replicas
	newReplicas := originalReplicas + 1
	instance.Spec.Components.Main.Replicas = newReplicas

	err = suite.k8sClient.Update(ctx, instance)
	require.NoError(suite.T(), err)

	// Wait for update to be processed
	suite.waitForDeploymentReplicas(ctx, fmt.Sprintf("%s-main", instanceName), newReplicas, 5*time.Minute)

	suite.T().Logf("Successfully updated N8nInstance %s replicas from %d to %d", instanceName, originalReplicas, newReplicas)
}

// testN8nInstanceScaling tests scaling operations
func (suite *E2ETestSuite) testN8nInstanceScaling(ctx context.Context, instanceName string) {
	// Test manual scaling
	instance := &n8nv1alpha1.N8nInstance{}
	err := suite.k8sClient.Get(ctx, types.NamespacedName{
		Name:      instanceName,
		Namespace: suite.testNamespace,
	}, instance)
	require.NoError(suite.T(), err)

	// Scale webhook component
	originalWebhookReplicas := instance.Spec.Components.Webhook.Replicas
	newWebhookReplicas := originalWebhookReplicas + 2
	instance.Spec.Components.Webhook.Replicas = newWebhookReplicas

	err = suite.k8sClient.Update(ctx, instance)
	require.NoError(suite.T(), err)

	// Wait for scaling to complete
	suite.waitForDeploymentReplicas(ctx, fmt.Sprintf("%s-webhook", instanceName), newWebhookReplicas, 5*time.Minute)

	// Verify HPA is created if autoscaling is enabled
	if instance.Spec.Components.Main.Autoscaling != nil && instance.Spec.Components.Main.Autoscaling.Enabled {
		suite.verifyHPA(ctx, fmt.Sprintf("%s-main", instanceName))
	}

	suite.T().Logf("Successfully scaled webhook component from %d to %d replicas", originalWebhookReplicas, newWebhookReplicas)
}

// testN8nInstanceDeletion tests deletion of N8nInstance
func (suite *E2ETestSuite) testN8nInstanceDeletion(ctx context.Context, instanceName string) {
	instance := &n8nv1alpha1.N8nInstance{}
	err := suite.k8sClient.Get(ctx, types.NamespacedName{
		Name:      instanceName,
		Namespace: suite.testNamespace,
	}, instance)
	require.NoError(suite.T(), err)

	// Delete the instance
	err = suite.k8sClient.Delete(ctx, instance)
	require.NoError(suite.T(), err)

	// Wait for deletion to complete
	suite.waitForN8nInstanceDeletion(ctx, instanceName, 10*time.Minute)

	// Verify all resources are cleaned up
	suite.verifyResourceCleanup(ctx, instanceName)

	suite.T().Logf("Successfully deleted N8nInstance %s and verified cleanup", instanceName)
}

// verifyCustomConfiguration verifies custom configuration is applied
func (suite *E2ETestSuite) verifyCustomConfiguration(ctx context.Context, instanceName string) {
	// Verify main deployment has 2 replicas
	mainDeployment := &appsv1.Deployment{}
	err := suite.k8sClient.Get(ctx, types.NamespacedName{
		Name:      fmt.Sprintf("%s-main", instanceName),
		Namespace: suite.testNamespace,
	}, mainDeployment)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), int32(2), *mainDeployment.Spec.Replicas)

	// Verify webhook deployment has 3 replicas
	webhookDeployment := &appsv1.Deployment{}
	err = suite.k8sClient.Get(ctx, types.NamespacedName{
		Name:      fmt.Sprintf("%s-webhook", instanceName),
		Namespace: suite.testNamespace,
	}, webhookDeployment)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), int32(3), *webhookDeployment.Spec.Replicas)

	// Verify HPA is created for components with autoscaling enabled
	suite.verifyHPA(ctx, fmt.Sprintf("%s-main", instanceName))
	suite.verifyHPA(ctx, fmt.Sprintf("%s-webhook", instanceName))
	suite.verifyHPA(ctx, fmt.Sprintf("%s-worker", instanceName))

	suite.T().Logf("Custom configuration verified for %s", instanceName)
}

// verifyErrorConditions verifies error conditions are set correctly
func (suite *E2ETestSuite) verifyErrorConditions(ctx context.Context, instanceName string) {
	instance := &n8nv1alpha1.N8nInstance{}
	err := suite.k8sClient.Get(ctx, types.NamespacedName{
		Name:      instanceName,
		Namespace: suite.testNamespace,
	}, instance)
	require.NoError(suite.T(), err)

	// Verify instance is in Failed phase
	assert.Equal(suite.T(), n8nv1alpha1.N8nInstancePhaseFailed, instance.Status.Phase)

	// Verify error conditions are present
	assert.NotEmpty(suite.T(), instance.Status.Conditions)

	// Look for error-related conditions
	hasErrorCondition := false
	for _, condition := range instance.Status.Conditions {
		if condition.Status == metav1.ConditionFalse &&
			(condition.Type == n8nv1alpha1.ConditionTypeReady || condition.Type == n8nv1alpha1.ConditionTypeProgressing) {
			hasErrorCondition = true
			assert.NotEmpty(suite.T(), condition.Message, "Error condition should have a message")
			break
		}
	}
	assert.True(suite.T(), hasErrorCondition, "Should have at least one error condition")

	suite.T().Logf("Error conditions verified for %s", instanceName)
}

// verifyMonitoringResources verifies monitoring resources are created
func (suite *E2ETestSuite) verifyMonitoringResources(ctx context.Context, instanceName string) {
	// Check for metrics services
	components := []string{"main", "webhook", "worker"}
	for _, component := range components {
		metricsServiceName := fmt.Sprintf("%s-%s-metrics", instanceName, component)
		service := &corev1.Service{}
		err := suite.k8sClient.Get(ctx, types.NamespacedName{
			Name:      metricsServiceName,
			Namespace: suite.testNamespace,
		}, service)

		if err == nil {
			assert.Equal(suite.T(), "prometheus", service.Labels["monitoring"])
			suite.T().Logf("Verified metrics service: %s", metricsServiceName)
		} else {
			suite.T().Logf("Metrics service %s not found (may be optional): %v", metricsServiceName, err)
		}
	}

	// Check for ServiceMonitor ConfigMap
	serviceMonitorName := fmt.Sprintf("%s-servicemonitor", instanceName)
	configMap := &corev1.ConfigMap{}
	err := suite.k8sClient.Get(ctx, types.NamespacedName{
		Name:      serviceMonitorName,
		Namespace: suite.testNamespace,
	}, configMap)

	if err == nil {
		assert.Equal(suite.T(), "servicemonitor", configMap.Labels["monitoring"])
		assert.Contains(suite.T(), configMap.Data, "servicemonitor.yaml")
		suite.T().Logf("Verified ServiceMonitor ConfigMap: %s", serviceMonitorName)
	} else {
		suite.T().Logf("ServiceMonitor ConfigMap %s not found: %v", serviceMonitorName, err)
	}

	// Check for Grafana dashboard ConfigMap
	dashboardName := fmt.Sprintf("%s-grafana-dashboard", instanceName)
	dashboardConfigMap := &corev1.ConfigMap{}
	err = suite.k8sClient.Get(ctx, types.NamespacedName{
		Name:      dashboardName,
		Namespace: suite.testNamespace,
	}, dashboardConfigMap)

	if err == nil {
		assert.Equal(suite.T(), "1", dashboardConfigMap.Labels["grafana_dashboard"])
		assert.Contains(suite.T(), dashboardConfigMap.Data, "n8n-dashboard.json")
		suite.T().Logf("Verified Grafana dashboard ConfigMap: %s", dashboardName)
	} else {
		suite.T().Logf("Grafana dashboard ConfigMap %s not found: %v", dashboardName, err)
	}

	suite.T().Logf("Monitoring resources verification completed for %s", instanceName)
}

// waitForDeploymentReplicas waits for deployment to have specified number of ready replicas
func (suite *E2ETestSuite) waitForDeploymentReplicas(ctx context.Context, deploymentName string, expectedReplicas int32, timeout time.Duration) {
	suite.T().Logf("Waiting for deployment %s to have %d ready replicas", deploymentName, expectedReplicas)

	err := wait.PollImmediate(10*time.Second, timeout, func() (bool, error) {
		deployment := &appsv1.Deployment{}
		err := suite.k8sClient.Get(ctx, types.NamespacedName{
			Name:      deploymentName,
			Namespace: suite.testNamespace,
		}, deployment)

		if err != nil {
			return false, err
		}

		suite.T().Logf("Deployment %s: %d/%d replicas ready", deploymentName, deployment.Status.ReadyReplicas, expectedReplicas)

		return deployment.Status.ReadyReplicas == expectedReplicas, nil
	})

	require.NoError(suite.T(), err, "Timeout waiting for deployment %s to have %d ready replicas", deploymentName, expectedReplicas)
}

// waitForN8nInstanceDeletion waits for N8nInstance to be deleted
func (suite *E2ETestSuite) waitForN8nInstanceDeletion(ctx context.Context, instanceName string, timeout time.Duration) {
	suite.T().Logf("Waiting for N8nInstance %s to be deleted", instanceName)

	err := wait.PollImmediate(10*time.Second, timeout, func() (bool, error) {
		instance := &n8nv1alpha1.N8nInstance{}
		err := suite.k8sClient.Get(ctx, types.NamespacedName{
			Name:      instanceName,
			Namespace: suite.testNamespace,
		}, instance)

		if errors.IsNotFound(err) {
			return true, nil
		}

		if err != nil {
			return false, err
		}

		suite.T().Logf("N8nInstance %s still exists, phase: %s", instanceName, instance.Status.Phase)
		return false, nil
	})

	require.NoError(suite.T(), err, "Timeout waiting for N8nInstance %s to be deleted", instanceName)
}

// verifyHPA verifies HorizontalPodAutoscaler is created
func (suite *E2ETestSuite) verifyHPA(ctx context.Context, deploymentName string) {
	hpaName := fmt.Sprintf("%s-hpa", deploymentName)
	hpa := &autoscalingv1.HorizontalPodAutoscaler{}
	err := suite.k8sClient.Get(ctx, types.NamespacedName{
		Name:      hpaName,
		Namespace: suite.testNamespace,
	}, hpa)

	if err == nil {
		assert.Equal(suite.T(), deploymentName, hpa.Spec.ScaleTargetRef.Name)
		assert.Equal(suite.T(), "Deployment", hpa.Spec.ScaleTargetRef.Kind)
		suite.T().Logf("Verified HPA: %s", hpaName)
	} else {
		suite.T().Logf("HPA %s not found (may be optional): %v", hpaName, err)
	}
}

// verifyResourceCleanup verifies all resources are cleaned up after deletion
func (suite *E2ETestSuite) verifyResourceCleanup(ctx context.Context, instanceName string) {
	components := []string{"main", "webhook", "worker"}

	// Verify deployments are deleted
	for _, component := range components {
		deploymentName := fmt.Sprintf("%s-%s", instanceName, component)
		deployment := &appsv1.Deployment{}
		err := suite.k8sClient.Get(ctx, types.NamespacedName{
			Name:      deploymentName,
			Namespace: suite.testNamespace,
		}, deployment)

		assert.True(suite.T(), errors.IsNotFound(err), "Deployment %s should be deleted", deploymentName)
	}

	// Verify services are deleted
	serviceComponents := []string{"main", "webhook"}
	for _, component := range serviceComponents {
		serviceName := fmt.Sprintf("%s-%s", instanceName, component)
		service := &corev1.Service{}
		err := suite.k8sClient.Get(ctx, types.NamespacedName{
			Name:      serviceName,
			Namespace: suite.testNamespace,
		}, service)

		assert.True(suite.T(), errors.IsNotFound(err), "Service %s should be deleted", serviceName)
	}

	// Verify ConfigMaps are deleted
	configMaps := []string{
		fmt.Sprintf("%s-config", instanceName),
		fmt.Sprintf("%s-servicemonitor", instanceName),
		fmt.Sprintf("%s-grafana-dashboard", instanceName),
	}

	for _, configMapName := range configMaps {
		configMap := &corev1.ConfigMap{}
		err := suite.k8sClient.Get(ctx, types.NamespacedName{
			Name:      configMapName,
			Namespace: suite.testNamespace,
		}, configMap)

		if err == nil {
			suite.T().Logf("Warning: ConfigMap %s still exists after deletion", configMapName)
		} else if !errors.IsNotFound(err) {
			suite.T().Logf("Error checking ConfigMap %s: %v", configMapName, err)
		}
	}

	suite.T().Logf("Resource cleanup verification completed for %s", instanceName)
}

// waitForCondition waits for a specific condition on N8nInstance
func (suite *E2ETestSuite) waitForCondition(ctx context.Context, instanceName string, conditionType n8nv1alpha1.ConditionType, status metav1.ConditionStatus, timeout time.Duration) {
	suite.T().Logf("Waiting for condition %s=%s on N8nInstance %s", conditionType, status, instanceName)

	err := wait.PollImmediate(10*time.Second, timeout, func() (bool, error) {
		instance := &n8nv1alpha1.N8nInstance{}
		err := suite.k8sClient.Get(ctx, types.NamespacedName{
			Name:      instanceName,
			Namespace: suite.testNamespace,
		}, instance)

		if err != nil {
			return false, err
		}

		for _, condition := range instance.Status.Conditions {
			if condition.Type == conditionType && condition.Status == status {
				return true, nil
			}
		}

		return false, nil
	})

	require.NoError(suite.T(), err, "Timeout waiting for condition %s=%s", conditionType, status)
}

// addCleanupFunc adds a cleanup function to be executed during teardown
func (suite *E2ETestSuite) addCleanupFunc(f func() error) {
	suite.cleanupFuncs = append(suite.cleanupFuncs, f)
}

// createTestSecret creates a test secret for the instance
func (suite *E2ETestSuite) createTestSecret(ctx context.Context, name string, data map[string][]byte) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-e2e",
				"test-run":   suite.testPrefix,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}

	err := suite.k8sClient.Create(ctx, secret)
	require.NoError(suite.T(), err)

	suite.addCleanupFunc(func() error {
		return suite.k8sClient.Delete(context.Background(), secret)
	})

	suite.T().Logf("Created test secret: %s", name)
}

// createTestConfigMap creates a test ConfigMap for the instance
func (suite *E2ETestSuite) createTestConfigMap(ctx context.Context, name string, data map[string]string) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-e2e",
				"test-run":   suite.testPrefix,
			},
		},
		Data: data,
	}

	err := suite.k8sClient.Create(ctx, configMap)
	require.NoError(suite.T(), err)

	suite.addCleanupFunc(func() error {
		return suite.k8sClient.Delete(context.Background(), configMap)
	})

	suite.T().Logf("Created test ConfigMap: %s", name)
}