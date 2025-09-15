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

package managers

import (
	"context"
	"fmt"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// N8nDeploymentManager implements the DeploymentManager interface for n8n components
type N8nDeploymentManager struct {
	client client.Client
}

// NewN8nDeploymentManager creates a new N8nDeploymentManager instance
func NewN8nDeploymentManager(client client.Client) *N8nDeploymentManager {
	return &N8nDeploymentManager{
		client: client,
	}
}

// ReconcileDeployments ensures all deployments are correct
func (m *N8nDeploymentManager) ReconcileDeployments(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nDeploymentManager")
	logger.Info("Reconciling deployments")

	// Define n8n components to deploy
	components := []struct {
		name        string
		component   string
		replicas    int32
		ports       []int32
		args        []string
		resources   corev1.ResourceRequirements
	}{
		{
			name:      fmt.Sprintf("%s-main", instance.Name),
			component: "main",
			replicas:  1,
			ports:     []int32{5678},
			args:      []string{"start"},
			resources: m.getDefaultResources("main"),
		},
		{
			name:      fmt.Sprintf("%s-webhook", instance.Name),
			component: "webhook",
			replicas:  2,
			ports:     []int32{5679},
			args:      []string{"webhook"},
			resources: m.getDefaultResources("webhook"),
		},
		{
			name:      fmt.Sprintf("%s-worker", instance.Name),
			component: "worker",
			replicas:  3,
			ports:     []int32{},
			args:      []string{"worker"},
			resources: m.getDefaultResources("worker"),
		},
	}

	// Create deployments for each component
	for _, comp := range components {
		if err := m.createOrUpdateDeployment(ctx, instance, comp); err != nil {
			return fmt.Errorf("failed to create deployment for %s: %w", comp.name, err)
		}
	}

	logger.Info("Deployments reconciled successfully")
	return nil
}

// ReconcileConfigMaps creates and manages config maps
func (m *N8nDeploymentManager) ReconcileConfigMaps(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nDeploymentManager")
	logger.Info("Reconciling ConfigMaps")

	// Create main configuration ConfigMap
	if err := m.createMainConfigMap(ctx, instance); err != nil {
		return fmt.Errorf("failed to create main ConfigMap: %w", err)
	}

	// Create component-specific ConfigMaps
	components := []string{"main", "webhook", "worker"}
	for _, component := range components {
		if err := m.createComponentConfigMap(ctx, instance, component); err != nil {
			return fmt.Errorf("failed to create ConfigMap for %s: %w", component, err)
		}
	}

	logger.Info("ConfigMaps reconciled successfully")
	return nil
}

// ReconcileAutoscaling creates and manages HPA resources
func (m *N8nDeploymentManager) ReconcileAutoscaling(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nDeploymentManager")
	logger.Info("Reconciling autoscaling")

	// Define autoscaling configurations for components
	autoscalingConfigs := []struct {
		name         string
		component    string
		minReplicas  int32
		maxReplicas  int32
		targetCPU    int32
		targetMemory int32
	}{
		{
			name:         fmt.Sprintf("%s-main-hpa", instance.Name),
			component:    "main",
			minReplicas:  1,
			maxReplicas:  5,
			targetCPU:    70,
			targetMemory: 80,
		},
		{
			name:         fmt.Sprintf("%s-webhook-hpa", instance.Name),
			component:    "webhook",
			minReplicas:  2,
			maxReplicas:  10,
			targetCPU:    60,
			targetMemory: 70,
		},
		{
			name:         fmt.Sprintf("%s-worker-hpa", instance.Name),
			component:    "worker",
			minReplicas:  3,
			maxReplicas:  20,
			targetCPU:    80,
			targetMemory: 85,
		},
	}

	// Create HPA for each component
	for _, config := range autoscalingConfigs {
		if err := m.createOrUpdateHPA(ctx, instance, config); err != nil {
			return fmt.Errorf("failed to create HPA for %s: %w", config.name, err)
		}
	}

	logger.Info("Autoscaling reconciled successfully")
	return nil
}

// createOrUpdateDeployment creates or updates a deployment for a component
func (m *N8nDeploymentManager) createOrUpdateDeployment(ctx context.Context, instance *n8nv1alpha1.N8nInstance, comp struct {
	name        string
	component   string
	replicas    int32
	ports       []int32
	args        []string
	resources   corev1.ResourceRequirements
}) error {
	logger := log.FromContext(ctx).WithName("N8nDeploymentManager")
	logger.Info("Creating or updating deployment", "name", comp.name, "component", comp.component)

	// Build container ports
	var containerPorts []corev1.ContainerPort
	for _, port := range comp.ports {
		containerPorts = append(containerPorts, corev1.ContainerPort{
			Name:          fmt.Sprintf("http-%d", port),
			ContainerPort: port,
			Protocol:      corev1.ProtocolTCP,
		})
	}

	// Build environment variables
	envVars := m.buildEnvironmentVariables(instance, comp.component)

	// Build volume mounts
	volumeMounts := m.buildVolumeMounts(instance, comp.component)

	// Build volumes
	volumes := m.buildVolumes(instance, comp.component)

	// Create deployment
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      comp.name,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  comp.component,
				"app.kubernetes.io/version":    instance.Spec.Version,
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &comp.replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":      "n8n",
					"app.kubernetes.io/instance":  instance.Name,
					"app.kubernetes.io/component": comp.component,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name":      "n8n",
						"app.kubernetes.io/instance":  instance.Name,
						"app.kubernetes.io/component": comp.component,
						"app.kubernetes.io/version":   instance.Spec.Version,
					},
					Annotations: map[string]string{
						"sidecar.istio.io/inject": "true",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: fmt.Sprintf("%s-sa", instance.Name),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &[]bool{true}[0],
						RunAsUser:    &[]int64{1000}[0],
						RunAsGroup:   &[]int64{1000}[0],
						FSGroup:      &[]int64{1000}[0],
					},
					Containers: []corev1.Container{
						{
							Name:            "n8n",
							Image:           fmt.Sprintf("n8nio/n8n:%s", instance.Spec.Version),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Args:            comp.args,
							Ports:           containerPorts,
							Env:             envVars,
							VolumeMounts:    volumeMounts,
							Resources:       comp.resources,
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &[]bool{false}[0],
								ReadOnlyRootFilesystem:   &[]bool{true}[0],
								RunAsNonRoot:             &[]bool{true}[0],
								RunAsUser:                &[]int64{1000}[0],
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
							},
							LivenessProbe:  m.buildLivenessProbe(comp.component, comp.ports),
							ReadinessProbe: m.buildReadinessProbe(comp.component, comp.ports),
						},
					},
					Volumes: volumes,
				},
			},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &intstr.IntOrString{
						Type:   intstr.String,
						StrVal: "25%",
					},
					MaxSurge: &intstr.IntOrString{
						Type:   intstr.String,
						StrVal: "25%",
					},
				},
			},
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, deployment, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update deployment
	existingDeployment := &appsv1.Deployment{}
	deploymentKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      comp.name,
	}

	if err := m.client.Get(ctx, deploymentKey, existingDeployment); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing deployment: %w", err)
		}
		// Deployment doesn't exist, create it
		if err := m.client.Create(ctx, deployment); err != nil {
			return fmt.Errorf("failed to create deployment: %w", err)
		}
		logger.Info("Deployment created successfully", "name", comp.name)
	} else {
		// Deployment exists, update it
		existingDeployment.Spec = deployment.Spec
		if err := m.client.Update(ctx, existingDeployment); err != nil {
			return fmt.Errorf("failed to update deployment: %w", err)
		}
		logger.Info("Deployment updated successfully", "name", comp.name)
	}

	return nil
}

// getDefaultResources returns default resource requirements for a component
func (m *N8nDeploymentManager) getDefaultResources(component string) corev1.ResourceRequirements {
	switch component {
	case "main":
		return corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("1Gi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("2"),
				corev1.ResourceMemory: resource.MustParse("4Gi"),
			},
		}
	case "webhook":
		return corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("200m"),
				corev1.ResourceMemory: resource.MustParse("512Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("1"),
				corev1.ResourceMemory: resource.MustParse("2Gi"),
			},
		}
	case "worker":
		return corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("300m"),
				corev1.ResourceMemory: resource.MustParse("768Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("1.5"),
				corev1.ResourceMemory: resource.MustParse("3Gi"),
			},
		}
	default:
		return corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("1Gi"),
			},
		}
	}
}

// buildLivenessProbe builds liveness probe for a component
func (m *N8nDeploymentManager) buildLivenessProbe(component string, ports []int32) *corev1.Probe {
	if len(ports) == 0 {
		// For worker component without exposed ports, use exec probe
		return &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{"/bin/sh", "-c", "pgrep -f n8n"},
				},
			},
			InitialDelaySeconds: 30,
			PeriodSeconds:       10,
			TimeoutSeconds:      5,
			FailureThreshold:    3,
		}
	}

	// For components with exposed ports, use HTTP probe
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/healthz",
				Port: intstr.FromInt(int(ports[0])),
			},
		},
		InitialDelaySeconds: 30,
		PeriodSeconds:       10,
		TimeoutSeconds:      5,
		FailureThreshold:    3,
	}
}

// buildReadinessProbe builds readiness probe for a component
func (m *N8nDeploymentManager) buildReadinessProbe(component string, ports []int32) *corev1.Probe {
	if len(ports) == 0 {
		// For worker component without exposed ports, use exec probe
		return &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{"/bin/sh", "-c", "pgrep -f n8n"},
				},
			},
			InitialDelaySeconds: 10,
			PeriodSeconds:       5,
			TimeoutSeconds:      3,
			FailureThreshold:    3,
		}
	}

	// For components with exposed ports, use HTTP probe
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/healthz",
				Port: intstr.FromInt(int(ports[0])),
			},
		},
		InitialDelaySeconds: 10,
		PeriodSeconds:       5,
		TimeoutSeconds:      3,
		FailureThreshold:    3,
	}
}

// buildEnvironmentVariables builds environment variables for a component
func (m *N8nDeploymentManager) buildEnvironmentVariables(instance *n8nv1alpha1.N8nInstance, component string) []corev1.EnvVar {
	baseEnvVars := []corev1.EnvVar{
		{
			Name:  "NODE_ENV",
			Value: "production",
		},
		{
			Name:  "N8N_LOG_LEVEL",
			Value: "info",
		},
		{
			Name: "N8N_ENCRYPTION_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-app-secret", instance.Name),
					},
					Key: "encryption_key",
				},
			},
		},
		{
			Name: "DB_TYPE",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-database-secret", instance.Name),
					},
					Key: "type",
				},
			},
		},
		{
			Name: "DB_POSTGRESDB_HOST",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-database-secret", instance.Name),
					},
					Key: "redis-host",
				},
			},
		},
		{
			Name: "DB_POSTGRESDB_PORT",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-database-secret", instance.Name),
					},
					Key: "redis-port",
				},
			},
		},
		{
			Name: "DB_POSTGRESDB_DATABASE",
			Value: "n8n",
		},
		{
			Name: "DB_POSTGRESDB_USER",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-database-secret", instance.Name),
					},
					Key: "username",
				},
			},
		},
		{
			Name: "DB_POSTGRESDB_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-database-secret", instance.Name),
					},
					Key: "password",
				},
			},
		},
		{
			Name: "QUEUE_BULL_REDIS_HOST",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-cache-secret", instance.Name),
					},
					Key: "redis-host",
				},
			},
		},
		{
			Name: "QUEUE_BULL_REDIS_PORT",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-cache-secret", instance.Name),
					},
					Key: "redis-port",
				},
			},
		},
		{
			Name: "QUEUE_BULL_REDIS_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-cache-secret", instance.Name),
					},
					Key: "redis-password",
				},
			},
		},
	}

	// Add component-specific environment variables
	switch component {
	case "main":
		baseEnvVars = append(baseEnvVars, []corev1.EnvVar{
			{
				Name:  "N8N_PORT",
				Value: "5678",
			},
			{
				Name:  "N8N_PROTOCOL",
				Value: "https",
			},
			{
				Name:  "N8N_HOST",
				Value: instance.Spec.Domain,
			},
			{
				Name:  "WEBHOOK_URL",
				Value: fmt.Sprintf("https://webhook.%s", instance.Spec.Domain),
			},
			{
				Name:  "EXECUTIONS_MODE",
				Value: "queue",
			},
		}...)
	case "webhook":
		baseEnvVars = append(baseEnvVars, []corev1.EnvVar{
			{
				Name:  "N8N_PORT",
				Value: "5679",
			},
			{
				Name:  "WEBHOOK_URL",
				Value: fmt.Sprintf("https://webhook.%s", instance.Spec.Domain),
			},
			{
				Name:  "N8N_DISABLE_UI",
				Value: "true",
			},
		}...)
	case "worker":
		baseEnvVars = append(baseEnvVars, []corev1.EnvVar{
			{
				Name:  "EXECUTIONS_MODE",
				Value: "queue",
			},
			{
				Name:  "QUEUE_BULL_REDIS_DB",
				Value: "0",
			},
			{
				Name:  "N8N_DISABLE_UI",
				Value: "true",
			},
		}...)
	}

	return baseEnvVars
}

// buildVolumeMounts builds volume mounts for a component
func (m *N8nDeploymentManager) buildVolumeMounts(instance *n8nv1alpha1.N8nInstance, component string) []corev1.VolumeMount {
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      "config",
			MountPath: "/home/node/.n8n",
			ReadOnly:  true,
		},
		{
			Name:      "tmp",
			MountPath: "/tmp",
		},
		{
			Name:      "var-tmp",
			MountPath: "/var/tmp",
		},
	}

	// Add component-specific volume mounts
	switch component {
	case "main":
		volumeMounts = append(volumeMounts, []corev1.VolumeMount{
			{
				Name:      "data",
				MountPath: "/home/node/.n8n/data",
			},
			{
				Name:      "workflows",
				MountPath: "/home/node/.n8n/workflows",
			},
		}...)
	case "webhook":
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "webhook-data",
			MountPath: "/home/node/.n8n/webhook-data",
		})
	case "worker":
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "worker-data",
			MountPath: "/home/node/.n8n/worker-data",
		})
	}

	return volumeMounts
}

// buildVolumes builds volumes for a component
func (m *N8nDeploymentManager) buildVolumes(instance *n8nv1alpha1.N8nInstance, component string) []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-%s-config", instance.Name, component),
					},
				},
			},
		},
		{
			Name: "tmp",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "var-tmp",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
	}

	// Add component-specific volumes
	switch component {
	case "main":
		volumes = append(volumes, []corev1.Volume{
			{
				Name: "data",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: fmt.Sprintf("%s-main-data", instance.Name),
					},
				},
			},
			{
				Name: "workflows",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
		}...)
	case "webhook":
		volumes = append(volumes, corev1.Volume{
			Name: "webhook-data",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: fmt.Sprintf("%s-webhook-data", instance.Name),
				},
			},
		})
	case "worker":
		volumes = append(volumes, corev1.Volume{
			Name: "worker-data",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		})
	}

	return volumes
}

// createMainConfigMap creates the main configuration ConfigMap
func (m *N8nDeploymentManager) createMainConfigMap(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nDeploymentManager")
	
	configMapName := fmt.Sprintf("%s-config", instance.Name)
	logger.Info("Creating main ConfigMap", "name", configMapName)

	configData := map[string]string{
		"config.json": `{
			"database": {
				"type": "postgresdb",
				"logging": ["error", "warn"]
			},
			"credentials": {
				"overwrite": {
					"data": "{\"host\":\"localhost\",\"port\":5432}"
				}
			},
			"executions": {
				"mode": "queue",
				"timeout": 3600,
				"maxTimeout": 7200,
				"saveDataOnError": "all",
				"saveDataOnSuccess": "all",
				"saveDataManualExecutions": true
			},
			"queue": {
				"bull": {
					"redis": {
						"db": 0,
						"timeoutThreshold": 10000
					}
				}
			},
			"endpoints": {
				"rest": "rest",
				"webhook": "webhook",
				"webhookWaiting": "webhook-waiting",
				"webhookTest": "webhook-test"
			},
			"security": {
				"excludeEndpoints": [],
				"basicAuth": {
					"active": false
				}
			}
		}`,
		"logging.json": `{
			"level": "info",
			"outputs": ["console"],
			"file": {
				"location": "/home/node/.n8n/logs/n8n.log",
				"logRotate": {
					"maxFiles": "12",
					"maxSize": "100m"
				}
			}
		}`,
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "config",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Data: configData,
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, configMap, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update ConfigMap
	existingConfigMap := &corev1.ConfigMap{}
	configMapKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      configMapName,
	}

	if err := m.client.Get(ctx, configMapKey, existingConfigMap); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing ConfigMap: %w", err)
		}
		// ConfigMap doesn't exist, create it
		if err := m.client.Create(ctx, configMap); err != nil {
			return fmt.Errorf("failed to create ConfigMap: %w", err)
		}
		logger.Info("Main ConfigMap created successfully", "name", configMapName)
	} else {
		// ConfigMap exists, update it
		existingConfigMap.Data = configData
		if err := m.client.Update(ctx, existingConfigMap); err != nil {
			return fmt.Errorf("failed to update ConfigMap: %w", err)
		}
		logger.Info("Main ConfigMap updated successfully", "name", configMapName)
	}

	return nil
}

// createComponentConfigMap creates component-specific ConfigMap
func (m *N8nDeploymentManager) createComponentConfigMap(ctx context.Context, instance *n8nv1alpha1.N8nInstance, component string) error {
	logger := log.FromContext(ctx).WithName("N8nDeploymentManager")
	
	configMapName := fmt.Sprintf("%s-%s-config", instance.Name, component)
	logger.Info("Creating component ConfigMap", "name", configMapName, "component", component)

	configData := m.getComponentConfigData(component)

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  component,
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Data: configData,
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, configMap, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update ConfigMap
	existingConfigMap := &corev1.ConfigMap{}
	configMapKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      configMapName,
	}

	if err := m.client.Get(ctx, configMapKey, existingConfigMap); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing ConfigMap: %w", err)
		}
		// ConfigMap doesn't exist, create it
		if err := m.client.Create(ctx, configMap); err != nil {
			return fmt.Errorf("failed to create ConfigMap: %w", err)
		}
		logger.Info("Component ConfigMap created successfully", "name", configMapName)
	} else {
		// ConfigMap exists, update it
		existingConfigMap.Data = configData
		if err := m.client.Update(ctx, existingConfigMap); err != nil {
			return fmt.Errorf("failed to update ConfigMap: %w", err)
		}
		logger.Info("Component ConfigMap updated successfully", "name", configMapName)
	}

	return nil
}

// getComponentConfigData returns configuration data for a specific component
func (m *N8nDeploymentManager) getComponentConfigData(component string) map[string]string {
	switch component {
	case "main":
		return map[string]string{
			"component.json": `{
				"component": "main",
				"features": {
					"ui": true,
					"api": true,
					"workflows": true,
					"executions": true
				},
				"ports": {
					"http": 5678
				},
				"healthcheck": {
					"path": "/healthz",
					"interval": "30s"
				}
			}`,
		}
	case "webhook":
		return map[string]string{
			"component.json": `{
				"component": "webhook",
				"features": {
					"ui": false,
					"api": false,
					"webhooks": true
				},
				"ports": {
					"http": 5679
				},
				"healthcheck": {
					"path": "/healthz",
					"interval": "30s"
				}
			}`,
		}
	case "worker":
		return map[string]string{
			"component.json": `{
				"component": "worker",
				"features": {
					"ui": false,
					"api": false,
					"worker": true,
					"queue": true
				},
				"healthcheck": {
					"type": "process",
					"interval": "30s"
				}
			}`,
		}
	default:
		return map[string]string{
			"component.json": `{
				"component": "unknown"
			}`,
		}
	}
}

// createOrUpdateHPA creates or updates HorizontalPodAutoscaler
func (m *N8nDeploymentManager) createOrUpdateHPA(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config struct {
	name         string
	component    string
	minReplicas  int32
	maxReplicas  int32
	targetCPU    int32
	targetMemory int32
}) error {
	logger := log.FromContext(ctx).WithName("N8nDeploymentManager")
	logger.Info("Creating or updating HPA", "name", config.name, "component", config.component)

	deploymentName := fmt.Sprintf("%s-%s", instance.Name, config.component)

	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      config.name,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  config.component,
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       deploymentName,
			},
			MinReplicas: &config.minReplicas,
			MaxReplicas: config.maxReplicas,
			Metrics: []autoscalingv2.MetricSpec{
				{
					Type: autoscalingv2.ResourceMetricSourceType,
					Resource: &autoscalingv2.ResourceMetricSource{
						Name: corev1.ResourceCPU,
						Target: autoscalingv2.MetricTarget{
							Type:               autoscalingv2.UtilizationMetricType,
							AverageUtilization: &config.targetCPU,
						},
					},
				},
				{
					Type: autoscalingv2.ResourceMetricSourceType,
					Resource: &autoscalingv2.ResourceMetricSource{
						Name: corev1.ResourceMemory,
						Target: autoscalingv2.MetricTarget{
							Type:               autoscalingv2.UtilizationMetricType,
							AverageUtilization: &config.targetMemory,
						},
					},
				},
			},
			Behavior: &autoscalingv2.HorizontalPodAutoscalerBehavior{
				ScaleUp: &autoscalingv2.HPAScalingRules{
					StabilizationWindowSeconds: &[]int32{60}[0],
					Policies: []autoscalingv2.HPAScalingPolicy{
						{
							Type:          autoscalingv2.PercentScalingPolicy,
							Value:         50,
							PeriodSeconds: 60,
						},
					},
				},
				ScaleDown: &autoscalingv2.HPAScalingRules{
					StabilizationWindowSeconds: &[]int32{300}[0],
					Policies: []autoscalingv2.HPAScalingPolicy{
						{
							Type:          autoscalingv2.PercentScalingPolicy,
							Value:         25,
							PeriodSeconds: 60,
						},
					},
				},
			},
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, hpa, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update HPA
	existingHPA := &autoscalingv2.HorizontalPodAutoscaler{}
	hpaKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      config.name,
	}

	if err := m.client.Get(ctx, hpaKey, existingHPA); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing HPA: %w", err)
		}
		// HPA doesn't exist, create it
		if err := m.client.Create(ctx, hpa); err != nil {
			return fmt.Errorf("failed to create HPA: %w", err)
		}
		logger.Info("HPA created successfully", "name", config.name)
	} else {
		// HPA exists, update it
		existingHPA.Spec = hpa.Spec
		if err := m.client.Update(ctx, existingHPA); err != nil {
			return fmt.Errorf("failed to update HPA: %w", err)
		}
		logger.Info("HPA updated successfully", "name", config.name)
	}

	return nil
}

// buildA
dvancedEnvironmentVariables builds comprehensive environment variables with all integrations
func (m *N8nDeploymentManager) buildAdvancedEnvironmentVariables(instance *n8nv1alpha1.N8nInstance, component string) []corev1.EnvVar {
	envVars := []corev1.EnvVar{
		// Core n8n configuration
		{
			Name:  "NODE_ENV",
			Value: "production",
		},
		{
			Name:  "N8N_LOG_LEVEL",
			Value: "info",
		},
		{
			Name:  "N8N_LOG_OUTPUT",
			Value: "console,file",
		},
		{
			Name:  "N8N_METRICS",
			Value: "true",
		},
		{
			Name:  "N8N_DIAGNOSTICS_ENABLED",
			Value: "false",
		},
		
		// Security configuration
		{
			Name: "N8N_ENCRYPTION_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-app-secret", instance.Name),
					},
					Key: "encryption_key",
				},
			},
		},
		{
			Name: "N8N_USER_MANAGEMENT_JWT_SECRET",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-app-secret", instance.Name),
					},
					Key: "jwt_secret",
				},
			},
		},
		
		// Database configuration
		{
			Name:  "DB_TYPE",
			Value: "postgresdb",
		},
		{
			Name: "DB_POSTGRESDB_HOST",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-database-secret", instance.Name),
					},
					Key: "host",
				},
			},
		},
		{
			Name: "DB_POSTGRESDB_PORT",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-database-secret", instance.Name),
					},
					Key: "port",
				},
			},
		},
		{
			Name:  "DB_POSTGRESDB_DATABASE",
			Value: "n8n",
		},
		{
			Name: "DB_POSTGRESDB_USER",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-database-secret", instance.Name),
					},
					Key: "username",
				},
			},
		},
		{
			Name: "DB_POSTGRESDB_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-database-secret", instance.Name),
					},
					Key: "password",
				},
			},
		},
		{
			Name:  "DB_POSTGRESDB_SSL_ENABLED",
			Value: "true",
		},
		{
			Name:  "DB_POSTGRESDB_SSL_REJECT_UNAUTHORIZED",
			Value: "false",
		},
		
		// Redis/Queue configuration
		{
			Name: "QUEUE_BULL_REDIS_HOST",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-cache-secret", instance.Name),
					},
					Key: "redis-host",
				},
			},
		},
		{
			Name: "QUEUE_BULL_REDIS_PORT",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-cache-secret", instance.Name),
					},
					Key: "redis-port",
				},
			},
		},
		{
			Name: "QUEUE_BULL_REDIS_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-cache-secret", instance.Name),
					},
					Key: "redis-password",
				},
			},
		},
		{
			Name:  "QUEUE_BULL_REDIS_DB",
			Value: "0",
		},
		{
			Name:  "QUEUE_BULL_REDIS_TIMEOUT_THRESHOLD",
			Value: "10000",
		},
		
		// Storage configuration (S3)
		{
			Name: "N8N_DEFAULT_BINARY_DATA_MODE",
			Value: "s3",
		},
		{
			Name: "N8N_BINARY_DATA_S3_BUCKET",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-storage-secret", instance.Name),
					},
					Key: "workflows-bucket",
				},
			},
		},
		{
			Name: "N8N_BINARY_DATA_S3_REGION",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-storage-secret", instance.Name),
					},
					Key: "workflows-region",
				},
			},
		},
		
		// Execution configuration
		{
			Name:  "EXECUTIONS_TIMEOUT",
			Value: "3600",
		},
		{
			Name:  "EXECUTIONS_TIMEOUT_MAX",
			Value: "7200",
		},
		{
			Name:  "EXECUTIONS_DATA_SAVE_ON_ERROR",
			Value: "all",
		},
		{
			Name:  "EXECUTIONS_DATA_SAVE_ON_SUCCESS",
			Value: "all",
		},
		{
			Name:  "EXECUTIONS_DATA_SAVE_MANUAL_EXECUTIONS",
			Value: "true",
		},
		
		// Performance and scaling
		{
			Name:  "N8N_CONCURRENCY_PRODUCTION_LIMIT",
			Value: "10",
		},
		{
			Name:  "N8N_PAYLOAD_SIZE_MAX",
			Value: "16",
		},
		
		// Health and monitoring
		{
			Name:  "N8N_DIAGNOSTICS_ENABLED",
			Value: "false",
		},
		{
			Name:  "N8N_VERSION_NOTIFICATIONS_ENABLED",
			Value: "false",
		},
		
		// Kubernetes-specific
		{
			Name: "POD_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.name",
				},
			},
		},
		{
			Name: "POD_NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.namespace",
				},
			},
		},
		{
			Name: "POD_IP",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "status.podIP",
				},
			},
		},
		{
			Name: "NODE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "spec.nodeName",
				},
			},
		},
	}

	// Add component-specific environment variables
	componentEnvVars := m.getComponentSpecificEnvVars(instance, component)
	envVars = append(envVars, componentEnvVars...)

	return envVars
}

// getComponentSpecificEnvVars returns component-specific environment variables
func (m *N8nDeploymentManager) getComponentSpecificEnvVars(instance *n8nv1alpha1.N8nInstance, component string) []corev1.EnvVar {
	switch component {
	case "main":
		return []corev1.EnvVar{
			{
				Name:  "N8N_PORT",
				Value: "5678",
			},
			{
				Name:  "N8N_PROTOCOL",
				Value: "https",
			},
			{
				Name:  "N8N_HOST",
				Value: instance.Spec.Domain,
			},
			{
				Name:  "WEBHOOK_URL",
				Value: fmt.Sprintf("https://webhook.%s", instance.Spec.Domain),
			},
			{
				Name:  "N8N_EDITOR_BASE_URL",
				Value: fmt.Sprintf("https://%s", instance.Spec.Domain),
			},
			{
				Name:  "EXECUTIONS_MODE",
				Value: "queue",
			},
			{
				Name:  "N8N_DISABLE_PRODUCTION_MAIN_PROCESS",
				Value: "false",
			},
			{
				Name:  "N8N_SKIP_WEBHOOK_DEREGISTRATION_SHUTDOWN",
				Value: "true",
			},
			// Enable UI and API
			{
				Name:  "N8N_DISABLE_UI",
				Value: "false",
			},
			// Workflow management
			{
				Name:  "WORKFLOWS_DEFAULT_NAME",
				Value: "My workflow",
			},
			// User management
			{
				Name:  "N8N_USER_MANAGEMENT_DISABLED",
				Value: "false",
			},
			// Public API
			{
				Name:  "N8N_PUBLIC_API_DISABLED",
				Value: "false",
			},
			{
				Name:  "N8N_PUBLIC_API_ENDPOINT",
				Value: "api",
			},
		}
	case "webhook":
		return []corev1.EnvVar{
			{
				Name:  "N8N_PORT",
				Value: "5679",
			},
			{
				Name:  "WEBHOOK_URL",
				Value: fmt.Sprintf("https://webhook.%s", instance.Spec.Domain),
			},
			{
				Name:  "N8N_DISABLE_UI",
				Value: "true",
			},
			{
				Name:  "N8N_DISABLE_PRODUCTION_MAIN_PROCESS",
				Value: "true",
			},
			{
				Name:  "EXECUTIONS_MODE",
				Value: "queue",
			},
			// Webhook-specific configuration
			{
				Name:  "N8N_SKIP_WEBHOOK_DEREGISTRATION_SHUTDOWN",
				Value: "false",
			},
			{
				Name:  "WEBHOOK_TUNNEL_URL",
				Value: fmt.Sprintf("https://webhook.%s", instance.Spec.Domain),
			},
			// Performance optimization for webhooks
			{
				Name:  "N8N_PAYLOAD_SIZE_MAX",
				Value: "32",
			},
		}
	case "worker":
		return []corev1.EnvVar{
			{
				Name:  "EXECUTIONS_MODE",
				Value: "queue",
			},
			{
				Name:  "N8N_DISABLE_UI",
				Value: "true",
			},
			{
				Name:  "N8N_DISABLE_PRODUCTION_MAIN_PROCESS",
				Value: "true",
			},
			{
				Name:  "QUEUE_BULL_REDIS_DB",
				Value: "0",
			},
			// Worker-specific configuration
			{
				Name:  "EXECUTIONS_PROCESS",
				Value: "main",
			},
			{
				Name:  "N8N_WORKERS_CONCURRENCY",
				Value: "10",
			},
			// Performance optimization for workers
			{
				Name:  "N8N_CONCURRENCY_PRODUCTION_LIMIT",
				Value: "20",
			},
			{
				Name:  "EXECUTIONS_TIMEOUT",
				Value: "7200",
			},
		}
	default:
		return []corev1.EnvVar{}
	}
}

// buildEnvironmentFromConfigMap builds environment variables from ConfigMap
func (m *N8nDeploymentManager) buildEnvironmentFromConfigMap(instance *n8nv1alpha1.N8nInstance, component string) []corev1.EnvVar {
	return []corev1.EnvVar{
		{
			Name: "N8N_CONFIG_FILES",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-config", instance.Name),
					},
					Key: "config.json",
				},
			},
		},
		{
			Name: "N8N_LOGGING_CONFIG",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-config", instance.Name),
					},
					Key: "logging.json",
				},
			},
		},
		{
			Name: "COMPONENT_CONFIG",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-%s-config", instance.Name, component),
					},
					Key: "component.json",
				},
			},
		},
	}
}

// validateEnvironmentVariables validates environment variables configuration
func (m *N8nDeploymentManager) validateEnvironmentVariables(envVars []corev1.EnvVar, component string) error {
	requiredVars := m.getRequiredEnvironmentVariables(component)
	
	existingVars := make(map[string]bool)
	for _, envVar := range envVars {
		existingVars[envVar.Name] = true
	}
	
	for _, requiredVar := range requiredVars {
		if !existingVars[requiredVar] {
			return fmt.Errorf("required environment variable %s is missing for component %s", requiredVar, component)
		}
	}
	
	return nil
}

// getRequiredEnvironmentVariables returns required environment variables for a component
func (m *N8nDeploymentManager) getRequiredEnvironmentVariables(component string) []string {
	baseRequired := []string{
		"NODE_ENV",
		"N8N_ENCRYPTION_KEY",
		"DB_TYPE",
		"DB_POSTGRESDB_HOST",
		"DB_POSTGRESDB_PORT",
		"DB_POSTGRESDB_DATABASE",
		"DB_POSTGRESDB_USER",
		"DB_POSTGRESDB_PASSWORD",
	}
	
	switch component {
	case "main":
		return append(baseRequired, []string{
			"N8N_PORT",
			"N8N_HOST",
			"WEBHOOK_URL",
		}...)
	case "webhook":
		return append(baseRequired, []string{
			"N8N_PORT",
			"WEBHOOK_URL",
		}...)
	case "worker":
		return append(baseRequired, []string{
			"EXECUTIONS_MODE",
			"QUEUE_BULL_REDIS_HOST",
			"QUEUE_BULL_REDIS_PORT",
		}...)
	default:
		return baseRequired
	}
}

// buildSecretEnvironmentVariables builds environment variables from secrets with validation
func (m *N8nDeploymentManager) buildSecretEnvironmentVariables(instance *n8nv1alpha1.N8nInstance, component string) []corev1.EnvVar {
	secretEnvVars := []corev1.EnvVar{}
	
	// Database secrets
	dbSecretVars := []struct {
		envName   string
		secretKey string
	}{
		{"DB_POSTGRESDB_HOST", "host"},
		{"DB_POSTGRESDB_PORT", "port"},
		{"DB_POSTGRESDB_USER", "username"},
		{"DB_POSTGRESDB_PASSWORD", "password"},
	}
	
	for _, dbVar := range dbSecretVars {
		secretEnvVars = append(secretEnvVars, corev1.EnvVar{
			Name: dbVar.envName,
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-database-secret", instance.Name),
					},
					Key: dbVar.secretKey,
				},
			},
		})
	}
	
	// Cache secrets
	cacheSecretVars := []struct {
		envName   string
		secretKey string
	}{
		{"QUEUE_BULL_REDIS_HOST", "redis-host"},
		{"QUEUE_BULL_REDIS_PORT", "redis-port"},
		{"QUEUE_BULL_REDIS_PASSWORD", "redis-password"},
	}
	
	for _, cacheVar := range cacheSecretVars {
		secretEnvVars = append(secretEnvVars, corev1.EnvVar{
			Name: cacheVar.envName,
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-cache-secret", instance.Name),
					},
					Key: cacheVar.secretKey,
				},
			},
		})
	}
	
	// Application secrets
	appSecretVars := []struct {
		envName   string
		secretKey string
	}{
		{"N8N_ENCRYPTION_KEY", "encryption_key"},
		{"N8N_USER_MANAGEMENT_JWT_SECRET", "jwt_secret"},
	}
	
	for _, appVar := range appSecretVars {
		secretEnvVars = append(secretEnvVars, corev1.EnvVar{
			Name: appVar.envName,
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-app-secret", instance.Name),
					},
					Key: appVar.secretKey,
				},
			},
		})
	}
	
	return secretEnvVars
}

// getDeploymentMetrics retrieves deployment metrics
func (m *N8nDeploymentManager) getDeploymentMetrics(ctx context.Context, instance *n8nv1alpha1.N8nInstance) (map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("N8nDeploymentManager")
	logger.Info("Retrieving deployment metrics")

	metrics := make(map[string]interface{})
	
	// Get deployments
	deploymentList := &appsv1.DeploymentList{}
	listOptions := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels{
			"app.kubernetes.io/instance": instance.Name,
		},
	}

	if err := m.client.List(ctx, deploymentList, listOptions...); err != nil {
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}

	deploymentMetrics := make([]map[string]interface{}, 0, len(deploymentList.Items))
	totalReplicas := int32(0)
	readyReplicas := int32(0)
	
	for _, deployment := range deploymentList.Items {
		deploymentMetric := map[string]interface{}{
			"name":      deployment.Name,
			"component": deployment.Labels["app.kubernetes.io/component"],
		}
		
		if deployment.Spec.Replicas != nil {
			deploymentMetric["desired_replicas"] = *deployment.Spec.Replicas
			totalReplicas += *deployment.Spec.Replicas
		}
		
		deploymentMetric["ready_replicas"] = deployment.Status.ReadyReplicas
		deploymentMetric["available_replicas"] = deployment.Status.AvailableReplicas
		deploymentMetric["updated_replicas"] = deployment.Status.UpdatedReplicas
		
		readyReplicas += deployment.Status.ReadyReplicas
		
		// Calculate readiness percentage
		if deployment.Spec.Replicas != nil && *deployment.Spec.Replicas > 0 {
			readinessPercent := float64(deployment.Status.ReadyReplicas) / float64(*deployment.Spec.Replicas) * 100
			deploymentMetric["readiness_percent"] = readinessPercent
		}
		
		deploymentMetrics = append(deploymentMetrics, deploymentMetric)
	}

	metrics["deployments"] = deploymentMetrics
	metrics["total_deployments"] = len(deploymentList.Items)
	metrics["total_desired_replicas"] = totalReplicas
	metrics["total_ready_replicas"] = readyReplicas
	
	if totalReplicas > 0 {
		metrics["overall_readiness_percent"] = float64(readyReplicas) / float64(totalReplicas) * 100
	}

	logger.Info("Deployment metrics retrieved", "totalDeployments", len(deploymentList.Items))
	return metrics, nil
}

// b
uildAdvancedVolumeMounts builds comprehensive volume mounts for a component
func (m *N8nDeploymentManager) buildAdvancedVolumeMounts(instance *n8nv1alpha1.N8nInstance, component string) []corev1.VolumeMount {
	volumeMounts := []corev1.VolumeMount{
		// Configuration mounts
		{
			Name:      "config",
			MountPath: "/home/node/.n8n/config",
			ReadOnly:  true,
		},
		{
			Name:      "component-config",
			MountPath: "/home/node/.n8n/component-config",
			ReadOnly:  true,
		},
		// Temporary directories (writable)
		{
			Name:      "tmp",
			MountPath: "/tmp",
		},
		{
			Name:      "var-tmp",
			MountPath: "/var/tmp",
		},
		{
			Name:      "run",
			MountPath: "/run",
		},
		// Logs directory
		{
			Name:      "logs",
			MountPath: "/home/node/.n8n/logs",
		},
	}

	// Add component-specific volume mounts
	switch component {
	case "main":
		volumeMounts = append(volumeMounts, []corev1.VolumeMount{
			{
				Name:      "main-data",
				MountPath: "/home/node/.n8n/data",
			},
			{
				Name:      "workflows",
				MountPath: "/home/node/.n8n/workflows",
			},
			{
				Name:      "credentials",
				MountPath: "/home/node/.n8n/credentials",
			},
			{
				Name:      "nodes",
				MountPath: "/home/node/.n8n/nodes",
			},
		}...)
	case "webhook":
		volumeMounts = append(volumeMounts, []corev1.VolumeMount{
			{
				Name:      "webhook-data",
				MountPath: "/home/node/.n8n/webhook-data",
			},
			{
				Name:      "webhook-cache",
				MountPath: "/home/node/.n8n/webhook-cache",
			},
		})
	case "worker":
		volumeMounts = append(volumeMounts, []corev1.VolumeMount{
			{
				Name:      "worker-data",
				MountPath: "/home/node/.n8n/worker-data",
			},
			{
				Name:      "execution-data",
				MountPath: "/home/node/.n8n/execution-data",
			},
		})
	}

	return volumeMounts
}

// buildAdvancedVolumes builds comprehensive volumes for a component
func (m *N8nDeploymentManager) buildAdvancedVolumes(instance *n8nv1alpha1.N8nInstance, component string) []corev1.Volume {
	volumes := []corev1.Volume{
		// Configuration volumes
		{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-config", instance.Name),
					},
					DefaultMode: &[]int32{0644}[0],
				},
			},
		},
		{
			Name: "component-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-%s-config", instance.Name, component),
					},
					DefaultMode: &[]int32{0644}[0],
				},
			},
		},
		// Temporary volumes
		{
			Name: "tmp",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					SizeLimit: &[]resource.Quantity{resource.MustParse("1Gi")}[0],
				},
			},
		},
		{
			Name: "var-tmp",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					SizeLimit: &[]resource.Quantity{resource.MustParse("1Gi")}[0],
				},
			},
		},
		{
			Name: "run",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium:    corev1.StorageMediumMemory,
					SizeLimit: &[]resource.Quantity{resource.MustParse("100Mi")}[0],
				},
			},
		},
		// Logs volume
		{
			Name: "logs",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					SizeLimit: &[]resource.Quantity{resource.MustParse("2Gi")}[0],
				},
			},
		},
	}

	// Add component-specific volumes
	componentVolumes := m.getComponentSpecificVolumes(instance, component)
	volumes = append(volumes, componentVolumes...)

	return volumes
}

// getComponentSpecificVolumes returns component-specific volumes
func (m *N8nDeploymentManager) getComponentSpecificVolumes(instance *n8nv1alpha1.N8nInstance, component string) []corev1.Volume {
	switch component {
	case "main":
		return []corev1.Volume{
			{
				Name: "main-data",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: fmt.Sprintf("%s-main-data", instance.Name),
					},
				},
			},
			{
				Name: "workflows",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						SizeLimit: &[]resource.Quantity{resource.MustParse("5Gi")}[0],
					},
				},
			},
			{
				Name: "credentials",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						SizeLimit: &[]resource.Quantity{resource.MustParse("1Gi")}[0],
					},
				},
			},
			{
				Name: "nodes",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						SizeLimit: &[]resource.Quantity{resource.MustParse("2Gi")}[0],
					},
				},
			},
		}
	case "webhook":
		return []corev1.Volume{
			{
				Name: "webhook-data",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: fmt.Sprintf("%s-webhook-data", instance.Name),
					},
				},
			},
			{
				Name: "webhook-cache",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						SizeLimit: &[]resource.Quantity{resource.MustParse("1Gi")}[0],
					},
				},
			},
		}
	case "worker":
		return []corev1.Volume{
			{
				Name: "worker-data",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						SizeLimit: &[]resource.Quantity{resource.MustParse("3Gi")}[0],
					},
				},
			},
			{
				Name: "execution-data",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						SizeLimit: &[]resource.Quantity{resource.MustParse("5Gi")}[0],
					},
				},
			},
		}
	default:
		return []corev1.Volume{}
	}
}

// create
AdvancedHPA creates HPA with custom metrics and advanced scaling policies
func (m *N8nDeploymentManager) createAdvancedHPA(ctx context.Context, instance *n8nv1alpha1.N8nInstance, component string) error {
	logger := log.FromContext(ctx).WithName("N8nDeploymentManager")
	
	hpaName := fmt.Sprintf("%s-%s-hpa", instance.Name, component)
	deploymentName := fmt.Sprintf("%s-%s", instance.Name, component)
	logger.Info("Creating advanced HPA", "name", hpaName, "component", component)

	// Get component-specific scaling configuration
	scalingConfig := m.getComponentScalingConfig(component)

	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      hpaName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  component,
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       deploymentName,
			},
			MinReplicas: &scalingConfig.minReplicas,
			MaxReplicas: scalingConfig.maxReplicas,
			Metrics:     m.buildHPAMetrics(component, scalingConfig),
			Behavior:    m.buildHPABehavior(component, scalingConfig),
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, hpa, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return m.createOrUpdateResource(ctx, hpa, "HPA")
}

// ComponentScalingConfig holds scaling configuration for a component
type ComponentScalingConfig struct {
	minReplicas    int32
	maxReplicas    int32
	targetCPU      int32
	targetMemory   int32
	scaleUpPolicy  ScalingPolicy
	scaleDownPolicy ScalingPolicy
}

// ScalingPolicy holds scaling policy configuration
type ScalingPolicy struct {
	stabilizationWindow int32
	maxChangePercent    int32
	maxChangePods       int32
	periodSeconds       int32
}

// getComponentScalingConfig returns scaling configuration for a component
func (m *N8nDeploymentManager) getComponentScalingConfig(component string) ComponentScalingConfig {
	switch component {
	case "main":
		return ComponentScalingConfig{
			minReplicas:  1,
			maxReplicas:  5,
			targetCPU:    70,
			targetMemory: 80,
			scaleUpPolicy: ScalingPolicy{
				stabilizationWindow: 60,
				maxChangePercent:    50,
				maxChangePods:       2,
				periodSeconds:       60,
			},
			scaleDownPolicy: ScalingPolicy{
				stabilizationWindow: 300,
				maxChangePercent:    25,
				maxChangePods:       1,
				periodSeconds:       60,
			},
		}
	case "webhook":
		return ComponentScalingConfig{
			minReplicas:  2,
			maxReplicas:  10,
			targetCPU:    60,
			targetMemory: 70,
			scaleUpPolicy: ScalingPolicy{
				stabilizationWindow: 30,
				maxChangePercent:    100,
				maxChangePods:       4,
				periodSeconds:       30,
			},
			scaleDownPolicy: ScalingPolicy{
				stabilizationWindow: 180,
				maxChangePercent:    50,
				maxChangePods:       2,
				periodSeconds:       60,
			},
		}
	case "worker":
		return ComponentScalingConfig{
			minReplicas:  3,
			maxReplicas:  20,
			targetCPU:    80,
			targetMemory: 85,
			scaleUpPolicy: ScalingPolicy{
				stabilizationWindow: 45,
				maxChangePercent:    100,
				maxChangePods:       5,
				periodSeconds:       30,
			},
			scaleDownPolicy: ScalingPolicy{
				stabilizationWindow: 300,
				maxChangePercent:    25,
				maxChangePods:       2,
				periodSeconds:       60,
			},
		}
	default:
		return ComponentScalingConfig{
			minReplicas:  1,
			maxReplicas:  3,
			targetCPU:    70,
			targetMemory: 80,
			scaleUpPolicy: ScalingPolicy{
				stabilizationWindow: 60,
				maxChangePercent:    50,
				maxChangePods:       1,
				periodSeconds:       60,
			},
			scaleDownPolicy: ScalingPolicy{
				stabilizationWindow: 300,
				maxChangePercent:    25,
				maxChangePods:       1,
				periodSeconds:       60,
			},
		}
	}
}

// buildHPAMetrics builds HPA metrics configuration
func (m *N8nDeploymentManager) buildHPAMetrics(component string, config ComponentScalingConfig) []autoscalingv2.MetricSpec {
	metrics := []autoscalingv2.MetricSpec{
		// CPU utilization
		{
			Type: autoscalingv2.ResourceMetricSourceType,
			Resource: &autoscalingv2.ResourceMetricSource{
				Name: corev1.ResourceCPU,
				Target: autoscalingv2.MetricTarget{
					Type:               autoscalingv2.UtilizationMetricType,
					AverageUtilization: &config.targetCPU,
				},
			},
		},
		// Memory utilization
		{
			Type: autoscalingv2.ResourceMetricSourceType,
			Resource: &autoscalingv2.ResourceMetricSource{
				Name: corev1.ResourceMemory,
				Target: autoscalingv2.MetricTarget{
					Type:               autoscalingv2.UtilizationMetricType,
					AverageUtilization: &config.targetMemory,
				},
			},
		},
	}

	// Add component-specific metrics
	switch component {
	case "webhook":
		// Add request rate metric for webhook component
		metrics = append(metrics, autoscalingv2.MetricSpec{
			Type: autoscalingv2.PodsMetricSourceType,
			Pods: &autoscalingv2.PodsMetricSource{
				Metric: autoscalingv2.MetricIdentifier{
					Name: "http_requests_per_second",
				},
				Target: autoscalingv2.MetricTarget{
					Type:         autoscalingv2.AverageValueMetricType,
					AverageValue: &[]resource.Quantity{resource.MustParse("100")}[0],
				},
			},
		})
	case "worker":
		// Add queue length metric for worker component
		metrics = append(metrics, autoscalingv2.MetricSpec{
			Type: autoscalingv2.ExternalMetricSourceType,
			External: &autoscalingv2.ExternalMetricSource{
				Metric: autoscalingv2.MetricIdentifier{
					Name: "redis_queue_length",
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"queue": "n8n-executions",
						},
					},
				},
				Target: autoscalingv2.MetricTarget{
					Type:         autoscalingv2.AverageValueMetricType,
					AverageValue: &[]resource.Quantity{resource.MustParse("10")}[0],
				},
			},
		})
	}

	return metrics
}

// buildHPABehavior builds HPA behavior configuration
func (m *N8nDeploymentManager) buildHPABehavior(component string, config ComponentScalingConfig) *autoscalingv2.HorizontalPodAutoscalerBehavior {
	return &autoscalingv2.HorizontalPodAutoscalerBehavior{
		ScaleUp: &autoscalingv2.HPAScalingRules{
			StabilizationWindowSeconds: &config.scaleUpPolicy.stabilizationWindow,
			SelectPolicy:               &[]autoscalingv2.ScalingPolicySelect{autoscalingv2.MaxPolicySelect}[0],
			Policies: []autoscalingv2.HPAScalingPolicy{
				{
					Type:          autoscalingv2.PercentScalingPolicy,
					Value:         config.scaleUpPolicy.maxChangePercent,
					PeriodSeconds: config.scaleUpPolicy.periodSeconds,
				},
				{
					Type:          autoscalingv2.PodsScalingPolicy,
					Value:         config.scaleUpPolicy.maxChangePods,
					PeriodSeconds: config.scaleUpPolicy.periodSeconds,
				},
			},
		},
		ScaleDown: &autoscalingv2.HPAScalingRules{
			StabilizationWindowSeconds: &config.scaleDownPolicy.stabilizationWindow,
			SelectPolicy:               &[]autoscalingv2.ScalingPolicySelect{autoscalingv2.MinPolicySelect}[0],
			Policies: []autoscalingv2.HPAScalingPolicy{
				{
					Type:          autoscalingv2.PercentScalingPolicy,
					Value:         config.scaleDownPolicy.maxChangePercent,
					PeriodSeconds: config.scaleDownPolicy.periodSeconds,
				},
				{
					Type:          autoscalingv2.PodsScalingPolicy,
					Value:         config.scaleDownPolicy.maxChangePods,
					PeriodSeconds: config.scaleDownPolicy.periodSeconds,
				},
			},
		},
	}
}

// createOrUpdateResource creates or updates a Kubernetes resource
func (m *N8nDeploymentManager) createOrUpdateResource(ctx context.Context, obj client.Object, resourceType string) error {
	logger := log.FromContext(ctx).WithName("N8nDeploymentManager")
	
	name := obj.GetName()
	namespace := obj.GetNamespace()
	
	logger.Info("Creating or updating resource", "type", resourceType, "name", name, "namespace", namespace)

	// Try to get existing resource
	existing := obj.DeepCopyObject().(client.Object)
	objKey := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}

	if err := m.client.Get(ctx, objKey, existing); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing %s: %w", resourceType, err)
		}
		// Resource doesn't exist, create it
		if err := m.client.Create(ctx, obj); err != nil {
			return fmt.Errorf("failed to create %s: %w", resourceType, err)
		}
		logger.Info("Resource created successfully", "type", resourceType, "name", name)
	} else {
		// Resource exists, update it
		obj.SetResourceVersion(existing.GetResourceVersion())
		if err := m.client.Update(ctx, obj); err != nil {
			return fmt.Errorf("failed to update %s: %w", resourceType, err)
		}
		logger.Info("Resource updated successfully", "type", resourceType, "name", name)
	}

	return nil
}