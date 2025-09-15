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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// MonitoringManagerImpl implements the MonitoringManager interface
type MonitoringManagerImpl struct {
	client               client.Client
	scheme               *runtime.Scheme
	logger               logr.Logger
	cloudWatchClient     *cloudwatch.Client
	cloudWatchLogsClient *cloudwatchlogs.Client
	snsClient            *sns.Client
}

// NewMonitoringManager creates a new MonitoringManager instance
func NewMonitoringManager(client client.Client, scheme *runtime.Scheme, logger logr.Logger) MonitoringManager {
	// Initialize AWS config
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		logger.Error(err, "Failed to load AWS config")
		// Continue without AWS clients - they will be nil and CloudWatch features will be disabled
	}

	var cloudWatchClient *cloudwatch.Client
	var cloudWatchLogsClient *cloudwatchlogs.Client
	var snsClient *sns.Client

	if err == nil {
		cloudWatchClient = cloudwatch.NewFromConfig(cfg)
		cloudWatchLogsClient = cloudwatchlogs.NewFromConfig(cfg)
		snsClient = sns.NewFromConfig(cfg)
	}

	return &MonitoringManagerImpl{
		client:               client,
		scheme:               scheme,
		logger:               logger,
		cloudWatchClient:     cloudWatchClient,
		cloudWatchLogsClient: cloudWatchLogsClient,
		snsClient:            snsClient,
	}
}

// MonitoringConfig holds monitoring configuration
type MonitoringConfig struct {
	Metrics MetricsConfig
	Logging LoggingConfig
	Alerts  AlertsConfig
}

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Enabled    bool
	Prometheus PrometheusConfig
	CloudWatch CloudWatchConfig
}

// PrometheusConfig holds Prometheus configuration
type PrometheusConfig struct {
	Enabled        bool
	ServiceMonitor bool
	Port           int32
	Path           string
	Interval       string
}

// CloudWatchConfig holds CloudWatch configuration
type CloudWatchConfig struct {
	Enabled   bool
	Namespace string
	Region    string
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level      string
	CloudWatch CloudWatchLogsConfig
}

// CloudWatchLogsConfig holds CloudWatch logs configuration
type CloudWatchLogsConfig struct {
	Enabled   bool
	LogGroup  string
	Retention int32
}

// AlertsConfig holds alerts configuration
type AlertsConfig struct {
	Enabled bool
	SNS     SNSConfig
	Rules   []AlertRule
}

// SNSConfig holds SNS configuration
type SNSConfig struct {
	TopicArn string
	Region   string
}

// AlertRule holds alert rule configuration
type AlertRule struct {
	Name      string
	Condition string
	Threshold string
	Severity  string
}

// ReconcileMonitoring ensures all monitoring configurations are correct
func (m *MonitoringManagerImpl) ReconcileMonitoring(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	m.logger.Info("Reconciling monitoring for N8nInstance", "instance", instance.Name)

	// Extract monitoring configuration from instance
	config := m.extractMonitoringConfig(instance)

	// Reconcile Prometheus monitoring if enabled
	if config.Metrics.Enabled && config.Metrics.Prometheus.Enabled {
		if err := m.ReconcilePrometheusMonitoring(ctx, instance); err != nil {
			m.logger.Error(err, "Failed to reconcile Prometheus monitoring", "instance", instance.Name)
			return fmt.Errorf("failed to reconcile Prometheus monitoring: %w", err)
		}
	}

	// Reconcile CloudWatch monitoring if enabled
	if config.Metrics.Enabled && config.Metrics.CloudWatch.Enabled {
		if err := m.ReconcileCloudWatchMonitoring(ctx, instance); err != nil {
			m.logger.Error(err, "Failed to reconcile CloudWatch monitoring", "instance", instance.Name)
			return fmt.Errorf("failed to reconcile CloudWatch monitoring: %w", err)
		}
	}

	// Reconcile alerts if enabled
	if config.Alerts.Enabled {
		if err := m.ReconcileAlerts(ctx, instance); err != nil {
			m.logger.Error(err, "Failed to reconcile alerts", "instance", instance.Name)
			return fmt.Errorf("failed to reconcile alerts: %w", err)
		}
	}

	m.logger.Info("Successfully reconciled monitoring for N8nInstance", "instance", instance.Name)
	return nil
}

// ReconcilePrometheusMonitoring creates Prometheus monitoring resources
func (m *MonitoringManagerImpl) ReconcilePrometheusMonitoring(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	m.logger.Info("Reconciling Prometheus monitoring for N8nInstance", "instance", instance.Name)

	config := m.extractMonitoringConfig(instance)

	// Create metrics services for each component
	components := []string{"main", "webhook", "worker"}
	for _, component := range components {
		if err := m.reconcileMetricsService(ctx, instance, component, config); err != nil {
			return fmt.Errorf("failed to reconcile metrics service for %s: %w", component, err)
		}
	}

	// Create ServiceMonitor if enabled
	if config.Metrics.Prometheus.ServiceMonitor {
		if err := m.reconcileServiceMonitor(ctx, instance, config); err != nil {
			return fmt.Errorf("failed to reconcile ServiceMonitor: %w", err)
		}
	}

	// Create Grafana dashboard ConfigMap
	if err := m.reconcileGrafanaDashboard(ctx, instance); err != nil {
		return fmt.Errorf("failed to reconcile Grafana dashboard: %w", err)
	}

	m.logger.Info("Successfully reconciled Prometheus monitoring", "instance", instance.Name)
	return nil
}

// ReconcileCloudWatchMonitoring creates CloudWatch monitoring resources
func (m *MonitoringManagerImpl) ReconcileCloudWatchMonitoring(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	m.logger.Info("Reconciling CloudWatch monitoring for N8nInstance", "instance", instance.Name)

	if m.cloudWatchClient == nil || m.cloudWatchLogsClient == nil {
		m.logger.Info("CloudWatch clients not available, skipping CloudWatch monitoring")
		return nil
	}

	config := m.extractMonitoringConfig(instance)

	// Create CloudWatch Log Group
	if config.Logging.CloudWatch.Enabled {
		if err := m.reconcileCloudWatchLogGroup(ctx, instance, config); err != nil {
			return fmt.Errorf("failed to reconcile CloudWatch log group: %w", err)
		}
	}

	// Create CloudWatch custom metrics
	if config.Metrics.CloudWatch.Enabled {
		if err := m.reconcileCloudWatchMetrics(ctx, instance, config); err != nil {
			return fmt.Errorf("failed to reconcile CloudWatch metrics: %w", err)
		}
	}

	// Create CloudWatch dashboard
	if config.Metrics.CloudWatch.Enabled {
		if err := m.reconcileCloudWatchDashboard(ctx, instance, config); err != nil {
			return fmt.Errorf("failed to reconcile CloudWatch dashboard: %w", err)
		}
	}

	m.logger.Info("Successfully reconciled CloudWatch monitoring", "instance", instance.Name)
	return nil
}

// ReconcileAlerts creates and manages alert rules
func (m *MonitoringManagerImpl) ReconcileAlerts(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	m.logger.Info("Reconciling alerts for N8nInstance", "instance", instance.Name)

	if m.cloudWatchClient == nil || m.snsClient == nil {
		m.logger.Info("CloudWatch or SNS clients not available, skipping alerts")
		return nil
	}

	config := m.extractMonitoringConfig(instance)

	// Validate SNS topic exists
	if config.Alerts.SNS.TopicArn != "" {
		if err := m.validateSNSTopic(ctx, config.Alerts.SNS.TopicArn); err != nil {
			return fmt.Errorf("failed to validate SNS topic: %w", err)
		}
	}

	// Create CloudWatch alarms
	if err := m.reconcileCloudWatchAlarms(ctx, instance, config); err != nil {
		return fmt.Errorf("failed to reconcile CloudWatch alarms: %w", err)
	}

	// Create Prometheus alert rules ConfigMap
	if err := m.reconcilePrometheusAlertRules(ctx, instance, config); err != nil {
		return fmt.Errorf("failed to reconcile Prometheus alert rules: %w", err)
	}

	m.logger.Info("Successfully reconciled alerts", "instance", instance.Name)
	return nil
}

// extractMonitoringConfig extracts monitoring configuration from N8nInstance
func (m *MonitoringManagerImpl) extractMonitoringConfig(instance *n8nv1alpha1.N8nInstance) MonitoringConfig {
	config := MonitoringConfig{
		Metrics: MetricsConfig{
			Enabled: true, // Default enabled
			Prometheus: PrometheusConfig{
				Enabled:        true,
				ServiceMonitor: true,
				Port:           9090,
				Path:           "/metrics",
				Interval:       "30s",
			},
			CloudWatch: CloudWatchConfig{
				Enabled:   false,
				Namespace: "N8N/EKS",
				Region:    "us-west-2", // Default region
			},
		},
		Logging: LoggingConfig{
			Level: "info",
			CloudWatch: CloudWatchLogsConfig{
				Enabled:   false,
				LogGroup:  fmt.Sprintf("/aws/eks/n8n/%s", instance.Name),
				Retention: 30,
			},
		},
		Alerts: AlertsConfig{
			Enabled: false,
			SNS: SNSConfig{
				TopicArn: "",
				Region:   "us-west-2",
			},
			Rules: []AlertRule{},
		},
	}

	// Override with instance-specific configuration if available
	if instance.Spec.Monitoring != nil {
		if instance.Spec.Monitoring.Metrics != nil {
			config.Metrics.Enabled = instance.Spec.Monitoring.Metrics.Enabled

			if instance.Spec.Monitoring.Metrics.Prometheus != nil {
				config.Metrics.Prometheus.Enabled = instance.Spec.Monitoring.Metrics.Prometheus.Enabled
				config.Metrics.Prometheus.ServiceMonitor = instance.Spec.Monitoring.Metrics.Prometheus.ServiceMonitor
			}

			if instance.Spec.Monitoring.Metrics.CloudWatch != nil {
				config.Metrics.CloudWatch.Enabled = instance.Spec.Monitoring.Metrics.CloudWatch.Enabled
				if instance.Spec.Monitoring.Metrics.CloudWatch.Namespace != "" {
					config.Metrics.CloudWatch.Namespace = instance.Spec.Monitoring.Metrics.CloudWatch.Namespace
				}
			}
		}

		if instance.Spec.Monitoring.Logging != nil {
			if instance.Spec.Monitoring.Logging.Level != "" {
				config.Logging.Level = instance.Spec.Monitoring.Logging.Level
			}

			if instance.Spec.Monitoring.Logging.CloudWatch != nil {
				config.Logging.CloudWatch.Enabled = instance.Spec.Monitoring.Logging.CloudWatch.Enabled
				if instance.Spec.Monitoring.Logging.CloudWatch.LogGroup != "" {
					config.Logging.CloudWatch.LogGroup = instance.Spec.Monitoring.Logging.CloudWatch.LogGroup
				}
				if instance.Spec.Monitoring.Logging.CloudWatch.Retention > 0 {
					config.Logging.CloudWatch.Retention = instance.Spec.Monitoring.Logging.CloudWatch.Retention
				}
			}
		}

		if instance.Spec.Monitoring.Alerts != nil {
			config.Alerts.Enabled = instance.Spec.Monitoring.Alerts.Enabled

			if instance.Spec.Monitoring.Alerts.SNS != nil {
				config.Alerts.SNS.TopicArn = instance.Spec.Monitoring.Alerts.SNS.TopicArn
			}
		}
	}

	return config
}

// reconcileMetricsService creates a metrics service for a component
func (m *MonitoringManagerImpl) reconcileMetricsService(ctx context.Context, instance *n8nv1alpha1.N8nInstance, component string, config MonitoringConfig) error {
	serviceName := fmt.Sprintf("%s-%s-metrics", instance.Name, component)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  component,
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"app.kubernetes.io/part-of":    "n8n",
				"monitoring":                   "prometheus",
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       "metrics",
					Port:       config.Metrics.Prometheus.Port,
					TargetPort: intstr.FromString("metrics"),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			Selector: map[string]string{
				"app.kubernetes.io/name":      "n8n",
				"app.kubernetes.io/instance":  instance.Name,
				"app.kubernetes.io/component": component,
			},
		},
	}

	// Set owner reference
	if err := controllerutil.SetControllerReference(instance, service, m.scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update the service
	existingService := &corev1.Service{}
	err := m.client.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: instance.Namespace}, existingService)
	if err != nil {
		if errors.IsNotFound(err) {
			m.logger.Info("Creating metrics service", "service", serviceName, "component", component)
			if err := m.client.Create(ctx, service); err != nil {
				return fmt.Errorf("failed to create metrics service: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get metrics service: %w", err)
		}
	} else {
		// Update existing service
		existingService.Spec = service.Spec
		existingService.Labels = service.Labels
		m.logger.Info("Updating metrics service", "service", serviceName, "component", component)
		if err := m.client.Update(ctx, existingService); err != nil {
			return fmt.Errorf("failed to update metrics service: %w", err)
		}
	}

	return nil
}

// reconcileServiceMonitor creates a ServiceMonitor for Prometheus
func (m *MonitoringManagerImpl) reconcileServiceMonitor(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config MonitoringConfig) error {
	serviceMonitorName := fmt.Sprintf("%s-servicemonitor", instance.Name)

	// Create ServiceMonitor as a ConfigMap since we don't have the Prometheus Operator CRDs
	// In a real deployment, this would be a proper ServiceMonitor CRD
	serviceMonitorData := fmt.Sprintf(`apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/name: n8n
    app.kubernetes.io/instance: %s
    app.kubernetes.io/managed-by: n8n-eks-operator
spec:
  selector:
    matchLabels:
      monitoring: prometheus
  endpoints:
  - port: metrics
    path: %s
    interval: %s
    scrapeTimeout: 10s
  - port: metrics
    path: /health
    interval: 30s
    scrapeTimeout: 5s
  namespaceSelector:
    matchNames:
    - %s`, serviceMonitorName, instance.Namespace, instance.Name, config.Metrics.Prometheus.Path, config.Metrics.Prometheus.Interval, instance.Namespace)

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceMonitorName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"app.kubernetes.io/part-of":    "n8n",
				"monitoring":                   "servicemonitor",
			},
		},
		Data: map[string]string{
			"servicemonitor.yaml": serviceMonitorData,
		},
	}

	// Set owner reference
	if err := controllerutil.SetControllerReference(instance, configMap, m.scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update the ConfigMap
	existingConfigMap := &corev1.ConfigMap{}
	err := m.client.Get(ctx, types.NamespacedName{Name: serviceMonitorName, Namespace: instance.Namespace}, existingConfigMap)
	if err != nil {
		if errors.IsNotFound(err) {
			m.logger.Info("Creating ServiceMonitor ConfigMap", "configmap", serviceMonitorName)
			if err := m.client.Create(ctx, configMap); err != nil {
				return fmt.Errorf("failed to create ServiceMonitor ConfigMap: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get ServiceMonitor ConfigMap: %w", err)
		}
	} else {
		// Update existing ConfigMap
		existingConfigMap.Data = configMap.Data
		existingConfigMap.Labels = configMap.Labels
		m.logger.Info("Updating ServiceMonitor ConfigMap", "configmap", serviceMonitorName)
		if err := m.client.Update(ctx, existingConfigMap); err != nil {
			return fmt.Errorf("failed to update ServiceMonitor ConfigMap: %w", err)
		}
	}

	return nil
}

// reconcileGrafanaDashboard creates a Grafana dashboard ConfigMap
func (m *MonitoringManagerImpl) reconcileGrafanaDashboard(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	dashboardName := fmt.Sprintf("%s-grafana-dashboard", instance.Name)

	// Create a comprehensive Grafana dashboard for n8n monitoring
	dashboardJSON := fmt.Sprintf(`{
  "dashboard": {
    "id": null,
    "title": "n8n Instance - %s",
    "tags": ["n8n", "eks", "kubernetes"],
    "style": "dark",
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "n8n Main Component - CPU Usage",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(container_cpu_usage_seconds_total{pod=~\"%s-main-.*\"}[5m]) * 100",
            "legendFormat": "CPU Usage %%"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "percent",
            "min": 0,
            "max": 100
          }
        },
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
      },
      {
        "id": 2,
        "title": "n8n Main Component - Memory Usage",
        "type": "stat",
        "targets": [
          {
            "expr": "container_memory_usage_bytes{pod=~\"%s-main-.*\"} / container_spec_memory_limit_bytes{pod=~\"%s-main-.*\"} * 100",
            "legendFormat": "Memory Usage %%"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "percent",
            "min": 0,
            "max": 100
          }
        },
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
      },
      {
        "id": 3,
        "title": "n8n Webhook Component - Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total{pod=~\"%s-webhook-.*\"}[5m])",
            "legendFormat": "Requests/sec"
          }
        ],
        "yAxes": [
          {
            "label": "Requests per second",
            "min": 0
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
      },
      {
        "id": 4,
        "title": "n8n Worker Component - Queue Length",
        "type": "graph",
        "targets": [
          {
            "expr": "n8n_queue_length{pod=~\"%s-worker-.*\"}",
            "legendFormat": "Queue Length"
          }
        ],
        "yAxes": [
          {
            "label": "Queue Items",
            "min": 0
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8}
      },
      {
        "id": 5,
        "title": "Database Connection Pool",
        "type": "graph",
        "targets": [
          {
            "expr": "n8n_db_connections_active{instance=\"%s\"}",
            "legendFormat": "Active Connections"
          },
          {
            "expr": "n8n_db_connections_idle{instance=\"%s\"}",
            "legendFormat": "Idle Connections"
          }
        ],
        "yAxes": [
          {
            "label": "Connections",
            "min": 0
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16}
      },
      {
        "id": 6,
        "title": "Redis Cache Hit Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "n8n_cache_hit_rate{instance=\"%s\"} * 100",
            "legendFormat": "Cache Hit Rate %%"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "percent",
            "min": 0,
            "max": 100
          }
        },
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16}
      },
      {
        "id": 7,
        "title": "Workflow Execution Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(n8n_workflow_executions_total{instance=\"%s\"}[5m])",
            "legendFormat": "Executions/sec"
          }
        ],
        "yAxes": [
          {
            "label": "Executions per second",
            "min": 0
          }
        ],
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 24}
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "30s"
  }
}`, instance.Name, instance.Name, instance.Name, instance.Name, instance.Name, instance.Name, instance.Name, instance.Name, instance.Name, instance.Name)

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      dashboardName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"app.kubernetes.io/part-of":    "n8n",
				"grafana_dashboard":            "1",
			},
		},
		Data: map[string]string{
			"n8n-dashboard.json": dashboardJSON,
		},
	}

	// Set owner reference
	if err := controllerutil.SetControllerReference(instance, configMap, m.scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update the ConfigMap
	existingConfigMap := &corev1.ConfigMap{}
	err := m.client.Get(ctx, types.NamespacedName{Name: dashboardName, Namespace: instance.Namespace}, existingConfigMap)
	if err != nil {
		if errors.IsNotFound(err) {
			m.logger.Info("Creating Grafana dashboard ConfigMap", "configmap", dashboardName)
			if err := m.client.Create(ctx, configMap); err != nil {
				return fmt.Errorf("failed to create Grafana dashboard ConfigMap: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get Grafana dashboard ConfigMap: %w", err)
		}
	} else {
		// Update existing ConfigMap
		existingConfigMap.Data = configMap.Data
		existingConfigMap.Labels = configMap.Labels
		m.logger.Info("Updating Grafana dashboard ConfigMap", "configmap", dashboardName)
		if err := m.client.Update(ctx, existingConfigMap); err != nil {
			return fmt.Errorf("failed to update Grafana dashboard ConfigMap: %w", err)
		}
	}

	return nil
}

// reconcileCloudWatchLogGroup creates or updates CloudWatch log group
func (m *MonitoringManagerImpl) reconcileCloudWatchLogGroup(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config MonitoringConfig) error {
	logGroupName := config.Logging.CloudWatch.LogGroup

	// Check if log group exists
	_, err := m.cloudWatchLogsClient.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: aws.String(logGroupName),
	})

	if err != nil {
		// Create log group if it doesn't exist
		m.logger.Info("Creating CloudWatch log group", "logGroup", logGroupName)
		_, err = m.cloudWatchLogsClient.CreateLogGroup(ctx, &cloudwatchlogs.CreateLogGroupInput{
			LogGroupName: aws.String(logGroupName),
		})
		if err != nil {
			return fmt.Errorf("failed to create CloudWatch log group: %w", err)
		}
	}

	// Set retention policy
	if config.Logging.CloudWatch.Retention > 0 {
		_, err = m.cloudWatchLogsClient.PutRetentionPolicy(ctx, &cloudwatchlogs.PutRetentionPolicyInput{
			LogGroupName:    aws.String(logGroupName),
			RetentionInDays: aws.Int32(config.Logging.CloudWatch.Retention),
		})
		if err != nil {
			m.logger.Error(err, "Failed to set retention policy for log group", "logGroup", logGroupName)
			// Don't fail the reconciliation for retention policy errors
		}
	}

	return nil
}

// reconcileCloudWatchMetrics creates custom CloudWatch metrics
func (m *MonitoringManagerImpl) reconcileCloudWatchMetrics(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config MonitoringConfig) error {
	namespace := config.Metrics.CloudWatch.Namespace

	// Create sample custom metrics for n8n
	metrics := []types.MetricDatum{
		{
			MetricName: aws.String("InstanceStatus"),
			Dimensions: []types.Dimension{
				{
					Name:  aws.String("InstanceName"),
					Value: aws.String(instance.Name),
				},
				{
					Name:  aws.String("Namespace"),
					Value: aws.String(instance.Namespace),
				},
			},
			Value:     aws.Float64(1.0), // 1 = healthy, 0 = unhealthy
			Unit:      types.StandardUnitCount,
			Timestamp: aws.Time(time.Now()),
		},
		{
			MetricName: aws.String("ComponentsReady"),
			Dimensions: []types.Dimension{
				{
					Name:  aws.String("InstanceName"),
					Value: aws.String(instance.Name),
				},
				{
					Name:  aws.String("Namespace"),
					Value: aws.String(instance.Namespace),
				},
			},
			Value:     aws.Float64(3.0), // Number of ready components (main, webhook, worker)
			Unit:      types.StandardUnitCount,
			Timestamp: aws.Time(time.Now()),
		},
	}

	// Put metrics to CloudWatch
	_, err := m.cloudWatchClient.PutMetricData(ctx, &cloudwatch.PutMetricDataInput{
		Namespace:  aws.String(namespace),
		MetricData: metrics,
	})
	if err != nil {
		return fmt.Errorf("failed to put metrics to CloudWatch: %w", err)
	}

	m.logger.Info("Successfully published custom metrics to CloudWatch", "namespace", namespace, "instance", instance.Name)
	return nil
}

// reconcileCloudWatchDashboard creates CloudWatch dashboard
func (m *MonitoringManagerImpl) reconcileCloudWatchDashboard(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config MonitoringConfig) error {
	dashboardName := fmt.Sprintf("n8n-instance-%s", instance.Name)
	namespace := config.Metrics.CloudWatch.Namespace

	// Create dashboard body JSON
	dashboardBody := fmt.Sprintf(`{
    "widgets": [
        {
            "type": "metric",
            "x": 0,
            "y": 0,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "%s", "InstanceStatus", "InstanceName", "%s", "Namespace", "%s" ],
                    [ ".", "ComponentsReady", ".", ".", ".", "." ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "%s",
                "title": "n8n Instance Health",
                "period": 300
            }
        },
        {
            "type": "metric",
            "x": 12,
            "y": 0,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/EKS", "cluster_failed_request_count", "ClusterName", "%s" ],
                    [ ".", "cluster_request_total", ".", "." ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "%s",
                "title": "EKS Cluster Metrics",
                "period": 300
            }
        },
        {
            "type": "log",
            "x": 0,
            "y": 6,
            "width": 24,
            "height": 6,
            "properties": {
                "query": "SOURCE '%s' | fields @timestamp, @message\n| filter @message like /ERROR/\n| sort @timestamp desc\n| limit 100",
                "region": "%s",
                "title": "Recent Errors",
                "view": "table"
            }
        }
    ]
}`, namespace, instance.Name, instance.Namespace, config.Metrics.CloudWatch.Region,
		instance.Name, config.Metrics.CloudWatch.Region, config.Logging.CloudWatch.LogGroup, config.Metrics.CloudWatch.Region)

	// Create or update dashboard
	_, err := m.cloudWatchClient.PutDashboard(ctx, &cloudwatch.PutDashboardInput{
		DashboardName: aws.String(dashboardName),
		DashboardBody: aws.String(dashboardBody),
	})
	if err != nil {
		return fmt.Errorf("failed to create CloudWatch dashboard: %w", err)
	}

	m.logger.Info("Successfully created CloudWatch dashboard", "dashboard", dashboardName, "instance", instance.Name)
	return nil
}

// validateSNSTopic validates that the SNS topic exists and is accessible
func (m *MonitoringManagerImpl) validateSNSTopic(ctx context.Context, topicArn string) error {
	_, err := m.snsClient.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
		TopicArn: aws.String(topicArn),
	})
	if err != nil {
		return fmt.Errorf("SNS topic %s is not accessible: %w", topicArn, err)
	}
	return nil
}

// reconcileCloudWatchAlarms creates CloudWatch alarms for n8n monitoring
func (m *MonitoringManagerImpl) reconcileCloudWatchAlarms(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config MonitoringConfig) error {
	namespace := config.Metrics.CloudWatch.Namespace

	// Define critical alarms for n8n
	alarms := []struct {
		name        string
		description string
		metricName  string
		threshold   float64
		comparison  types.ComparisonOperator
		severity    string
	}{
		{
			name:        fmt.Sprintf("%s-instance-unhealthy", instance.Name),
			description: "n8n instance is unhealthy",
			metricName:  "InstanceStatus",
			threshold:   1.0,
			comparison:  types.ComparisonOperatorLessThanThreshold,
			severity:    "critical",
		},
		{
			name:        fmt.Sprintf("%s-components-not-ready", instance.Name),
			description: "n8n components are not ready",
			metricName:  "ComponentsReady",
			threshold:   3.0,
			comparison:  types.ComparisonOperatorLessThanThreshold,
			severity:    "warning",
		},
		{
			name:        fmt.Sprintf("%s-high-cpu-usage", instance.Name),
			description: "n8n instance high CPU usage",
			metricName:  "CPUUtilization",
			threshold:   80.0,
			comparison:  types.ComparisonOperatorGreaterThanThreshold,
			severity:    "warning",
		},
		{
			name:        fmt.Sprintf("%s-high-memory-usage", instance.Name),
			description: "n8n instance high memory usage",
			metricName:  "MemoryUtilization",
			threshold:   85.0,
			comparison:  types.ComparisonOperatorGreaterThanThreshold,
			severity:    "warning",
		},
	}

	for _, alarm := range alarms {
		alarmInput := &cloudwatch.PutMetricAlarmInput{
			AlarmName:          aws.String(alarm.name),
			AlarmDescription:   aws.String(alarm.description),
			MetricName:         aws.String(alarm.metricName),
			Namespace:          aws.String(namespace),
			Statistic:          types.StatisticAverage,
			Period:             aws.Int32(300), // 5 minutes
			EvaluationPeriods:  aws.Int32(2),
			Threshold:          aws.Float64(alarm.threshold),
			ComparisonOperator: alarm.comparison,
			Dimensions: []types.Dimension{
				{
					Name:  aws.String("InstanceName"),
					Value: aws.String(instance.Name),
				},
				{
					Name:  aws.String("Namespace"),
					Value: aws.String(instance.Namespace),
				},
			},
			TreatMissingData: aws.String("breaching"),
		}

		// Add SNS action if configured
		if config.Alerts.SNS.TopicArn != "" {
			alarmInput.AlarmActions = []string{config.Alerts.SNS.TopicArn}
			alarmInput.OKActions = []string{config.Alerts.SNS.TopicArn}
		}

		_, err := m.cloudWatchClient.PutMetricAlarm(ctx, alarmInput)
		if err != nil {
			m.logger.Error(err, "Failed to create CloudWatch alarm", "alarm", alarm.name)
			return fmt.Errorf("failed to create CloudWatch alarm %s: %w", alarm.name, err)
		}

		m.logger.Info("Created CloudWatch alarm", "alarm", alarm.name, "severity", alarm.severity)
	}

	return nil
}

// reconcilePrometheusAlertRules creates Prometheus alert rules ConfigMap
func (m *MonitoringManagerImpl) reconcilePrometheusAlertRules(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config MonitoringConfig) error {
	alertRulesName := fmt.Sprintf("%s-prometheus-alerts", instance.Name)

	// Create Prometheus alert rules YAML
	alertRulesYAML := fmt.Sprintf(`groups:
- name: n8n-instance-%s
  rules:
  - alert: N8nInstanceDown
    expr: up{job="n8n-main", instance="%s"} == 0
    for: 5m
    labels:
      severity: critical
      instance: %s
      component: main
    annotations:
      summary: "n8n main component is down"
      description: "n8n main component for instance {{ $labels.instance }} has been down for more than 5 minutes."
      
  - alert: N8nWebhookDown
    expr: up{job="n8n-webhook", instance="%s"} == 0
    for: 5m
    labels:
      severity: critical
      instance: %s
      component: webhook
    annotations:
      summary: "n8n webhook component is down"
      description: "n8n webhook component for instance {{ $labels.instance }} has been down for more than 5 minutes."
      
  - alert: N8nHighCPUUsage
    expr: rate(container_cpu_usage_seconds_total{pod=~"%s-.*"}[5m]) * 100 > 80
    for: 10m
    labels:
      severity: warning
      instance: %s
    annotations:
      summary: "n8n instance high CPU usage"
      description: "n8n instance {{ $labels.instance }} CPU usage is above 80%% for more than 10 minutes."
      
  - alert: N8nHighMemoryUsage
    expr: container_memory_usage_bytes{pod=~"%s-.*"} / container_spec_memory_limit_bytes{pod=~"%s-.*"} * 100 > 85
    for: 10m
    labels:
      severity: warning
      instance: %s
    annotations:
      summary: "n8n instance high memory usage"
      description: "n8n instance {{ $labels.instance }} memory usage is above 85%% for more than 10 minutes."
      
  - alert: N8nDatabaseConnectionHigh
    expr: n8n_db_connections_active{instance="%s"} / n8n_db_connections_max{instance="%s"} * 100 > 90
    for: 5m
    labels:
      severity: warning
      instance: %s
    annotations:
      summary: "n8n database connection pool nearly exhausted"
      description: "n8n instance {{ $labels.instance }} is using more than 90%% of available database connections."
      
  - alert: N8nCacheHitRateLow
    expr: n8n_cache_hit_rate{instance="%s"} < 0.7
    for: 15m
    labels:
      severity: info
      instance: %s
    annotations:
      summary: "n8n cache hit rate is low"
      description: "n8n instance {{ $labels.instance }} cache hit rate is below 70%% for more than 15 minutes."
      
  - alert: N8nWorkflowExecutionErrors
    expr: rate(n8n_workflow_executions_failed_total{instance="%s"}[5m]) > 0.1
    for: 5m
    labels:
      severity: warning
      instance: %s
    annotations:
      summary: "n8n workflow execution errors detected"
      description: "n8n instance {{ $labels.instance }} is experiencing workflow execution errors at a rate of {{ $value }} per second."
`, instance.Name, instance.Name, instance.Name, instance.Name, instance.Name, instance.Name, instance.Name,
		instance.Name, instance.Name, instance.Name, instance.Name, instance.Name, instance.Name,
		instance.Name, instance.Name, instance.Name, instance.Name)

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      alertRulesName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"app.kubernetes.io/part-of":    "n8n",
				"prometheus":                   "alert-rules",
			},
		},
		Data: map[string]string{
			"alert-rules.yaml": alertRulesYAML,
		},
	}

	// Set owner reference
	if err := controllerutil.SetControllerReference(instance, configMap, m.scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update the ConfigMap
	existingConfigMap := &corev1.ConfigMap{}
	err := m.client.Get(ctx, types.NamespacedName{Name: alertRulesName, Namespace: instance.Namespace}, existingConfigMap)
	if err != nil {
		if errors.IsNotFound(err) {
			m.logger.Info("Creating Prometheus alert rules ConfigMap", "configmap", alertRulesName)
			if err := m.client.Create(ctx, configMap); err != nil {
				return fmt.Errorf("failed to create Prometheus alert rules ConfigMap: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get Prometheus alert rules ConfigMap: %w", err)
		}
	} else {
		// Update existing ConfigMap
		existingConfigMap.Data = configMap.Data
		existingConfigMap.Labels = configMap.Labels
		m.logger.Info("Updating Prometheus alert rules ConfigMap", "configmap", alertRulesName)
		if err := m.client.Update(ctx, existingConfigMap); err != nil {
			return fmt.Errorf("failed to update Prometheus alert rules ConfigMap: %w", err)
		}
	}

	return nil
}
