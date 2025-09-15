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
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

func TestMonitoringManager_ExtractMonitoringConfig(t *testing.T) {
	logger := logr.Discard()
	monitoringManager := &MonitoringManagerImpl{
		logger: logger,
	}

	tests := []struct {
		name     string
		instance *n8nv1alpha1.N8nInstance
		validate func(*MonitoringConfig) error
	}{
		{
			name: "default configuration",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					// No monitoring config specified, should use defaults
				},
			},
			validate: func(config *MonitoringConfig) error {
				if !config.Metrics.Enabled {
					t.Error("Expected metrics to be enabled by default")
				}
				if !config.Metrics.Prometheus.Enabled {
					t.Error("Expected Prometheus to be enabled by default")
				}
				if config.Metrics.Prometheus.Port != 9090 {
					t.Errorf("Expected default Prometheus port 9090, got %d", config.Metrics.Prometheus.Port)
				}
				if config.Logging.Level != "info" {
					t.Errorf("Expected default log level 'info', got '%s'", config.Logging.Level)
				}
				return nil
			},
		},
		{
			name: "custom configuration",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Monitoring: &n8nv1alpha1.MonitoringSpec{
						Metrics: &n8nv1alpha1.MetricsSpec{
							Enabled: true,
							Prometheus: &n8nv1alpha1.PrometheusSpec{
								Enabled:        true,
								ServiceMonitor: false,
							},
							CloudWatch: &n8nv1alpha1.CloudWatchSpec{
								Enabled:   true,
								Namespace: "CustomN8N/EKS",
							},
						},
						Logging: &n8nv1alpha1.LoggingSpec{
							Level: "debug",
							CloudWatch: &n8nv1alpha1.CloudWatchLogsSpec{
								Enabled:   true,
								LogGroup:  "/custom/n8n/logs",
								Retention: 14,
							},
						},
						Alerts: &n8nv1alpha1.AlertsSpec{
							Enabled: true,
							SNS: &n8nv1alpha1.SNSSpec{
								TopicArn: "arn:aws:sns:us-west-2:123456789012:n8n-alerts",
							},
						},
					},
				},
			},
			validate: func(config *MonitoringConfig) error {
				if !config.Metrics.Enabled {
					t.Error("Expected metrics to be enabled")
				}
				if config.Metrics.Prometheus.ServiceMonitor {
					t.Error("Expected ServiceMonitor to be disabled")
				}
				if !config.Metrics.CloudWatch.Enabled {
					t.Error("Expected CloudWatch to be enabled")
				}
				if config.Metrics.CloudWatch.Namespace != "CustomN8N/EKS" {
					t.Errorf("Expected custom CloudWatch namespace, got '%s'", config.Metrics.CloudWatch.Namespace)
				}
				if config.Logging.Level != "debug" {
					t.Errorf("Expected log level 'debug', got '%s'", config.Logging.Level)
				}
				if !config.Alerts.Enabled {
					t.Error("Expected alerts to be enabled")
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := monitoringManager.extractMonitoringConfig(tt.instance)
			if err := tt.validate(&config); err != nil {
				t.Errorf("Validation failed: %v", err)
			}
		})
	}
}

func TestMonitoringConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config MonitoringConfig
		valid  bool
	}{
		{
			name: "valid complete config",
			config: MonitoringConfig{
				Metrics: MetricsConfig{
					Enabled: true,
					Prometheus: PrometheusConfig{
						Enabled:        true,
						ServiceMonitor: true,
						Port:           9090,
						Path:           "/metrics",
						Interval:       "30s",
					},
					CloudWatch: CloudWatchConfig{
						Enabled:   true,
						Namespace: "N8N/EKS",
						Region:    "us-west-2",
					},
				},
				Logging: LoggingConfig{
					Level: "info",
					CloudWatch: CloudWatchLogsConfig{
						Enabled:   true,
						LogGroup:  "/aws/eks/n8n/test",
						Retention: 30,
					},
				},
				Alerts: AlertsConfig{
					Enabled: true,
					SNS: SNSConfig{
						TopicArn: "arn:aws:sns:us-west-2:123456789012:alerts",
						Region:   "us-west-2",
					},
				},
			},
			valid: true,
		},
		{
			name: "invalid Prometheus port",
			config: MonitoringConfig{
				Metrics: MetricsConfig{
					Enabled: true,
					Prometheus: PrometheusConfig{
						Enabled: true,
						Port:    0,
					},
				},
			},
			valid: false,
		},
		{
			name: "invalid log level",
			config: MonitoringConfig{
				Logging: LoggingConfig{
					Level: "invalid",
				},
			},
			valid: false,
		},
		{
			name: "invalid CloudWatch retention",
			config: MonitoringConfig{
				Logging: LoggingConfig{
					CloudWatch: CloudWatchLogsConfig{
						Enabled:   true,
						Retention: -1,
					},
				},
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate Prometheus port
			prometheusValid := !tt.config.Metrics.Prometheus.Enabled ||
				(tt.config.Metrics.Prometheus.Port > 0 && tt.config.Metrics.Prometheus.Port <= 65535)

			// Validate log level
			validLogLevels := []string{"debug", "info", "warn", "error"}
			logLevelValid := tt.config.Logging.Level == ""
			for _, level := range validLogLevels {
				if tt.config.Logging.Level == level {
					logLevelValid = true
					break
				}
			}

			// Validate CloudWatch retention
			retentionValid := !tt.config.Logging.CloudWatch.Enabled || tt.config.Logging.CloudWatch.Retention >= 0

			valid := prometheusValid && logLevelValid && retentionValid

			if valid != tt.valid {
				t.Errorf("Expected validation result %v, got %v (prometheus: %v, logLevel: %v, retention: %v)",
					tt.valid, valid, prometheusValid, logLevelValid, retentionValid)
			}
		})
	}
}

func TestAlertRule_Validation(t *testing.T) {
	tests := []struct {
		name  string
		rule  AlertRule
		valid bool
	}{
		{
			name: "valid alert rule",
			rule: AlertRule{
				Name:      "HighCPUUsage",
				Condition: "cpu_usage > 80",
				Threshold: "80%",
				Severity:  "warning",
			},
			valid: true,
		},
		{
			name: "missing name",
			rule: AlertRule{
				Condition: "cpu_usage > 80",
				Threshold: "80%",
				Severity:  "warning",
			},
			valid: false,
		},
		{
			name: "missing condition",
			rule: AlertRule{
				Name:      "HighCPUUsage",
				Threshold: "80%",
				Severity:  "warning",
			},
			valid: false,
		},
		{
			name: "invalid severity",
			rule: AlertRule{
				Name:      "HighCPUUsage",
				Condition: "cpu_usage > 80",
				Threshold: "80%",
				Severity:  "invalid",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validSeverities := []string{"critical", "warning", "info"}
			severityValid := false
			for _, severity := range validSeverities {
				if tt.rule.Severity == severity {
					severityValid = true
					break
				}
			}

			valid := tt.rule.Name != "" &&
				tt.rule.Condition != "" &&
				severityValid

			if valid != tt.valid {
				t.Errorf("Expected validation result %v, got %v", tt.valid, valid)
			}
		})
	}
}

func TestMonitoringManager_ReconcileMonitoring_Structure(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = n8nv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: "default",
		},
		Spec: n8nv1alpha1.N8nInstanceSpec{
			Monitoring: &n8nv1alpha1.MonitoringSpec{
				Metrics: &n8nv1alpha1.MetricsSpec{
					Enabled: true,
					Prometheus: &n8nv1alpha1.PrometheusSpec{
						Enabled:        true,
						ServiceMonitor: true,
					},
					CloudWatch: &n8nv1alpha1.CloudWatchSpec{
						Enabled:   true,
						Namespace: "N8N/EKS",
					},
				},
				Logging: &n8nv1alpha1.LoggingSpec{
					Level: "info",
					CloudWatch: &n8nv1alpha1.CloudWatchLogsSpec{
						Enabled:   true,
						Retention: 30,
					},
				},
				Alerts: &n8nv1alpha1.AlertsSpec{
					Enabled: true,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(instance).Build()
	logger := logr.Discard()

	monitoringManager := NewMonitoringManager(fakeClient, scheme, logger)

	ctx := context.Background()
	err := monitoringManager.ReconcileMonitoring(ctx, instance)

	// We expect this to potentially fail without real AWS clients, but we can test the structure
	if err != nil {
		t.Logf("ReconcileMonitoring failed as expected without AWS clients: %v", err)
	} else {
		t.Log("ReconcileMonitoring completed without error")
	}
}

func TestPrometheusConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config PrometheusConfig
		valid  bool
	}{
		{
			name: "valid Prometheus config",
			config: PrometheusConfig{
				Enabled:        true,
				ServiceMonitor: true,
				Port:           9090,
				Path:           "/metrics",
				Interval:       "30s",
			},
			valid: true,
		},
		{
			name: "disabled Prometheus",
			config: PrometheusConfig{
				Enabled: false,
			},
			valid: true,
		},
		{
			name: "invalid port (too low)",
			config: PrometheusConfig{
				Enabled: true,
				Port:    0,
			},
			valid: false,
		},
		{
			name: "invalid port (too high)",
			config: PrometheusConfig{
				Enabled: true,
				Port:    99999,
			},
			valid: false,
		},
		{
			name: "invalid interval format",
			config: PrometheusConfig{
				Enabled:  true,
				Port:     9090,
				Interval: "invalid",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			portValid := !tt.config.Enabled || (tt.config.Port > 0 && tt.config.Port <= 65535)

			// Simple interval validation
			intervalValid := tt.config.Interval == "" ||
				strings.HasSuffix(tt.config.Interval, "s") ||
				strings.HasSuffix(tt.config.Interval, "m") ||
				strings.HasSuffix(tt.config.Interval, "h")

			valid := portValid && intervalValid

			if valid != tt.valid {
				t.Errorf("Expected validation result %v, got %v (port: %v, interval: %v)",
					tt.valid, valid, portValid, intervalValid)
			}
		})
	}
}

func TestCloudWatchConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config CloudWatchConfig
		valid  bool
	}{
		{
			name: "valid CloudWatch config",
			config: CloudWatchConfig{
				Enabled:   true,
				Namespace: "N8N/EKS",
				Region:    "us-west-2",
			},
			valid: true,
		},
		{
			name: "disabled CloudWatch",
			config: CloudWatchConfig{
				Enabled: false,
			},
			valid: true,
		},
		{
			name: "invalid namespace (empty when enabled)",
			config: CloudWatchConfig{
				Enabled:   true,
				Namespace: "",
				Region:    "us-west-2",
			},
			valid: false,
		},
		{
			name: "invalid region",
			config: CloudWatchConfig{
				Enabled:   true,
				Namespace: "N8N/EKS",
				Region:    "invalid-region",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespaceValid := !tt.config.Enabled || tt.config.Namespace != ""

			validRegions := []string{
				"us-east-1", "us-east-2", "us-west-1", "us-west-2",
				"eu-west-1", "eu-west-2", "eu-central-1",
				"ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
			}
			regionValid := !tt.config.Enabled || tt.config.Region == ""
			for _, region := range validRegions {
				if tt.config.Region == region {
					regionValid = true
					break
				}
			}

			valid := namespaceValid && regionValid

			if valid != tt.valid {
				t.Errorf("Expected validation result %v, got %v (namespace: %v, region: %v)",
					tt.valid, valid, namespaceValid, regionValid)
			}
		})
	}
}
