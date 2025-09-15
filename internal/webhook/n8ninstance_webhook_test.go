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

package webhook

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

func TestN8nInstanceWebhook_Default(t *testing.T) {
	webhook := &N8nInstanceWebhook{}
	ctx := context.Background()

	tests := []struct {
		name     string
		instance *n8nv1alpha1.N8nInstance
		validate func(*n8nv1alpha1.N8nInstance) error
	}{
		{
			name: "should set default version",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{},
			},
			validate: func(instance *n8nv1alpha1.N8nInstance) error {
				if instance.Spec.Version != "1.0.0" {
					t.Errorf("Expected default version to be '1.0.0', got '%s'", instance.Spec.Version)
				}
				return nil
			},
		},
		{
			name: "should set default database configuration",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{},
			},
			validate: func(instance *n8nv1alpha1.N8nInstance) error {
				if instance.Spec.Database == nil {
					t.Error("Expected database configuration to be set")
					return nil
				}
				if instance.Spec.Database.Type != "rds-postgresql" {
					t.Errorf("Expected database type to be 'rds-postgresql', got '%s'", instance.Spec.Database.Type)
				}
				if instance.Spec.Database.RDS == nil {
					t.Error("Expected RDS configuration to be set")
					return nil
				}
				if instance.Spec.Database.RDS.Port != 5432 {
					t.Errorf("Expected RDS port to be 5432, got %d", instance.Spec.Database.RDS.Port)
				}
				return nil
			},
		},
		{
			name: "should set default cache configuration",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{},
			},
			validate: func(instance *n8nv1alpha1.N8nInstance) error {
				if instance.Spec.Cache == nil {
					t.Error("Expected cache configuration to be set")
					return nil
				}
				if instance.Spec.Cache.Type != "elasticache-redis" {
					t.Errorf("Expected cache type to be 'elasticache-redis', got '%s'", instance.Spec.Cache.Type)
				}
				if instance.Spec.Cache.Redis == nil {
					t.Error("Expected Redis configuration to be set")
					return nil
				}
				if instance.Spec.Cache.Redis.Port != 6379 {
					t.Errorf("Expected Redis port to be 6379, got %d", instance.Spec.Cache.Redis.Port)
				}
				return nil
			},
		},
		{
			name: "should set default component configurations",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{},
			},
			validate: func(instance *n8nv1alpha1.N8nInstance) error {
				if instance.Spec.Components == nil {
					t.Error("Expected components configuration to be set")
					return nil
				}

				// Check main component
				if instance.Spec.Components.Main == nil {
					t.Error("Expected main component to be set")
				} else {
					if instance.Spec.Components.Main.Replicas != 2 {
						t.Errorf("Expected main replicas to be 2, got %d", instance.Spec.Components.Main.Replicas)
					}
					if instance.Spec.Components.Main.Port != 5678 {
						t.Errorf("Expected main port to be 5678, got %d", instance.Spec.Components.Main.Port)
					}
				}

				// Check webhook component
				if instance.Spec.Components.Webhook == nil {
					t.Error("Expected webhook component to be set")
				} else {
					if instance.Spec.Components.Webhook.Replicas != 3 {
						t.Errorf("Expected webhook replicas to be 3, got %d", instance.Spec.Components.Webhook.Replicas)
					}
					if instance.Spec.Components.Webhook.Port != 5679 {
						t.Errorf("Expected webhook port to be 5679, got %d", instance.Spec.Components.Webhook.Port)
					}
				}

				// Check worker component
				if instance.Spec.Components.Worker == nil {
					t.Error("Expected worker component to be set")
				} else {
					if instance.Spec.Components.Worker.Replicas != 5 {
						t.Errorf("Expected worker replicas to be 5, got %d", instance.Spec.Components.Worker.Replicas)
					}
				}

				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := webhook.Default(ctx, tt.instance)
			if err != nil {
				t.Errorf("Default() error = %v", err)
				return
			}

			if tt.validate != nil {
				if err := tt.validate(tt.instance); err != nil {
					t.Errorf("Validation failed: %v", err)
				}
			}
		})
	}
}

func TestN8nInstanceWebhook_ValidateCreate(t *testing.T) {
	webhook := &N8nInstanceWebhook{}
	ctx := context.Background()

	tests := []struct {
		name        string
		instance    *n8nv1alpha1.N8nInstance
		expectError bool
	}{
		{
			name: "valid instance should pass validation",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Version: "1.0.0",
					Domain:  "n8n.example.com",
					Database: &n8nv1alpha1.DatabaseSpec{
						Type: "rds-postgresql",
						RDS: &n8nv1alpha1.RDSSpec{
							Endpoint:          "postgres.example.com",
							Port:              5432,
							DatabaseName:      "n8n",
							CredentialsSource: "secrets-manager",
							SecretsManagerArn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:n8n-db-credentials",
							SSLMode:           "require",
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid version should fail validation",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Version: "invalid-version",
				},
			},
			expectError: true,
		},
		{
			name: "invalid domain should fail validation",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Version: "1.0.0",
					Domain:  "invalid..domain",
				},
			},
			expectError: true,
		},
		{
			name: "invalid database type should fail validation",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Version: "1.0.0",
					Database: &n8nv1alpha1.DatabaseSpec{
						Type: "mysql", // Not supported
					},
				},
			},
			expectError: true,
		},
		{
			name: "missing RDS endpoint should fail validation",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Version: "1.0.0",
					Database: &n8nv1alpha1.DatabaseSpec{
						Type: "rds-postgresql",
						RDS: &n8nv1alpha1.RDSSpec{
							// Missing endpoint
							Port:              5432,
							DatabaseName:      "n8n",
							CredentialsSource: "secrets-manager",
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "invalid port should fail validation",
			instance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Version: "1.0.0",
					Database: &n8nv1alpha1.DatabaseSpec{
						Type: "rds-postgresql",
						RDS: &n8nv1alpha1.RDSSpec{
							Endpoint:          "postgres.example.com",
							Port:              99999, // Invalid port
							DatabaseName:      "n8n",
							CredentialsSource: "secrets-manager",
						},
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := webhook.ValidateCreate(ctx, tt.instance)

			if tt.expectError && err == nil {
				t.Error("Expected validation error, but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no validation error, but got: %v", err)
			}
		})
	}
}

func TestN8nInstanceWebhook_ValidateUpdate(t *testing.T) {
	webhook := &N8nInstanceWebhook{}
	ctx := context.Background()

	oldInstance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: "default",
		},
		Spec: n8nv1alpha1.N8nInstanceSpec{
			Version: "1.0.0",
			Domain:  "n8n.example.com",
			Database: &n8nv1alpha1.DatabaseSpec{
				Type: "rds-postgresql",
				RDS: &n8nv1alpha1.RDSSpec{
					Endpoint:          "postgres.example.com",
					Port:              5432,
					DatabaseName:      "n8n",
					CredentialsSource: "secrets-manager",
				},
			},
		},
	}

	tests := []struct {
		name        string
		newInstance *n8nv1alpha1.N8nInstance
		expectError bool
	}{
		{
			name: "valid update should pass validation",
			newInstance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Version: "1.1.0", // Version update is allowed
					Domain:  "n8n.example.com",
					Database: &n8nv1alpha1.DatabaseSpec{
						Type: "rds-postgresql",
						RDS: &n8nv1alpha1.RDSSpec{
							Endpoint:          "postgres.example.com",
							Port:              5432,
							DatabaseName:      "n8n",
							CredentialsSource: "secrets-manager",
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "changing domain should fail validation",
			newInstance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Version: "1.0.0",
					Domain:  "new-domain.example.com", // Domain change not allowed
					Database: &n8nv1alpha1.DatabaseSpec{
						Type: "rds-postgresql",
						RDS: &n8nv1alpha1.RDSSpec{
							Endpoint:          "postgres.example.com",
							Port:              5432,
							DatabaseName:      "n8n",
							CredentialsSource: "secrets-manager",
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "changing database endpoint should fail validation",
			newInstance: &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: "default",
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Version: "1.0.0",
					Domain:  "n8n.example.com",
					Database: &n8nv1alpha1.DatabaseSpec{
						Type: "rds-postgresql",
						RDS: &n8nv1alpha1.RDSSpec{
							Endpoint:          "new-postgres.example.com", // Endpoint change requires careful migration
							Port:              5432,
							DatabaseName:      "n8n",
							CredentialsSource: "secrets-manager",
						},
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := webhook.ValidateUpdate(ctx, oldInstance, tt.newInstance)

			if tt.expectError && err == nil {
				t.Error("Expected validation error, but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no validation error, but got: %v", err)
			}
		})
	}
}

func TestValidationHelpers(t *testing.T) {
	tests := []struct {
		name     string
		function func() bool
		expected bool
	}{
		{
			name:     "valid duration should pass",
			function: func() bool { return isValidDuration("1h") },
			expected: true,
		},
		{
			name:     "invalid duration should fail",
			function: func() bool { return isValidDuration("invalid") },
			expected: false,
		},
		{
			name:     "valid storage size should pass",
			function: func() bool { return isValidStorageSize("20Gi") },
			expected: true,
		},
		{
			name:     "invalid storage size should fail",
			function: func() bool { return isValidStorageSize("invalid") },
			expected: false,
		},
		{
			name:     "valid S3 bucket name should pass",
			function: func() bool { return isValidS3BucketName("my-bucket-name") },
			expected: true,
		},
		{
			name:     "invalid S3 bucket name should fail",
			function: func() bool { return isValidS3BucketName("Invalid..Bucket") },
			expected: false,
		},
		{
			name:     "valid AWS region should pass",
			function: func() bool { return isValidAWSRegion("us-west-2") },
			expected: true,
		},
		{
			name:     "invalid AWS region should fail",
			function: func() bool { return isValidAWSRegion("invalid-region") },
			expected: false,
		},
		{
			name:     "valid file extension should pass",
			function: func() bool { return isValidFileExtension("jpg") },
			expected: true,
		},
		{
			name:     "invalid file extension should fail",
			function: func() bool { return isValidFileExtension("invalid.ext") },
			expected: false,
		},
		{
			name:     "valid file size should pass",
			function: func() bool { return isValidFileSize("10MB") },
			expected: true,
		},
		{
			name:     "invalid file size should fail",
			function: func() bool { return isValidFileSize("invalid") },
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.function()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
