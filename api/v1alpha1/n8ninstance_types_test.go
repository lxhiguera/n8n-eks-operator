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

package v1alpha1

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestN8nInstanceDefaults(t *testing.T) {
	instance := &N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: "default",
		},
		Spec: N8nInstanceSpec{
			Version: "1.0.0",
			Domain:  "test.example.com",
			Database: DatabaseSpec{
				Type: "rds-postgresql",
				RDS: &RDSSpec{
					Endpoint:          "test.cluster.amazonaws.com",
					DatabaseName:      "n8n",
					CredentialsSource: "secrets-manager",
					SecretsManagerArn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:test",
				},
			},
			Cache: CacheSpec{
				Type: "elasticache-redis",
				Redis: &RedisSpec{
					Endpoint:          "test.cache.amazonaws.com",
					CredentialsSource: "secrets-manager",
					SecretsManagerArn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:test-redis",
				},
			},
			Storage: StorageSpec{
				Workflows: WorkflowsStorageSpec{
					Type: "s3",
					S3: &S3Spec{
						BucketName: "test-workflows",
						Region:     "us-west-2",
					},
				},
				Assets: AssetsStorageSpec{
					Type: "s3-cloudfront",
					S3: &S3Spec{
						BucketName: "test-assets",
						Region:     "us-west-2",
					},
				},
				Persistent: PersistentStorageSpec{
					Type: "ebs-csi",
				},
			},
			Components: ComponentsSpec{
				Main: ComponentSpec{
					Resources: &corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("500m"),
							corev1.ResourceMemory: resource.MustParse("1Gi"),
						},
					},
				},
				Webhook: ComponentSpec{
					Resources: &corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("200m"),
							corev1.ResourceMemory: resource.MustParse("512Mi"),
						},
					},
				},
				Worker: ComponentSpec{
					Resources: &corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("300m"),
							corev1.ResourceMemory: resource.MustParse("768Mi"),
						},
					},
				},
			},
			Networking: NetworkingSpec{
				DNS: DNSSpec{
					Provider: "route53",
					Route53: &Route53Spec{
						HostedZoneId: "Z123456789",
					},
				},
				SSL: SSLSpec{
					Provider: "acm",
				},
			},
			Security: SecuritySpec{
				SecretsManagement: SecretsManagementSpec{
					Provider: "secrets-manager",
				},
				IAM: IAMSpec{
					RoleArn: "arn:aws:iam::123456789012:role/test-role",
				},
			},
		},
	}

	// Apply defaults
	instance.Default()

	// Test that defaults were applied
	if instance.Spec.Components.Main.Replicas != 2 {
		t.Errorf("Expected main replicas to be 2, got %d", instance.Spec.Components.Main.Replicas)
	}

	if instance.Spec.Components.Main.Port != 5678 {
		t.Errorf("Expected main port to be 5678, got %d", instance.Spec.Components.Main.Port)
	}

	if instance.Spec.Components.Webhook.Replicas != 3 {
		t.Errorf("Expected webhook replicas to be 3, got %d", instance.Spec.Components.Webhook.Replicas)
	}

	if instance.Spec.Components.Webhook.Port != 5679 {
		t.Errorf("Expected webhook port to be 5679, got %d", instance.Spec.Components.Webhook.Port)
	}

	if instance.Spec.Components.Webhook.Subdomain != "webhooks" {
		t.Errorf("Expected webhook subdomain to be 'webhooks', got %s", instance.Spec.Components.Webhook.Subdomain)
	}

	if instance.Spec.Components.Worker.Replicas != 5 {
		t.Errorf("Expected worker replicas to be 5, got %d", instance.Spec.Components.Worker.Replicas)
	}

	if instance.Spec.Security.IAM.ServiceAccountName != "n8n-service-account" {
		t.Errorf("Expected service account name to be 'n8n-service-account', got %s", instance.Spec.Security.IAM.ServiceAccountName)
	}

	if instance.Spec.Security.SecretsManagement.Provider != "secrets-manager" {
		t.Errorf("Expected secrets management provider to be 'secrets-manager', got %s", instance.Spec.Security.SecretsManagement.Provider)
	}
}

func TestN8nInstanceValidation(t *testing.T) {
	tests := []struct {
		name        string
		instance    *N8nInstance
		expectError bool
	}{
		{
			name: "valid instance",
			instance: &N8nInstance{
				Spec: N8nInstanceSpec{
					Version: "1.0.0",
					Domain:  "test.example.com",
					Database: DatabaseSpec{
						Type: "rds-postgresql",
						RDS: &RDSSpec{
							Endpoint:          "test.cluster.amazonaws.com",
							DatabaseName:      "n8n",
							CredentialsSource: "secrets-manager",
							SecretsManagerArn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:test",
						},
					},
					Cache: CacheSpec{
						Type: "elasticache-redis",
						Redis: &RedisSpec{
							Endpoint:          "test.cache.amazonaws.com",
							CredentialsSource: "secrets-manager",
							SecretsManagerArn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:test-redis",
						},
					},
					Storage: StorageSpec{
						Workflows: WorkflowsStorageSpec{
							Type: "s3",
							S3: &S3Spec{
								BucketName: "test-workflows",
								Region:     "us-west-2",
							},
						},
						Assets: AssetsStorageSpec{
							Type: "s3-cloudfront",
							S3: &S3Spec{
								BucketName: "test-assets",
								Region:     "us-west-2",
							},
						},
						Persistent: PersistentStorageSpec{
							Type: "ebs-csi",
						},
					},
					Components: ComponentsSpec{
						Main:    ComponentSpec{Replicas: 2},
						Webhook: ComponentSpec{Replicas: 3},
						Worker:  ComponentSpec{Replicas: 5},
					},
					Networking: NetworkingSpec{
						DNS: DNSSpec{
							Provider: "route53",
							Route53: &Route53Spec{
								HostedZoneId: "Z123456789",
							},
						},
						SSL: SSLSpec{
							Provider: "acm",
						},
					},
					Security: SecuritySpec{
						SecretsManagement: SecretsManagementSpec{
							Provider: "secrets-manager",
						},
						IAM: IAMSpec{
							RoleArn: "arn:aws:iam::123456789012:role/test-role",
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid version format",
			instance: &N8nInstance{
				Spec: N8nInstanceSpec{
					Version: "invalid-version",
					Domain:  "test.example.com",
					Security: SecuritySpec{
						IAM: IAMSpec{
							RoleArn: "arn:aws:iam::123456789012:role/test-role",
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "invalid IAM role ARN",
			instance: &N8nInstance{
				Spec: N8nInstanceSpec{
					Version: "1.0.0",
					Domain:  "test.example.com",
					Security: SecuritySpec{
						IAM: IAMSpec{
							RoleArn: "invalid-arn",
						},
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.instance.validateN8nInstance()
			if tt.expectError && err == nil {
				t.Errorf("Expected validation error, but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no validation error, but got: %v", err)
			}
		})
	}
}
