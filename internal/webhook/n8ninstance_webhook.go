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
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// log is for logging in this package.
var n8ninstancelog = logf.Log.WithName("n8ninstance-webhook")

// N8nInstanceWebhook implements webhook.Validator and webhook.Defaulter for N8nInstance
type N8nInstanceWebhook struct{}

// SetupWebhookWithManager sets up the webhook with the manager
func (w *N8nInstanceWebhook) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&n8nv1alpha1.N8nInstance{}).
		WithValidator(w).
		WithDefaulter(w).
		Complete()
}

//+kubebuilder:webhook:path=/mutate-n8n-io-v1alpha1-n8ninstance,mutating=true,failurePolicy=fail,sideEffects=None,groups=n8n.io,resources=n8ninstances,verbs=create;update,versions=v1alpha1,name=mn8ninstance.kb.io,admissionReviewVersions=v1

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (w *N8nInstanceWebhook) Default(ctx context.Context, obj runtime.Object) error {
	instance := obj.(*n8nv1alpha1.N8nInstance)
	n8ninstancelog.Info("Setting defaults for N8nInstance", "name", instance.Name, "namespace", instance.Namespace)

	// Set default version if not specified
	if instance.Spec.Version == "" {
		instance.Spec.Version = "1.0.0"
	}

	// Set default database configuration
	if instance.Spec.Database == nil {
		instance.Spec.Database = &n8nv1alpha1.DatabaseSpec{
			Type: "rds-postgresql",
			RDS: &n8nv1alpha1.RDSSpec{
				Port:              5432,
				CredentialsSource: "secrets-manager",
				SSLMode:           "require",
				ConnectionPooling: &n8nv1alpha1.ConnectionPoolingSpec{
					Enabled:        true,
					MaxConnections: 20,
					IdleTimeout:    "30s",
				},
			},
		}
	} else {
		// Set defaults for existing database config
		if instance.Spec.Database.RDS != nil {
			if instance.Spec.Database.RDS.Port == 0 {
				instance.Spec.Database.RDS.Port = 5432
			}
			if instance.Spec.Database.RDS.CredentialsSource == "" {
				instance.Spec.Database.RDS.CredentialsSource = "secrets-manager"
			}
			if instance.Spec.Database.RDS.SSLMode == "" {
				instance.Spec.Database.RDS.SSLMode = "require"
			}
			if instance.Spec.Database.RDS.ConnectionPooling == nil {
				instance.Spec.Database.RDS.ConnectionPooling = &n8nv1alpha1.ConnectionPoolingSpec{
					Enabled:        true,
					MaxConnections: 20,
					IdleTimeout:    "30s",
				}
			}
		}
	}

	// Set default cache configuration
	if instance.Spec.Cache == nil {
		instance.Spec.Cache = &n8nv1alpha1.CacheSpec{
			Type: "elasticache-redis",
			Redis: &n8nv1alpha1.RedisSpec{
				Port:              6379,
				ClusterMode:       false,
				AuthEnabled:       true,
				CredentialsSource: "secrets-manager",
				TLSEnabled:        true,
				TTLDefault:        "1h",
			},
		}
	} else {
		// Set defaults for existing cache config
		if instance.Spec.Cache.Redis != nil {
			if instance.Spec.Cache.Redis.Port == 0 {
				instance.Spec.Cache.Redis.Port = 6379
			}
			if instance.Spec.Cache.Redis.CredentialsSource == "" {
				instance.Spec.Cache.Redis.CredentialsSource = "secrets-manager"
			}
			if instance.Spec.Cache.Redis.TTLDefault == "" {
				instance.Spec.Cache.Redis.TTLDefault = "1h"
			}
		}
	}

	// Set default storage configuration
	if instance.Spec.Storage == nil {
		instance.Spec.Storage = &n8nv1alpha1.StorageSpec{
			Workflows: &n8nv1alpha1.WorkflowsStorageSpec{
				Type: "s3",
				S3: &n8nv1alpha1.S3Spec{
					Encryption: &n8nv1alpha1.EncryptionSpec{
						Enabled: true,
					},
					Versioning: true,
					Lifecycle: &n8nv1alpha1.LifecycleSpec{
						Enabled:             true,
						TransitionToIA:      "30d",
						TransitionToGlacier: "90d",
					},
				},
			},
			Assets: &n8nv1alpha1.AssetsStorageSpec{
				Type: "s3-cloudfront",
				S3: &n8nv1alpha1.S3Spec{
					AllowedFileTypes: []string{"jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "xls", "xlsx"},
					MaxFileSize:      "10MB",
				},
				CloudFront: &n8nv1alpha1.CloudFrontSpec{
					Enabled: true,
				},
			},
			Persistent: &n8nv1alpha1.PersistentStorageSpec{
				Type:          "ebs-csi",
				StorageClass:  "gp3",
				Size:          "20Gi",
				AutoExpansion: true,
				SnapshotPolicy: &n8nv1alpha1.SnapshotPolicySpec{
					Enabled:   true,
					Schedule:  "0 2 * * *",
					Retention: "7d",
				},
			},
		}
	}

	// Set default component configurations
	if instance.Spec.Components == nil {
		instance.Spec.Components = &n8nv1alpha1.ComponentsSpec{}
	}

	// Set defaults for main component
	if instance.Spec.Components.Main == nil {
		instance.Spec.Components.Main = &n8nv1alpha1.ComponentSpec{
			Replicas: 2,
			Port:     5678,
			Resources: &n8nv1alpha1.ResourcesSpec{
				Requests: &n8nv1alpha1.ResourceRequirementsSpec{
					CPU:    "500m",
					Memory: "1Gi",
				},
				Limits: &n8nv1alpha1.ResourceRequirementsSpec{
					CPU:    "2",
					Memory: "4Gi",
				},
			},
			Autoscaling: &n8nv1alpha1.AutoscalingSpec{
				Enabled:      true,
				MinReplicas:  2,
				MaxReplicas:  10,
				TargetCPU:    70,
				TargetMemory: 80,
			},
		}
	}

	// Set defaults for webhook component
	if instance.Spec.Components.Webhook == nil {
		instance.Spec.Components.Webhook = &n8nv1alpha1.ComponentSpec{
			Replicas:  3,
			Port:      5679,
			Subdomain: "webhooks",
			Resources: &n8nv1alpha1.ResourcesSpec{
				Requests: &n8nv1alpha1.ResourceRequirementsSpec{
					CPU:    "200m",
					Memory: "512Mi",
				},
				Limits: &n8nv1alpha1.ResourceRequirementsSpec{
					CPU:    "1",
					Memory: "2Gi",
				},
			},
			Autoscaling: &n8nv1alpha1.AutoscalingSpec{
				Enabled:     true,
				MinReplicas: 3,
				MaxReplicas: 20,
				TargetCPU:   70,
			},
		}
	}

	// Set defaults for worker component
	if instance.Spec.Components.Worker == nil {
		instance.Spec.Components.Worker = &n8nv1alpha1.ComponentSpec{
			Replicas:  5,
			Subdomain: "workers",
			Resources: &n8nv1alpha1.ResourcesSpec{
				Requests: &n8nv1alpha1.ResourceRequirementsSpec{
					CPU:    "300m",
					Memory: "768Mi",
				},
				Limits: &n8nv1alpha1.ResourceRequirementsSpec{
					CPU:    "1.5",
					Memory: "3Gi",
				},
			},
			Autoscaling: &n8nv1alpha1.AutoscalingSpec{
				Enabled:     true,
				MinReplicas: 5,
				MaxReplicas: 50,
				TargetCPU:   80,
			},
		}
	}

	// Set default networking configuration
	if instance.Spec.Networking == nil {
		instance.Spec.Networking = &n8nv1alpha1.NetworkingSpec{
			DNS: &n8nv1alpha1.DNSSpec{
				Provider: "route53",
				Route53: &n8nv1alpha1.Route53Spec{
					CreateZone: false,
				},
			},
			SSL: &n8nv1alpha1.SSLSpec{
				Provider: "acm",
				ACM: &n8nv1alpha1.ACMSpec{
					AutoValidation:   true,
					ValidationMethod: "DNS",
				},
			},
			Istio: &n8nv1alpha1.IstioSpec{
				Enabled: true,
				Gateway: &n8nv1alpha1.GatewaySpec{
					Name: "n8n-gateway",
				},
				VirtualService: &n8nv1alpha1.VirtualServiceSpec{
					Timeout: "30s",
					Retries: 3,
				},
				AuthorizationPolicy: &n8nv1alpha1.AuthorizationPolicySpec{
					Enabled: true,
				},
			},
		}
	}

	// Set default security configuration
	if instance.Spec.Security == nil {
		instance.Spec.Security = &n8nv1alpha1.SecuritySpec{
			SecretsManagement: &n8nv1alpha1.SecretsManagementSpec{
				Provider: "secrets-manager",
				Rotation: &n8nv1alpha1.RotationSpec{
					Enabled:  true,
					Schedule: "0 0 1 * *",
				},
				Encryption: &n8nv1alpha1.EncryptionSpec{
					InTransit: true,
					AtRest:    true,
				},
			},
			IAM: &n8nv1alpha1.IAMSpec{
				ServiceAccountName: "n8n-service-account",
			},
			NetworkPolicies: &n8nv1alpha1.NetworkPoliciesSpec{
				Enabled: true,
				DenyAll: true,
			},
		}
	}

	// Set default monitoring configuration
	if instance.Spec.Monitoring == nil {
		instance.Spec.Monitoring = &n8nv1alpha1.MonitoringSpec{
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
		}
	}

	n8ninstancelog.Info("Successfully set defaults for N8nInstance", "name", instance.Name)
	return nil
}

//+kubebuilder:webhook:path=/validate-n8n-io-v1alpha1-n8ninstance,mutating=false,failurePolicy=fail,sideEffects=None,groups=n8n.io,resources=n8ninstances,verbs=create;update,versions=v1alpha1,name=vn8ninstance.kb.io,admissionReviewVersions=v1

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (w *N8nInstanceWebhook) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	instance := obj.(*n8nv1alpha1.N8nInstance)
	n8ninstancelog.Info("Validating N8nInstance creation", "name", instance.Name, "namespace", instance.Namespace)

	allErrs := w.validateN8nInstance(instance)
	if len(allErrs) == 0 {
		return nil, nil
	}

	return nil, fmt.Errorf("validation failed: %v", allErrs.ToAggregate())
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (w *N8nInstanceWebhook) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	instance := newObj.(*n8nv1alpha1.N8nInstance)
	oldInstance := oldObj.(*n8nv1alpha1.N8nInstance)
	n8ninstancelog.Info("Validating N8nInstance update", "name", instance.Name, "namespace", instance.Namespace)

	allErrs := w.validateN8nInstance(instance)

	// Add update-specific validations
	allErrs = append(allErrs, w.validateN8nInstanceUpdate(oldInstance, instance)...)

	if len(allErrs) == 0 {
		return nil, nil
	}

	return nil, fmt.Errorf("validation failed: %v", allErrs.ToAggregate())
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (w *N8nInstanceWebhook) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	instance := obj.(*n8nv1alpha1.N8nInstance)
	n8ninstancelog.Info("Validating N8nInstance deletion", "name", instance.Name, "namespace", instance.Namespace)

	// Add any deletion-specific validations here
	// For example, check if there are running workflows that shouldn't be interrupted

	return nil, nil
}

// validateN8nInstance performs comprehensive validation of N8nInstance
func (w *N8nInstanceWebhook) validateN8nInstance(instance *n8nv1alpha1.N8nInstance) field.ErrorList {
	var allErrs field.ErrorList
	specPath := field.NewPath("spec")

	// Validate version
	allErrs = append(allErrs, w.validateVersion(instance.Spec.Version, specPath.Child("version"))...)

	// Validate domain
	if instance.Spec.Domain != "" {
		allErrs = append(allErrs, w.validateDomain(instance.Spec.Domain, specPath.Child("domain"))...)
	}

	// Validate database configuration
	if instance.Spec.Database != nil {
		allErrs = append(allErrs, w.validateDatabase(instance.Spec.Database, specPath.Child("database"))...)
	}

	// Validate cache configuration
	if instance.Spec.Cache != nil {
		allErrs = append(allErrs, w.validateCache(instance.Spec.Cache, specPath.Child("cache"))...)
	}

	// Validate storage configuration
	if instance.Spec.Storage != nil {
		allErrs = append(allErrs, w.validateStorage(instance.Spec.Storage, specPath.Child("storage"))...)
	}

	// Validate components configuration
	if instance.Spec.Components != nil {
		allErrs = append(allErrs, w.validateComponents(instance.Spec.Components, specPath.Child("components"))...)
	}

	// Validate networking configuration
	if instance.Spec.Networking != nil {
		allErrs = append(allErrs, w.validateNetworking(instance.Spec.Networking, specPath.Child("networking"))...)
	}

	// Validate security configuration
	if instance.Spec.Security != nil {
		allErrs = append(allErrs, w.validateSecurity(instance.Spec.Security, specPath.Child("security"))...)
	}

	// Validate monitoring configuration
	if instance.Spec.Monitoring != nil {
		allErrs = append(allErrs, w.validateMonitoring(instance.Spec.Monitoring, specPath.Child("monitoring"))...)
	}

	// Cross-field validations
	allErrs = append(allErrs, w.validateCrossFieldDependencies(instance, specPath)...)

	return allErrs
}

// validateN8nInstanceUpdate performs update-specific validations
func (w *N8nInstanceWebhook) validateN8nInstanceUpdate(oldInstance, newInstance *n8nv1alpha1.N8nInstance) field.ErrorList {
	var allErrs field.ErrorList
	specPath := field.NewPath("spec")

	// Validate that certain immutable fields haven't changed
	if oldInstance.Spec.Domain != newInstance.Spec.Domain {
		allErrs = append(allErrs, field.Forbidden(specPath.Child("domain"), "domain cannot be changed after creation"))
	}

	// Validate database endpoint changes (should be careful)
	if oldInstance.Spec.Database != nil && newInstance.Spec.Database != nil {
		if oldInstance.Spec.Database.RDS != nil && newInstance.Spec.Database.RDS != nil {
			if oldInstance.Spec.Database.RDS.Endpoint != newInstance.Spec.Database.RDS.Endpoint {
				allErrs = append(allErrs, field.Invalid(specPath.Child("database", "rds", "endpoint"),
					newInstance.Spec.Database.RDS.Endpoint, "changing database endpoint requires careful migration"))
			}
		}
	}

	// Validate that scaling down doesn't go below minimum safe values
	if oldInstance.Spec.Components != nil && newInstance.Spec.Components != nil {
		if oldInstance.Spec.Components.Main != nil && newInstance.Spec.Components.Main != nil {
			if newInstance.Spec.Components.Main.Replicas < 1 {
				allErrs = append(allErrs, field.Invalid(specPath.Child("components", "main", "replicas"),
					newInstance.Spec.Components.Main.Replicas, "main component must have at least 1 replica"))
			}
		}
	}

	return allErrs
}

// validateVersion validates the n8n version format
func (w *N8nInstanceWebhook) validateVersion(version string, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	if version == "" {
		allErrs = append(allErrs, field.Required(fldPath, "version is required"))
		return allErrs
	}

	// Validate semantic version format
	semverRegex := regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)
	if !semverRegex.MatchString(version) {
		allErrs = append(allErrs, field.Invalid(fldPath, version, "version must be a valid semantic version (e.g., 1.0.0)"))
	}

	return allErrs
}

// validateDomain validates the domain format
func (w *N8nInstanceWebhook) validateDomain(domain string, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// Validate domain format
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !domainRegex.MatchString(domain) {
		allErrs = append(allErrs, field.Invalid(fldPath, domain, "domain must be a valid DNS name"))
	}

	// Check domain length
	if len(domain) > 253 {
		allErrs = append(allErrs, field.Invalid(fldPath, domain, "domain must not exceed 253 characters"))
	}

	return allErrs
}

// validateDatabase validates database configuration
func (w *N8nInstanceWebhook) validateDatabase(db *n8nv1alpha1.DatabaseSpec, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// Validate database type
	if db.Type != "rds-postgresql" {
		allErrs = append(allErrs, field.NotSupported(fldPath.Child("type"), db.Type, []string{"rds-postgresql"}))
	}

	// Validate RDS configuration
	if db.RDS != nil {
		allErrs = append(allErrs, w.validateRDS(db.RDS, fldPath.Child("rds"))...)
	} else if db.Type == "rds-postgresql" {
		allErrs = append(allErrs, field.Required(fldPath.Child("rds"), "rds configuration is required when type is rds-postgresql"))
	}

	return allErrs
}

// validateRDS validates RDS configuration
func (w *N8nInstanceWebhook) validateRDS(rds *n8nv1alpha1.RDSSpec, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// Validate endpoint
	if rds.Endpoint == "" {
		allErrs = append(allErrs, field.Required(fldPath.Child("endpoint"), "endpoint is required"))
	} else {
		// Validate endpoint format (should be a valid hostname)
		if _, err := url.Parse("postgres://" + rds.Endpoint); err != nil {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("endpoint"), rds.Endpoint, "endpoint must be a valid hostname"))
		}
	}

	// Validate port
	if rds.Port < 1 || rds.Port > 65535 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("port"), rds.Port, "port must be between 1 and 65535"))
	}

	// Validate database name
	if rds.DatabaseName == "" {
		allErrs = append(allErrs, field.Required(fldPath.Child("databaseName"), "databaseName is required"))
	}

	// Validate credentials source
	validCredentialsSources := []string{"secrets-manager", "kubernetes-secret"}
	if !contains(validCredentialsSources, rds.CredentialsSource) {
		allErrs = append(allErrs, field.NotSupported(fldPath.Child("credentialsSource"), rds.CredentialsSource, validCredentialsSources))
	}

	// Validate secrets manager ARN if using secrets manager
	if rds.CredentialsSource == "secrets-manager" && rds.SecretsManagerArn == "" {
		allErrs = append(allErrs, field.Required(fldPath.Child("secretsManagerArn"), "secretsManagerArn is required when using secrets-manager"))
	}

	// Validate kubernetes secret name if using kubernetes secret
	if rds.CredentialsSource == "kubernetes-secret" && rds.KubernetesSecretName == "" {
		allErrs = append(allErrs, field.Required(fldPath.Child("kubernetesSecretName"), "kubernetesSecretName is required when using kubernetes-secret"))
	}

	// Validate SSL mode
	validSSLModes := []string{"require", "prefer", "disable"}
	if !contains(validSSLModes, rds.SSLMode) {
		allErrs = append(allErrs, field.NotSupported(fldPath.Child("sslMode"), rds.SSLMode, validSSLModes))
	}

	// Validate connection pooling
	if rds.ConnectionPooling != nil {
		if rds.ConnectionPooling.MaxConnections < 1 || rds.ConnectionPooling.MaxConnections > 1000 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("connectionPooling", "maxConnections"),
				rds.ConnectionPooling.MaxConnections, "maxConnections must be between 1 and 1000"))
		}
	}

	return allErrs
}

// validateCache validates cache configuration
func (w *N8nInstanceWebhook) validateCache(cache *n8nv1alpha1.CacheSpec, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// Validate cache type
	if cache.Type != "elasticache-redis" {
		allErrs = append(allErrs, field.NotSupported(fldPath.Child("type"), cache.Type, []string{"elasticache-redis"}))
	}

	// Validate Redis configuration
	if cache.Redis != nil {
		allErrs = append(allErrs, w.validateRedis(cache.Redis, fldPath.Child("redis"))...)
	} else if cache.Type == "elasticache-redis" {
		allErrs = append(allErrs, field.Required(fldPath.Child("redis"), "redis configuration is required when type is elasticache-redis"))
	}

	return allErrs
}

// validateRedis validates Redis configuration
func (w *N8nInstanceWebhook) validateRedis(redis *n8nv1alpha1.RedisSpec, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// Validate endpoint
	if redis.Endpoint == "" {
		allErrs = append(allErrs, field.Required(fldPath.Child("endpoint"), "endpoint is required"))
	}

	// Validate port
	if redis.Port < 1 || redis.Port > 65535 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("port"), redis.Port, "port must be between 1 and 65535"))
	}

	// Validate credentials source
	validCredentialsSources := []string{"secrets-manager", "kubernetes-secret"}
	if !contains(validCredentialsSources, redis.CredentialsSource) {
		allErrs = append(allErrs, field.NotSupported(fldPath.Child("credentialsSource"), redis.CredentialsSource, validCredentialsSources))
	}

	// Validate TTL format
	if redis.TTLDefault != "" {
		if !isValidDuration(redis.TTLDefault) {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("ttlDefault"), redis.TTLDefault, "ttlDefault must be a valid duration (e.g., 1h, 30m, 60s)"))
		}
	}

	return allErrs
}

// validateStorage validates storage configuration
func (w *N8nInstanceWebhook) validateStorage(storage *n8nv1alpha1.StorageSpec, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// Validate workflows storage
	if storage.Workflows != nil {
		if storage.Workflows.Type != "s3" {
			allErrs = append(allErrs, field.NotSupported(fldPath.Child("workflows", "type"), storage.Workflows.Type, []string{"s3"}))
		}
		if storage.Workflows.S3 != nil {
			allErrs = append(allErrs, w.validateS3Config(storage.Workflows.S3, fldPath.Child("workflows", "s3"))...)
		}
	}

	// Validate assets storage
	if storage.Assets != nil {
		if storage.Assets.Type != "s3-cloudfront" {
			allErrs = append(allErrs, field.NotSupported(fldPath.Child("assets", "type"), storage.Assets.Type, []string{"s3-cloudfront"}))
		}
		if storage.Assets.S3 != nil {
			allErrs = append(allErrs, w.validateS3Config(storage.Assets.S3, fldPath.Child("assets", "s3"))...)
		}
	}

	// Validate persistent storage
	if storage.Persistent != nil {
		if storage.Persistent.Type != "ebs-csi" {
			allErrs = append(allErrs, field.NotSupported(fldPath.Child("persistent", "type"), storage.Persistent.Type, []string{"ebs-csi"}))
		}

		// Validate storage size
		if storage.Persistent.Size != "" {
			if !isValidStorageSize(storage.Persistent.Size) {
				allErrs = append(allErrs, field.Invalid(fldPath.Child("persistent", "size"), storage.Persistent.Size, "size must be a valid Kubernetes quantity (e.g., 20Gi, 100Mi)"))
			}
		}
	}

	return allErrs
}

// validateS3Config validates S3 configuration
func (w *N8nInstanceWebhook) validateS3Config(s3 *n8nv1alpha1.S3Spec, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// Validate bucket name format
	if s3.BucketName != "" {
		if !isValidS3BucketName(s3.BucketName) {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("bucketName"), s3.BucketName, "bucketName must be a valid S3 bucket name"))
		}
	}

	// Validate region
	if s3.Region != "" {
		if !isValidAWSRegion(s3.Region) {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("region"), s3.Region, "region must be a valid AWS region"))
		}
	}

	// Validate file types
	if len(s3.AllowedFileTypes) > 0 {
		for i, fileType := range s3.AllowedFileTypes {
			if !isValidFileExtension(fileType) {
				allErrs = append(allErrs, field.Invalid(fldPath.Child("allowedFileTypes").Index(i), fileType, "file type must be a valid extension without dot (e.g., jpg, pdf)"))
			}
		}
	}

	// Validate max file size
	if s3.MaxFileSize != "" {
		if !isValidFileSize(s3.MaxFileSize) {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("maxFileSize"), s3.MaxFileSize, "maxFileSize must be a valid size (e.g., 10MB, 1GB)"))
		}
	}

	return allErrs
}

// validateComponents validates components configuration
func (w *N8nInstanceWebhook) validateComponents(components *n8nv1alpha1.ComponentsSpec, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// Validate main component
	if components.Main != nil {
		allErrs = append(allErrs, w.validateComponent(components.Main, fldPath.Child("main"), "main")...)
	}

	// Validate webhook component
	if components.Webhook != nil {
		allErrs = append(allErrs, w.validateComponent(components.Webhook, fldPath.Child("webhook"), "webhook")...)
	}

	// Validate worker component
	if components.Worker != nil {
		allErrs = append(allErrs, w.validateComponent(components.Worker, fldPath.Child("worker"), "worker")...)
	}

	return allErrs
}

// validateComponent validates individual component configuration
func (w *N8nInstanceWebhook) validateComponent(component *n8nv1alpha1.ComponentSpec, fldPath *field.Path, componentType string) field.ErrorList {
	var allErrs field.ErrorList

	// Validate replicas
	if component.Replicas < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("replicas"), component.Replicas, "replicas must be non-negative"))
	}

	// Validate port for components that need it
	if componentType != "worker" && component.Port != 0 {
		if component.Port < 1024 || component.Port > 65535 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("port"), component.Port, "port must be between 1024 and 65535"))
		}
	}

	// Validate autoscaling
	if component.Autoscaling != nil {
		if component.Autoscaling.MinReplicas < 0 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("autoscaling", "minReplicas"), component.Autoscaling.MinReplicas, "minReplicas must be non-negative"))
		}
		if component.Autoscaling.MaxReplicas < component.Autoscaling.MinReplicas {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("autoscaling", "maxReplicas"), component.Autoscaling.MaxReplicas, "maxReplicas must be greater than or equal to minReplicas"))
		}
		if component.Autoscaling.TargetCPU < 1 || component.Autoscaling.TargetCPU > 100 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("autoscaling", "targetCPU"), component.Autoscaling.TargetCPU, "targetCPU must be between 1 and 100"))
		}
		if component.Autoscaling.TargetMemory != 0 && (component.Autoscaling.TargetMemory < 1 || component.Autoscaling.TargetMemory > 100) {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("autoscaling", "targetMemory"), component.Autoscaling.TargetMemory, "targetMemory must be between 1 and 100"))
		}
	}

	return allErrs
}

// validateNetworking validates networking configuration
func (w *N8nInstanceWebhook) validateNetworking(networking *n8nv1alpha1.NetworkingSpec, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// Validate DNS configuration
	if networking.DNS != nil {
		if networking.DNS.Provider != "route53" {
			allErrs = append(allErrs, field.NotSupported(fldPath.Child("dns", "provider"), networking.DNS.Provider, []string{"route53"}))
		}
	}

	// Validate SSL configuration
	if networking.SSL != nil {
		if networking.SSL.Provider != "acm" {
			allErrs = append(allErrs, field.NotSupported(fldPath.Child("ssl", "provider"), networking.SSL.Provider, []string{"acm"}))
		}
		if networking.SSL.ACM != nil {
			validationMethods := []string{"DNS", "EMAIL"}
			if !contains(validationMethods, networking.SSL.ACM.ValidationMethod) {
				allErrs = append(allErrs, field.NotSupported(fldPath.Child("ssl", "acm", "validationMethod"), networking.SSL.ACM.ValidationMethod, validationMethods))
			}
		}
	}

	return allErrs
}

// validateSecurity validates security configuration
func (w *N8nInstanceWebhook) validateSecurity(security *n8nv1alpha1.SecuritySpec, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// Validate secrets management
	if security.SecretsManagement != nil {
		validProviders := []string{"secrets-manager", "kubernetes"}
		if !contains(validProviders, security.SecretsManagement.Provider) {
			allErrs = append(allErrs, field.NotSupported(fldPath.Child("secretsManagement", "provider"), security.SecretsManagement.Provider, validProviders))
		}
	}

	return allErrs
}

// validateMonitoring validates monitoring configuration
func (w *N8nInstanceWebhook) validateMonitoring(monitoring *n8nv1alpha1.MonitoringSpec, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// Validate logging level
	if monitoring.Logging != nil {
		validLevels := []string{"debug", "info", "warn", "error"}
		if !contains(validLevels, monitoring.Logging.Level) {
			allErrs = append(allErrs, field.NotSupported(fldPath.Child("logging", "level"), monitoring.Logging.Level, validLevels))
		}
	}

	return allErrs
}

// validateCrossFieldDependencies validates dependencies between different fields
func (w *N8nInstanceWebhook) validateCrossFieldDependencies(instance *n8nv1alpha1.N8nInstance, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// Validate that if CloudFront is enabled, S3 assets storage is also configured
	if instance.Spec.Storage != nil && instance.Spec.Storage.Assets != nil {
		if instance.Spec.Storage.Assets.CloudFront != nil && instance.Spec.Storage.Assets.CloudFront.Enabled {
			if instance.Spec.Storage.Assets.S3 == nil {
				allErrs = append(allErrs, field.Required(fldPath.Child("storage", "assets", "s3"), "s3 configuration is required when CloudFront is enabled"))
			}
		}
	}

	// Validate that if Istio is enabled, networking configuration is present
	if instance.Spec.Networking != nil && instance.Spec.Networking.Istio != nil && instance.Spec.Networking.Istio.Enabled {
		if instance.Spec.Domain == "" {
			allErrs = append(allErrs, field.Required(fldPath.Child("domain"), "domain is required when Istio is enabled"))
		}
	}

	// Validate that secrets manager ARNs are provided when using secrets manager
	if instance.Spec.Database != nil && instance.Spec.Database.RDS != nil {
		if instance.Spec.Database.RDS.CredentialsSource == "secrets-manager" && instance.Spec.Database.RDS.SecretsManagerArn == "" {
			allErrs = append(allErrs, field.Required(fldPath.Child("database", "rds", "secretsManagerArn"), "secretsManagerArn is required when using secrets-manager"))
		}
	}

	return allErrs
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func isValidDuration(duration string) bool {
	durationRegex := regexp.MustCompile(`^(\d+(\.\d+)?)(ns|us|µs|ms|s|m|h)$`)
	return durationRegex.MatchString(duration)
}

func isValidStorageSize(size string) bool {
	sizeRegex := regexp.MustCompile(`^(\d+(\.\d+)?)(E|P|T|G|M|K|Ei|Pi|Ti|Gi|Mi|Ki)$`)
	return sizeRegex.MatchString(size)
}

func isValidS3BucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}
	bucketRegex := regexp.MustCompile(`^[a-z0-9][a-z0-9\-]*[a-z0-9]$`)
	return bucketRegex.MatchString(name) && !strings.Contains(name, "..")
}

func isValidAWSRegion(region string) bool {
	validRegions := []string{
		"us-east-1", "us-east-2", "us-west-1", "us-west-2",
		"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
		"ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1",
		"ca-central-1", "sa-east-1",
	}
	return contains(validRegions, region)
}

func isValidFileExtension(ext string) bool {
	extRegex := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	return extRegex.MatchString(ext) && len(ext) <= 10
}

func isValidFileSize(size string) bool {
	sizeRegex := regexp.MustCompile(`^(\d+(\.\d+)?)(B|KB|MB|GB|TB)$`)
	return sizeRegex.MatchString(size)
}
