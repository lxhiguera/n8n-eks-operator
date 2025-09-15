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
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// log is for logging in this package.
var n8ninstancelog = logf.Log.WithName("n8ninstance-resource")

// SetupWebhookWithManager will setup the manager to manage the webhooks
func (r *N8nInstance) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

//+kubebuilder:webhook:path=/mutate-n8n-io-v1alpha1-n8ninstance,mutating=true,failurePolicy=fail,sideEffects=None,groups=n8n.io,resources=n8ninstances,verbs=create;update,versions=v1alpha1,name=mn8ninstance.kb.io,admissionReviewVersions=v1

var _ webhook.Defaulter = &N8nInstance{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *N8nInstance) Default() {
	n8ninstancelog.Info("default", "name", r.Name)

	// Set default values for replicas
	if r.Spec.Replicas == nil {
		defaultReplicas := int32(1)
		r.Spec.Replicas = &defaultReplicas
	}

	// Set default values for AWS region if not specified
	if r.Spec.AWS != nil && r.Spec.AWS.Region == "" {
		r.Spec.AWS.Region = "us-east-1"
	}

	// Set default database type
	if r.Spec.Database != nil && r.Spec.Database.Type == "" {
		r.Spec.Database.Type = "postgres"
	}

	// Set default cache type
	if r.Spec.Cache != nil && r.Spec.Cache.Type == "" {
		r.Spec.Cache.Type = "redis"
	}

	// Set default storage type
	if r.Spec.Storage != nil && r.Spec.Storage.Type == "" {
		r.Spec.Storage.Type = "s3"
	}
}

//+kubebuilder:webhook:path=/validate-n8n-io-v1alpha1-n8ninstance,mutating=false,failurePolicy=fail,sideEffects=None,groups=n8n.io,resources=n8ninstances,verbs=create;update,versions=v1alpha1,name=vn8ninstance.kb.io,admissionReviewVersions=v1

var _ webhook.Validator = &N8nInstance{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *N8nInstance) ValidateCreate() (admission.Warnings, error) {
	n8ninstancelog.Info("validate create", "name", r.Name)
	return r.validateN8nInstance()
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *N8nInstance) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	n8ninstancelog.Info("validate update", "name", r.Name)
	return r.validateN8nInstance()
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *N8nInstance) ValidateDelete() (admission.Warnings, error) {
	n8ninstancelog.Info("validate delete", "name", r.Name)
	return nil, nil
}

// validateN8nInstance validates the N8nInstance resource
func (r *N8nInstance) validateN8nInstance() (admission.Warnings, error) {
	var allErrs []string
	var warnings admission.Warnings

	// Validate image is specified
	if r.Spec.Image == "" {
		allErrs = append(allErrs, "image cannot be empty")
	}

	// Validate replicas
	if r.Spec.Replicas != nil && *r.Spec.Replicas < 1 {
		allErrs = append(allErrs, "replicas must be at least 1")
	}

	// Validate AWS configuration if specified
	if r.Spec.AWS != nil {
		if r.Spec.AWS.Region == "" {
			allErrs = append(allErrs, "AWS region cannot be empty")
		}
	}

	// Validate database configuration if specified
	if r.Spec.Database != nil {
		if r.Spec.Database.Type != "" && r.Spec.Database.Type != "postgres" && r.Spec.Database.Type != "mysql" {
			allErrs = append(allErrs, "database type must be 'postgres' or 'mysql'")
		}

		if r.Spec.Database.Postgres != nil {
			if r.Spec.Database.Postgres.Host == "" {
				allErrs = append(allErrs, "PostgreSQL host cannot be empty")
			}
			if r.Spec.Database.Postgres.Database == "" {
				allErrs = append(allErrs, "PostgreSQL database name cannot be empty")
			}
			if r.Spec.Database.Postgres.Username == "" {
				allErrs = append(allErrs, "PostgreSQL username cannot be empty")
			}
		}
	}

	// Validate cache configuration if specified
	if r.Spec.Cache != nil {
		if r.Spec.Cache.Type != "" && r.Spec.Cache.Type != "redis" {
			allErrs = append(allErrs, "cache type must be 'redis'")
		}

		if r.Spec.Cache.Redis != nil {
			if r.Spec.Cache.Redis.Host == "" {
				allErrs = append(allErrs, "Redis host cannot be empty")
			}
		}
	}

	// Validate storage configuration if specified
	if r.Spec.Storage != nil {
		if r.Spec.Storage.Type != "" && r.Spec.Storage.Type != "s3" {
			allErrs = append(allErrs, "storage type must be 's3'")
		}

		if r.Spec.Storage.S3 != nil {
			if r.Spec.Storage.S3.Bucket == "" {
				allErrs = append(allErrs, "S3 bucket cannot be empty")
			}
			if r.Spec.Storage.S3.Region == "" {
				allErrs = append(allErrs, "S3 region cannot be empty")
			}
		}
	}

	// Validate ingress configuration if specified
	if r.Spec.Ingress != nil && r.Spec.Ingress.Enabled {
		if r.Spec.Ingress.Host == "" {
			allErrs = append(allErrs, "ingress host cannot be empty when ingress is enabled")
		}
	}

	if len(allErrs) > 0 {
		return warnings, fmt.Errorf("validation failed: %s", strings.Join(allErrs, "; "))
	}

	return warnings, nil
}
