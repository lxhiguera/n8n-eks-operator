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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// N8nInstanceSpec defines the desired state of N8nInstance
type N8nInstanceSpec struct {
	// Image specifies the n8n container image
	// +kubebuilder:validation:Required
	Image string `json:"image"`

	// Replicas specifies the number of n8n replicas
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	Replicas *int32 `json:"replicas,omitempty"`

	// AWS configuration
	// +optional
	AWS *AWSSpec `json:"aws,omitempty"`

	// Database configuration
	// +optional
	Database *DatabaseSpec `json:"database,omitempty"`

	// Cache configuration
	// +optional
	Cache *CacheSpec `json:"cache,omitempty"`

	// Storage configuration
	// +optional
	Storage *StorageSpec `json:"storage,omitempty"`

	// Ingress configuration
	// +optional
	Ingress *IngressSpec `json:"ingress,omitempty"`

	// Enterprise configuration
	// +optional
	Enterprise *EnterpriseSpec `json:"enterprise,omitempty"`

	// Monitoring configuration
	// +optional
	Monitoring *MonitoringSpec `json:"monitoring,omitempty"`

	// Backup configuration
	// +optional
	Backup *BackupSpec `json:"backup,omitempty"`
}

// AWSSpec defines AWS-specific configuration
type AWSSpec struct {
	// Region specifies the AWS region
	// +kubebuilder:validation:Required
	Region string `json:"region"`
}

// DatabaseSpec defines database configuration
type DatabaseSpec struct {
	// Type of database
	// +kubebuilder:validation:Enum=postgres;mysql
	// +kubebuilder:default=postgres
	Type string `json:"type,omitempty"`

	// PostgreSQL configuration
	// +optional
	Postgres *PostgresSpec `json:"postgres,omitempty"`
}

// PostgresSpec defines PostgreSQL configuration
type PostgresSpec struct {
	// Host of the PostgreSQL server
	// +kubebuilder:validation:Required
	Host string `json:"host"`

	// Port of the PostgreSQL server
	// +kubebuilder:default=5432
	Port int32 `json:"port,omitempty"`

	// Database name
	// +kubebuilder:validation:Required
	Database string `json:"database"`

	// Username for database connection
	// +kubebuilder:validation:Required
	Username string `json:"username"`

	// Password secret reference
	// +optional
	PasswordSecret *corev1.SecretKeySelector `json:"passwordSecret,omitempty"`

	// SSL mode
	// +kubebuilder:default=true
	SSL bool `json:"ssl,omitempty"`
}

// CacheSpec defines cache configuration
type CacheSpec struct {
	// Type of cache
	// +kubebuilder:validation:Enum=redis
	// +kubebuilder:default=redis
	Type string `json:"type,omitempty"`

	// Redis configuration
	// +optional
	Redis *RedisSpec `json:"redis,omitempty"`
}

// RedisSpec defines Redis configuration
type RedisSpec struct {
	// Host of the Redis server
	// +kubebuilder:validation:Required
	Host string `json:"host"`

	// Port of the Redis server
	// +kubebuilder:default=6379
	Port int32 `json:"port,omitempty"`

	// Database number
	// +kubebuilder:default=0
	Database int32 `json:"database,omitempty"`

	// Password secret reference
	// +optional
	PasswordSecret *corev1.SecretKeySelector `json:"passwordSecret,omitempty"`

	// SSL mode
	// +kubebuilder:default=false
	SSL bool `json:"ssl,omitempty"`
}

// StorageSpec defines storage configuration
type StorageSpec struct {
	// Type of storage
	// +kubebuilder:validation:Enum=s3
	// +kubebuilder:default=s3
	Type string `json:"type,omitempty"`

	// S3 configuration
	// +optional
	S3 *S3Spec `json:"s3,omitempty"`
}

// S3Spec defines S3 configuration
type S3Spec struct {
	// Bucket name
	// +kubebuilder:validation:Required
	Bucket string `json:"bucket"`

	// Region of the S3 bucket
	// +kubebuilder:validation:Required
	Region string `json:"region"`
}

// IngressSpec defines ingress configuration
type IngressSpec struct {
	// Enabled specifies if ingress should be created
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Host for the ingress
	// +kubebuilder:validation:Required
	Host string `json:"host"`

	// TLS configuration
	// +optional
	TLS *TLSSpec `json:"tls,omitempty"`
}

// TLSSpec defines TLS configuration
type TLSSpec struct {
	// Enabled specifies if TLS should be enabled
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Certificate ARN for AWS Certificate Manager
	// +optional
	CertificateArn string `json:"certificateArn,omitempty"`
}

// EnterpriseSpec defines enterprise features configuration
type EnterpriseSpec struct {
	// Enabled specifies if enterprise features are enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Multi-tenancy configuration
	// +optional
	MultiTenancy *MultiTenancySpec `json:"multiTenancy,omitempty"`

	// SSO configuration
	// +optional
	SSO *SSOSpec `json:"sso,omitempty"`

	// Audit logging configuration
	// +optional
	AuditLogging *AuditLoggingSpec `json:"auditLogging,omitempty"`

	// API Gateway configuration
	// +optional
	APIGateway *APIGatewaySpec `json:"apiGateway,omitempty"`

	// Compliance configuration
	// +optional
	Compliance *ComplianceSpec `json:"compliance,omitempty"`
}

// MultiTenancySpec defines multi-tenancy configuration
type MultiTenancySpec struct {
	// Enabled specifies if multi-tenancy is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Tenants configuration
	// +optional
	Tenants []TenantSpec `json:"tenants,omitempty"`
}

// TenantSpec defines a tenant configuration
type TenantSpec struct {
	// ID of the tenant
	// +kubebuilder:validation:Required
	ID string `json:"id"`

	// Name of the tenant
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Description of the tenant
	// +optional
	Description string `json:"description,omitempty"`

	// Enabled specifies if the tenant is enabled
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Metadata for the tenant
	// +optional
	Metadata map[string]string `json:"metadata,omitempty"`

	// Resource quota for the tenant
	// +optional
	ResourceQuota *TenantResourceQuotaSpec `json:"resourceQuota,omitempty"`

	// Network isolation configuration
	// +optional
	NetworkIsolation *TenantNetworkIsolationSpec `json:"networkIsolation,omitempty"`

	// Storage isolation configuration
	// +optional
	StorageIsolation *TenantStorageIsolationSpec `json:"storageIsolation,omitempty"`

	// User management configuration
	// +optional
	UserManagement *TenantUserManagementSpec `json:"userManagement,omitempty"`
}

// TenantResourceQuotaSpec defines resource quotas for a tenant
type TenantResourceQuotaSpec struct {
	// CPU quota
	// +optional
	CPU string `json:"cpu,omitempty"`

	// Memory quota
	// +optional
	Memory string `json:"memory,omitempty"`

	// Storage quota
	// +optional
	Storage string `json:"storage,omitempty"`

	// Pods quota
	// +optional
	Pods int32 `json:"pods,omitempty"`

	// Services quota
	// +optional
	Services int32 `json:"services,omitempty"`

	// Secrets quota
	// +optional
	Secrets int32 `json:"secrets,omitempty"`

	// ConfigMaps quota
	// +optional
	ConfigMaps int32 `json:"configMaps,omitempty"`

	// PersistentVolumes quota
	// +optional
	PersistentVolumes int32 `json:"persistentVolumes,omitempty"`
}

// TenantNetworkIsolationSpec defines network isolation for a tenant
type TenantNetworkIsolationSpec struct {
	// Enabled specifies if network isolation is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// VPC isolation
	// +kubebuilder:default=false
	VPCIsolation bool `json:"vpcIsolation,omitempty"`

	// Subnet isolation
	// +kubebuilder:default=false
	SubnetIsolation bool `json:"subnetIsolation,omitempty"`

	// Security groups
	// +optional
	SecurityGroups []string `json:"securityGroups,omitempty"`

	// Network policies
	// +optional
	NetworkPolicies []string `json:"networkPolicies,omitempty"`

	// Service mesh
	// +kubebuilder:default=false
	ServiceMesh bool `json:"serviceMesh,omitempty"`
}

// TenantStorageIsolationSpec defines storage isolation for a tenant
type TenantStorageIsolationSpec struct {
	// Enabled specifies if storage isolation is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Dedicated buckets
	// +kubebuilder:default=false
	DedicatedBuckets bool `json:"dedicatedBuckets,omitempty"`

	// Encryption keys
	// +optional
	EncryptionKeys []string `json:"encryptionKeys,omitempty"`

	// Access policies
	// +optional
	AccessPolicies []string `json:"accessPolicies,omitempty"`

	// Data classification
	// +optional
	DataClassification string `json:"dataClassification,omitempty"`
}

// TenantUserManagementSpec defines user management for a tenant
type TenantUserManagementSpec struct {
	// Enabled specifies if user management is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Auth provider
	// +optional
	AuthProvider string `json:"authProvider,omitempty"`

	// SSO enabled
	// +kubebuilder:default=false
	SSOEnabled bool `json:"ssoEnabled,omitempty"`

	// MFA required
	// +kubebuilder:default=false
	MFARequired bool `json:"mfaRequired,omitempty"`

	// Session timeout
	// +optional
	SessionTimeout string `json:"sessionTimeout,omitempty"`

	// Audit logging
	// +kubebuilder:default=false
	AuditLogging bool `json:"auditLogging,omitempty"`

	// Password policy
	// +optional
	PasswordPolicy *TenantPasswordPolicySpec `json:"passwordPolicy,omitempty"`

	// Role-based access control
	// +optional
	RoleBasedAccess *TenantRoleBasedAccessSpec `json:"roleBasedAccess,omitempty"`
}

// TenantPasswordPolicySpec defines password policy for a tenant
type TenantPasswordPolicySpec struct {
	// Minimum length
	// +kubebuilder:default=8
	MinLength int `json:"minLength,omitempty"`

	// Require uppercase
	// +kubebuilder:default=false
	RequireUppercase bool `json:"requireUppercase,omitempty"`

	// Require lowercase
	// +kubebuilder:default=false
	RequireLowercase bool `json:"requireLowercase,omitempty"`

	// Require numbers
	// +kubebuilder:default=false
	RequireNumbers bool `json:"requireNumbers,omitempty"`

	// Require symbols
	// +kubebuilder:default=false
	RequireSymbols bool `json:"requireSymbols,omitempty"`

	// Maximum age in days
	// +optional
	MaxAge int `json:"maxAge,omitempty"`

	// History count
	// +optional
	HistoryCount int `json:"historyCount,omitempty"`
}

// TenantRoleBasedAccessSpec defines RBAC for a tenant
type TenantRoleBasedAccessSpec struct {
	// Enabled specifies if RBAC is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Default role
	// +optional
	DefaultRole string `json:"defaultRole,omitempty"`

	// Roles
	// +optional
	Roles []TenantRoleSpec `json:"roles,omitempty"`
}

// TenantRoleSpec defines a role for a tenant
type TenantRoleSpec struct {
	// Name of the role
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Description of the role
	// +optional
	Description string `json:"description,omitempty"`

	// Permissions
	// +optional
	Permissions []TenantPermissionSpec `json:"permissions,omitempty"`
}

// TenantPermissionSpec defines a permission for a tenant role
type TenantPermissionSpec struct {
	// Resource
	// +kubebuilder:validation:Required
	Resource string `json:"resource"`

	// Actions
	// +optional
	Actions []string `json:"actions,omitempty"`

	// Scope
	// +optional
	Scope string `json:"scope,omitempty"`
}

// SSOSpec defines SSO configuration
type SSOSpec struct {
	// Enabled specifies if SSO is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Provider type
	// +kubebuilder:validation:Enum=oidc;saml
	// +optional
	Provider string `json:"provider,omitempty"`

	// OIDC configuration
	// +optional
	OIDC *OIDCSpec `json:"oidc,omitempty"`
}

// OIDCSpec defines OIDC configuration
type OIDCSpec struct {
	// Issuer URL
	// +kubebuilder:validation:Required
	IssuerUrl string `json:"issuerUrl"`

	// Client ID
	// +kubebuilder:validation:Required
	ClientId string `json:"clientId"`

	// Client secret reference
	// +optional
	ClientSecret *corev1.SecretKeySelector `json:"clientSecret,omitempty"`

	// Scopes
	// +optional
	Scopes []string `json:"scopes,omitempty"`

	// Username claim
	// +optional
	UsernameClaim string `json:"usernameClaim,omitempty"`

	// Email claim
	// +optional
	EmailClaim string `json:"emailClaim,omitempty"`

	// Groups claim
	// +optional
	GroupsClaim string `json:"groupsClaim,omitempty"`
}

// AuditLoggingSpec defines audit logging configuration
type AuditLoggingSpec struct {
	// Enabled specifies if audit logging is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Level of audit logging
	// +kubebuilder:validation:Enum=standard;detailed;verbose
	// +kubebuilder:default=standard
	Level string `json:"level,omitempty"`

	// Destinations for audit logs
	// +optional
	Destinations []string `json:"destinations,omitempty"`

	// Retention period
	// +optional
	RetentionPeriod string `json:"retentionPeriod,omitempty"`

	// Encryption enabled
	// +kubebuilder:default=false
	EncryptionEnabled bool `json:"encryptionEnabled,omitempty"`
}

// APIGatewaySpec defines API gateway configuration
type APIGatewaySpec struct {
	// Enabled specifies if API gateway is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Rate limiting configuration
	// +optional
	RateLimiting *RateLimitingSpec `json:"rateLimiting,omitempty"`

	// Authentication configuration
	// +optional
	Authentication *AuthenticationSpec `json:"authentication,omitempty"`

	// Security headers configuration
	// +optional
	SecurityHeaders *SecurityHeadersSpec `json:"securityHeaders,omitempty"`
}

// RateLimitingSpec defines rate limiting configuration
type RateLimitingSpec struct {
	// Enabled specifies if rate limiting is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Rules for rate limiting
	// +optional
	Rules []RateLimitingRuleSpec `json:"rules,omitempty"`
}

// RateLimitingRuleSpec defines a rate limiting rule
type RateLimitingRuleSpec struct {
	// Path pattern
	// +kubebuilder:validation:Required
	Path string `json:"path"`

	// Limit (e.g., "100/minute")
	// +kubebuilder:validation:Required
	Limit string `json:"limit"`

	// Burst limit
	// +optional
	Burst int32 `json:"burst,omitempty"`
}

// AuthenticationSpec defines authentication configuration
type AuthenticationSpec struct {
	// Enabled specifies if authentication is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Exempt paths from authentication
	// +optional
	ExemptPaths []string `json:"exemptPaths,omitempty"`
}

// SecurityHeadersSpec defines security headers configuration
type SecurityHeadersSpec struct {
	// Enabled specifies if security headers are enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Headers to add
	// +optional
	Headers map[string]string `json:"headers,omitempty"`
}

// ComplianceSpec defines compliance configuration
type ComplianceSpec struct {
	// Enabled specifies if compliance features are enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Standards to comply with
	// +optional
	Standards []string `json:"standards,omitempty"`

	// Data retention configuration
	// +optional
	DataRetention *DataRetentionSpec `json:"dataRetention,omitempty"`

	// Data classification configuration
	// +optional
	DataClassification *DataClassificationSpec `json:"dataClassification,omitempty"`

	// Privacy controls configuration
	// +optional
	PrivacyControls *PrivacyControlsSpec `json:"privacyControls,omitempty"`
}

// DataRetentionSpec defines data retention configuration
type DataRetentionSpec struct {
	// Enabled specifies if data retention is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Default retention period
	// +optional
	DefaultRetention string `json:"defaultRetention,omitempty"`

	// Retention policies
	// +optional
	Policies []RetentionPolicySpec `json:"policies,omitempty"`
}

// RetentionPolicySpec defines a retention policy
type RetentionPolicySpec struct {
	// Name of the policy
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Data type
	// +kubebuilder:validation:Required
	DataType string `json:"dataType"`

	// Retention period
	// +kubebuilder:validation:Required
	Retention string `json:"retention"`

	// Action to take
	// +kubebuilder:validation:Enum=delete;archive;anonymize
	// +kubebuilder:validation:Required
	Action string `json:"action"`

	// Enabled specifies if the policy is enabled
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`
}

// DataClassificationSpec defines data classification configuration
type DataClassificationSpec struct {
	// Enabled specifies if data classification is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Default classification level
	// +optional
	DefaultLevel string `json:"defaultLevel,omitempty"`

	// Classification levels
	// +optional
	Levels []ClassificationLevelSpec `json:"levels,omitempty"`

	// Auto-tagging enabled
	// +kubebuilder:default=false
	AutoTagging bool `json:"autoTagging,omitempty"`
}

// ClassificationLevelSpec defines a data classification level
type ClassificationLevelSpec struct {
	// Name of the level
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Description of the level
	// +optional
	Description string `json:"description,omitempty"`

	// Color for the level
	// +optional
	Color string `json:"color,omitempty"`

	// Policies for the level
	// +optional
	Policies []string `json:"policies,omitempty"`

	// Metadata for the level
	// +optional
	Metadata map[string]string `json:"metadata,omitempty"`
}

// PrivacyControlsSpec defines privacy controls configuration
type PrivacyControlsSpec struct {
	// Enabled specifies if privacy controls are enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// PII detection enabled
	// +kubebuilder:default=false
	PIIDetection bool `json:"piiDetection,omitempty"`

	// Data masking enabled
	// +kubebuilder:default=false
	DataMasking bool `json:"dataMasking,omitempty"`

	// Consent management enabled
	// +kubebuilder:default=false
	ConsentManagement bool `json:"consentManagement,omitempty"`

	// Right to erasure enabled
	// +kubebuilder:default=false
	RightToErasure bool `json:"rightToErasure,omitempty"`
}

// MonitoringSpec defines monitoring configuration
type MonitoringSpec struct {
	// Enabled specifies if monitoring is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Prometheus configuration
	// +optional
	Prometheus *PrometheusSpec `json:"prometheus,omitempty"`

	// Grafana configuration
	// +optional
	Grafana *GrafanaSpec `json:"grafana,omitempty"`

	// Alerting configuration
	// +optional
	Alerting *AlertingSpec `json:"alerting,omitempty"`
}

// PrometheusSpec defines Prometheus configuration
type PrometheusSpec struct {
	// Enabled specifies if Prometheus is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Service monitor enabled
	// +kubebuilder:default=false
	ServiceMonitor bool `json:"serviceMonitor,omitempty"`
}

// GrafanaSpec defines Grafana configuration
type GrafanaSpec struct {
	// Enabled specifies if Grafana is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Dashboards enabled
	// +kubebuilder:default=false
	Dashboards bool `json:"dashboards,omitempty"`
}

// AlertingSpec defines alerting configuration
type AlertingSpec struct {
	// Enabled specifies if alerting is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`
}

// BackupSpec defines backup configuration
type BackupSpec struct {
	// Enabled specifies if backup is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Schedule for backups (cron format)
	// +optional
	Schedule string `json:"schedule,omitempty"`

	// Retention period for backups
	// +optional
	Retention string `json:"retention,omitempty"`

	// Encryption enabled for backups
	// +kubebuilder:default=false
	Encryption bool `json:"encryption,omitempty"`
}

// N8nInstanceStatus defines the observed state of N8nInstance
type N8nInstanceStatus struct {
	// Phase represents the current phase of the N8nInstance
	// +optional
	Phase string `json:"phase,omitempty"`

	// Conditions represent the latest available observations of the N8nInstance's current state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the most recent generation observed by the controller
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Endpoints contains the endpoints for accessing n8n
	// +optional
	Endpoints *N8nEndpoints `json:"endpoints,omitempty"`

	// Database status
	// +optional
	Database *DatabaseStatus `json:"database,omitempty"`

	// Cache status
	// +optional
	Cache *CacheStatus `json:"cache,omitempty"`

	// Storage status
	// +optional
	Storage *StorageStatus `json:"storage,omitempty"`
}

// N8nEndpoints contains the endpoints for accessing n8n
type N8nEndpoints struct {
	// Main endpoint for the n8n UI
	// +optional
	Main string `json:"main,omitempty"`

	// Webhook endpoint for receiving webhooks
	// +optional
	Webhook string `json:"webhook,omitempty"`
}

// DatabaseStatus represents the status of the database
type DatabaseStatus struct {
	// Ready indicates if the database is ready
	// +optional
	Ready bool `json:"ready,omitempty"`

	// Message contains additional information about the database status
	// +optional
	Message string `json:"message,omitempty"`
}

// CacheStatus represents the status of the cache
type CacheStatus struct {
	// Ready indicates if the cache is ready
	// +optional
	Ready bool `json:"ready,omitempty"`

	// Message contains additional information about the cache status
	// +optional
	Message string `json:"message,omitempty"`
}

// StorageStatus represents the status of the storage
type StorageStatus struct {
	// Ready indicates if the storage is ready
	// +optional
	Ready bool `json:"ready,omitempty"`

	// Message contains additional information about the storage status
	// +optional
	Message string `json:"message,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Namespaced
//+kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
//+kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
//+kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// N8nInstance is the Schema for the n8ninstances API
type N8nInstance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   N8nInstanceSpec   `json:"spec,omitempty"`
	Status N8nInstanceStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// N8nInstanceList contains a list of N8nInstance
type N8nInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []N8nInstance `json:"items"`
}

func init() {
	SchemeBuilder.Register(&N8nInstance{}, &N8nInstanceList{})
}
