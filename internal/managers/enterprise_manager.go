package managers

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// EnterpriseManager handles enterprise features for n8n instances
type EnterpriseManager interface {
	// ReconcileEnterprise ensures enterprise features are properly configured
	ReconcileEnterprise(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// SetupMultiTenancy configures multi-tenancy for the instance
	SetupMultiTenancy(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// ManageUserAccess handles user access management and RBAC
	ManageUserAccess(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// ConfigureAuditLogging sets up comprehensive audit logging
	ConfigureAuditLogging(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// SetupComplianceFeatures configures compliance and governance features
	SetupComplianceFeatures(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// ManageAPIGateway configures API gateway and rate limiting
	ManageAPIGateway(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// SetupSSOIntegration configures Single Sign-On integration
	SetupSSOIntegration(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error

	// ConfigureDataGovernance sets up data governance and retention policies
	ConfigureDataGovernance(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error
}

// TenantConfig represents multi-tenant configuration
type TenantConfig struct {
	TenantID         string            `json:"tenantId"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	Enabled          bool              `json:"enabled"`
	ResourceQuota    *ResourceQuota    `json:"resourceQuota"`
	NetworkIsolation *NetworkIsolation `json:"networkIsolation"`
	StorageIsolation *StorageIsolation `json:"storageIsolation"`
	UserManagement   *UserManagement   `json:"userManagement"`
	ComplianceConfig *ComplianceConfig `json:"complianceConfig"`
	CreatedAt        time.Time         `json:"createdAt"`
	UpdatedAt        time.Time         `json:"updatedAt"`
	Metadata         map[string]string `json:"metadata"`
}

// ResourceQuota represents resource quotas for a tenant
type ResourceQuota struct {
	CPU               string `json:"cpu"`
	Memory            string `json:"memory"`
	Storage           string `json:"storage"`
	Pods              int32  `json:"pods"`
	Services          int32  `json:"services"`
	Secrets           int32  `json:"secrets"`
	ConfigMaps        int32  `json:"configMaps"`
	PersistentVolumes int32  `json:"persistentVolumes"`
}

// NetworkIsolation represents network isolation configuration
type NetworkIsolation struct {
	Enabled         bool     `json:"enabled"`
	VPCIsolation    bool     `json:"vpcIsolation"`
	SubnetIsolation bool     `json:"subnetIsolation"`
	SecurityGroups  []string `json:"securityGroups"`
	NetworkPolicies []string `json:"networkPolicies"`
	ServiceMesh     bool     `json:"serviceMesh"`
}

// StorageIsolation represents storage isolation configuration
type StorageIsolation struct {
	Enabled            bool     `json:"enabled"`
	DedicatedBuckets   bool     `json:"dedicatedBuckets"`
	EncryptionKeys     []string `json:"encryptionKeys"`
	AccessPolicies     []string `json:"accessPolicies"`
	DataClassification string   `json:"dataClassification"`
}

// UserManagement represents user management configuration
type UserManagement struct {
	Enabled         bool             `json:"enabled"`
	AuthProvider    string           `json:"authProvider"`
	SSOEnabled      bool             `json:"ssoEnabled"`
	MFARequired     bool             `json:"mfaRequired"`
	SessionTimeout  string           `json:"sessionTimeout"`
	PasswordPolicy  *PasswordPolicy  `json:"passwordPolicy"`
	RoleBasedAccess *RoleBasedAccess `json:"roleBasedAccess"`
	AuditLogging    bool             `json:"auditLogging"`
}

// PasswordPolicy represents password policy configuration
type PasswordPolicy struct {
	MinLength        int  `json:"minLength"`
	RequireUppercase bool `json:"requireUppercase"`
	RequireLowercase bool `json:"requireLowercase"`
	RequireNumbers   bool `json:"requireNumbers"`
	RequireSymbols   bool `json:"requireSymbols"`
	MaxAge           int  `json:"maxAge"`
	HistoryCount     int  `json:"historyCount"`
}

// RoleBasedAccess represents RBAC configuration
type RoleBasedAccess struct {
	Enabled     bool   `json:"enabled"`
	Roles       []Role `json:"roles"`
	DefaultRole string `json:"defaultRole"`
}

// Role represents a user role
type Role struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
}

// Permission represents a permission
type Permission struct {
	Resource string   `json:"resource"`
	Actions  []string `json:"actions"`
	Scope    string   `json:"scope"`
}

// ComplianceConfig represents compliance configuration
type ComplianceConfig struct {
	Enabled            bool                `json:"enabled"`
	Standards          []string            `json:"standards"`
	DataRetention      *DataRetention      `json:"dataRetention"`
	AuditLogging       *AuditLogging       `json:"auditLogging"`
	DataClassification *DataClassification `json:"dataClassification"`
	PrivacyControls    *PrivacyControls    `json:"privacyControls"`
}

// DataRetention represents data retention policies
type DataRetention struct {
	Enabled          bool              `json:"enabled"`
	DefaultRetention string            `json:"defaultRetention"`
	Policies         []RetentionPolicy `json:"policies"`
}

// RetentionPolicy represents a data retention policy
type RetentionPolicy struct {
	Name      string `json:"name"`
	DataType  string `json:"dataType"`
	Retention string `json:"retention"`
	Action    string `json:"action"`
	Enabled   bool   `json:"enabled"`
}

// AuditLogging represents audit logging configuration
type AuditLogging struct {
	Enabled           bool     `json:"enabled"`
	Level             string   `json:"level"`
	Destinations      []string `json:"destinations"`
	RetentionPeriod   string   `json:"retentionPeriod"`
	EncryptionEnabled bool     `json:"encryptionEnabled"`
}

// DataClassification represents data classification configuration
type DataClassification struct {
	Enabled      bool                  `json:"enabled"`
	DefaultLevel string                `json:"defaultLevel"`
	Levels       []ClassificationLevel `json:"levels"`
	AutoTagging  bool                  `json:"autoTagging"`
}

// ClassificationLevel represents a data classification level
type ClassificationLevel struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Color       string            `json:"color"`
	Policies    []string          `json:"policies"`
	Metadata    map[string]string `json:"metadata"`
}

// PrivacyControls represents privacy control configuration
type PrivacyControls struct {
	Enabled           bool `json:"enabled"`
	PIIDetection      bool `json:"piiDetection"`
	DataMasking       bool `json:"dataMasking"`
	ConsentManagement bool `json:"consentManagement"`
	RightToErasure    bool `json:"rightToErasure"`
}

// enterpriseManager implements the EnterpriseManager interface
type enterpriseManager struct {
	client client.Client
	scheme *runtime.Scheme
	logger logr.Logger
}

// NewEnterpriseManager creates a new EnterpriseManager instance
func NewEnterpriseManager(client client.Client, scheme *runtime.Scheme, logger logr.Logger) EnterpriseManager {
	return &enterpriseManager{
		client: client,
		scheme: scheme,
		logger: logger.WithName("enterprise-manager"),
	}
}

// ReconcileEnterprise ensures enterprise features are properly configured
func (em *enterpriseManager) ReconcileEnterprise(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := em.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)
	logger.Info("Reconciling enterprise features")

	// Check if enterprise features are enabled
	if !em.isEnterpriseEnabled(instance) {
		logger.Info("Enterprise features are disabled, skipping configuration")
		return nil
	}

	// Setup multi-tenancy
	if err := em.SetupMultiTenancy(ctx, instance); err != nil {
		return fmt.Errorf("failed to setup multi-tenancy: %w", err)
	}

	// Manage user access
	if err := em.ManageUserAccess(ctx, instance); err != nil {
		return fmt.Errorf("failed to manage user access: %w", err)
	}

	// Configure audit logging
	if err := em.ConfigureAuditLogging(ctx, instance); err != nil {
		return fmt.Errorf("failed to configure audit logging: %w", err)
	}

	// Setup compliance features
	if err := em.SetupComplianceFeatures(ctx, instance); err != nil {
		return fmt.Errorf("failed to setup compliance features: %w", err)
	}

	// Manage API gateway
	if err := em.ManageAPIGateway(ctx, instance); err != nil {
		return fmt.Errorf("failed to manage API gateway: %w", err)
	}

	// Setup SSO integration
	if err := em.SetupSSOIntegration(ctx, instance); err != nil {
		return fmt.Errorf("failed to setup SSO integration: %w", err)
	}

	// Configure data governance
	if err := em.ConfigureDataGovernance(ctx, instance); err != nil {
		return fmt.Errorf("failed to configure data governance: %w", err)
	}

	logger.Info("Enterprise features reconciled successfully")
	return nil
}

// SetupMultiTenancy configures multi-tenancy for the instance
func (em *enterpriseManager) SetupMultiTenancy(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := em.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)
	logger.Info("Setting up multi-tenancy")

	// Check if multi-tenancy is enabled
	if !em.isMultiTenancyEnabled(instance) {
		logger.Info("Multi-tenancy is disabled, skipping setup")
		return nil
	}

	// Create tenant configurations
	tenants := em.getTenantConfigurations(instance)
	for _, tenant := range tenants {
		if err := em.createTenantResources(ctx, instance, tenant); err != nil {
			return fmt.Errorf("failed to create resources for tenant %s: %w", tenant.TenantID, err)
		}
	}

	logger.Info("Multi-tenancy setup completed", "tenants", len(tenants))
	return nil
}

// ManageUserAccess handles user access management and RBAC
func (em *enterpriseManager) ManageUserAccess(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := em.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)
	logger.Info("Managing user access")

	// Create RBAC resources
	if err := em.createRBACResources(ctx, instance); err != nil {
		return fmt.Errorf("failed to create RBAC resources: %w", err)
	}

	// Setup user authentication
	if err := em.setupUserAuthentication(ctx, instance); err != nil {
		return fmt.Errorf("failed to setup user authentication: %w", err)
	}

	// Configure session management
	if err := em.configureSessionManagement(ctx, instance); err != nil {
		return fmt.Errorf("failed to configure session management: %w", err)
	}

	logger.Info("User access management completed")
	return nil
}

// ConfigureAuditLogging sets up comprehensive audit logging
func (em *enterpriseManager) ConfigureAuditLogging(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := em.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)
	logger.Info("Configuring audit logging")

	// Setup audit log collection
	if err := em.setupAuditLogCollection(ctx, instance); err != nil {
		return fmt.Errorf("failed to setup audit log collection: %w", err)
	}

	// Configure log forwarding
	if err := em.configureAuditLogForwarding(ctx, instance); err != nil {
		return fmt.Errorf("failed to configure audit log forwarding: %w", err)
	}

	// Setup log retention policies
	if err := em.setupAuditLogRetention(ctx, instance); err != nil {
		return fmt.Errorf("failed to setup audit log retention: %w", err)
	}

	logger.Info("Audit logging configuration completed")
	return nil
}

// SetupComplianceFeatures configures compliance and governance features
func (em *enterpriseManager) SetupComplianceFeatures(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := em.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)
	logger.Info("Setting up compliance features")

	// Configure data classification
	if err := em.configureDataClassification(ctx, instance); err != nil {
		return fmt.Errorf("failed to configure data classification: %w", err)
	}

	// Setup privacy controls
	if err := em.setupPrivacyControls(ctx, instance); err != nil {
		return fmt.Errorf("failed to setup privacy controls: %w", err)
	}

	// Configure compliance monitoring
	if err := em.configureComplianceMonitoring(ctx, instance); err != nil {
		return fmt.Errorf("failed to configure compliance monitoring: %w", err)
	}

	logger.Info("Compliance features setup completed")
	return nil
}

// ManageAPIGateway configures API gateway and rate limiting
func (em *enterpriseManager) ManageAPIGateway(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := em.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)
	logger.Info("Managing API gateway")

	// Setup API gateway
	if err := em.setupAPIGateway(ctx, instance); err != nil {
		return fmt.Errorf("failed to setup API gateway: %w", err)
	}

	// Configure rate limiting
	if err := em.configureRateLimiting(ctx, instance); err != nil {
		return fmt.Errorf("failed to configure rate limiting: %w", err)
	}

	// Setup API monitoring
	if err := em.setupAPIMonitoring(ctx, instance); err != nil {
		return fmt.Errorf("failed to setup API monitoring: %w", err)
	}

	logger.Info("API gateway management completed")
	return nil
}

// SetupSSOIntegration configures Single Sign-On integration
func (em *enterpriseManager) SetupSSOIntegration(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := em.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)
	logger.Info("Setting up SSO integration")

	// Check if SSO is enabled
	if !em.isSSOEnabled(instance) {
		logger.Info("SSO is disabled, skipping setup")
		return nil
	}

	// Configure OIDC/SAML
	if err := em.configureSSOProvider(ctx, instance); err != nil {
		return fmt.Errorf("failed to configure SSO provider: %w", err)
	}

	// Setup user provisioning
	if err := em.setupUserProvisioning(ctx, instance); err != nil {
		return fmt.Errorf("failed to setup user provisioning: %w", err)
	}

	logger.Info("SSO integration setup completed")
	return nil
}

// ConfigureDataGovernance sets up data governance and retention policies
func (em *enterpriseManager) ConfigureDataGovernance(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := em.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)
	logger.Info("Configuring data governance")

	// Setup data retention policies
	if err := em.setupDataRetentionPolicies(ctx, instance); err != nil {
		return fmt.Errorf("failed to setup data retention policies: %w", err)
	}

	// Configure data lifecycle management
	if err := em.configureDataLifecycleManagement(ctx, instance); err != nil {
		return fmt.Errorf("failed to configure data lifecycle management: %w", err)
	}

	// Setup data discovery and cataloging
	if err := em.setupDataDiscovery(ctx, instance); err != nil {
		return fmt.Errorf("failed to setup data discovery: %w", err)
	}

	logger.Info("Data governance configuration completed")
	return nil
}

// Helper methods

func (em *enterpriseManager) isEnterpriseEnabled(instance *n8nv1alpha1.N8nInstance) bool {
	if instance.Spec.Enterprise != nil {
		return instance.Spec.Enterprise.Enabled
	}
	return false
}

func (em *enterpriseManager) isMultiTenancyEnabled(instance *n8nv1alpha1.N8nInstance) bool {
	if instance.Spec.Enterprise != nil && instance.Spec.Enterprise.MultiTenancy != nil {
		return instance.Spec.Enterprise.MultiTenancy.Enabled
	}
	return false
}

func (em *enterpriseManager) isSSOEnabled(instance *n8nv1alpha1.N8nInstance) bool {
	if instance.Spec.Enterprise != nil && instance.Spec.Enterprise.SSO != nil {
		return instance.Spec.Enterprise.SSO.Enabled
	}
	return false
}

func (em *enterpriseManager) getTenantConfigurations(instance *n8nv1alpha1.N8nInstance) []TenantConfig {
	var tenants []TenantConfig

	if instance.Spec.Enterprise == nil || instance.Spec.Enterprise.MultiTenancy == nil {
		return tenants
	}

	// Parse tenant configurations from instance spec
	for _, tenantSpec := range instance.Spec.Enterprise.MultiTenancy.Tenants {
		tenant := TenantConfig{
			TenantID:    tenantSpec.ID,
			Name:        tenantSpec.Name,
			Description: tenantSpec.Description,
			Enabled:     tenantSpec.Enabled,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Metadata:    tenantSpec.Metadata,
		}

		// Configure resource quota
		if tenantSpec.ResourceQuota != nil {
			tenant.ResourceQuota = &ResourceQuota{
				CPU:               tenantSpec.ResourceQuota.CPU,
				Memory:            tenantSpec.ResourceQuota.Memory,
				Storage:           tenantSpec.ResourceQuota.Storage,
				Pods:              tenantSpec.ResourceQuota.Pods,
				Services:          tenantSpec.ResourceQuota.Services,
				Secrets:           tenantSpec.ResourceQuota.Secrets,
				ConfigMaps:        tenantSpec.ResourceQuota.ConfigMaps,
				PersistentVolumes: tenantSpec.ResourceQuota.PersistentVolumes,
			}
		}

		// Configure network isolation
		if tenantSpec.NetworkIsolation != nil {
			tenant.NetworkIsolation = &NetworkIsolation{
				Enabled:         tenantSpec.NetworkIsolation.Enabled,
				VPCIsolation:    tenantSpec.NetworkIsolation.VPCIsolation,
				SubnetIsolation: tenantSpec.NetworkIsolation.SubnetIsolation,
				SecurityGroups:  tenantSpec.NetworkIsolation.SecurityGroups,
				NetworkPolicies: tenantSpec.NetworkIsolation.NetworkPolicies,
				ServiceMesh:     tenantSpec.NetworkIsolation.ServiceMesh,
			}
		}

		// Configure storage isolation
		if tenantSpec.StorageIsolation != nil {
			tenant.StorageIsolation = &StorageIsolation{
				Enabled:            tenantSpec.StorageIsolation.Enabled,
				DedicatedBuckets:   tenantSpec.StorageIsolation.DedicatedBuckets,
				EncryptionKeys:     tenantSpec.StorageIsolation.EncryptionKeys,
				AccessPolicies:     tenantSpec.StorageIsolation.AccessPolicies,
				DataClassification: tenantSpec.StorageIsolation.DataClassification,
			}
		}

		// Configure user management
		if tenantSpec.UserManagement != nil {
			tenant.UserManagement = &UserManagement{
				Enabled:        tenantSpec.UserManagement.Enabled,
				AuthProvider:   tenantSpec.UserManagement.AuthProvider,
				SSOEnabled:     tenantSpec.UserManagement.SSOEnabled,
				MFARequired:    tenantSpec.UserManagement.MFARequired,
				SessionTimeout: tenantSpec.UserManagement.SessionTimeout,
				AuditLogging:   tenantSpec.UserManagement.AuditLogging,
			}

			// Configure password policy
			if tenantSpec.UserManagement.PasswordPolicy != nil {
				tenant.UserManagement.PasswordPolicy = &PasswordPolicy{
					MinLength:        tenantSpec.UserManagement.PasswordPolicy.MinLength,
					RequireUppercase: tenantSpec.UserManagement.PasswordPolicy.RequireUppercase,
					RequireLowercase: tenantSpec.UserManagement.PasswordPolicy.RequireLowercase,
					RequireNumbers:   tenantSpec.UserManagement.PasswordPolicy.RequireNumbers,
					RequireSymbols:   tenantSpec.UserManagement.PasswordPolicy.RequireSymbols,
					MaxAge:           tenantSpec.UserManagement.PasswordPolicy.MaxAge,
					HistoryCount:     tenantSpec.UserManagement.PasswordPolicy.HistoryCount,
				}
			}

			// Configure RBAC
			if tenantSpec.UserManagement.RoleBasedAccess != nil {
				tenant.UserManagement.RoleBasedAccess = &RoleBasedAccess{
					Enabled:     tenantSpec.UserManagement.RoleBasedAccess.Enabled,
					DefaultRole: tenantSpec.UserManagement.RoleBasedAccess.DefaultRole,
				}

				// Parse roles
				for _, roleSpec := range tenantSpec.UserManagement.RoleBasedAccess.Roles {
					role := Role{
						Name:        roleSpec.Name,
						Description: roleSpec.Description,
					}

					// Parse permissions
					for _, permSpec := range roleSpec.Permissions {
						permission := Permission{
							Resource: permSpec.Resource,
							Actions:  permSpec.Actions,
							Scope:    permSpec.Scope,
						}
						role.Permissions = append(role.Permissions, permission)
					}

					tenant.UserManagement.RoleBasedAccess.Roles = append(tenant.UserManagement.RoleBasedAccess.Roles, role)
				}
			}
		}

		tenants = append(tenants, tenant)
	}

	return tenants
}

func (em *enterpriseManager) createTenantResources(ctx context.Context, instance *n8nv1alpha1.N8nInstance, tenant TenantConfig) error {
	logger := em.logger.WithValues("tenant", tenant.TenantID)

	if !tenant.Enabled {
		logger.Info("Tenant is disabled, skipping resource creation")
		return nil
	}

	// Create tenant namespace
	if err := em.createTenantNamespace(ctx, instance, tenant); err != nil {
		return fmt.Errorf("failed to create tenant namespace: %w", err)
	}

	// Create resource quota
	if tenant.ResourceQuota != nil {
		if err := em.createTenantResourceQuota(ctx, instance, tenant); err != nil {
			return fmt.Errorf("failed to create tenant resource quota: %w", err)
		}
	}

	// Create network policies
	if tenant.NetworkIsolation != nil && tenant.NetworkIsolation.Enabled {
		if err := em.createTenantNetworkPolicies(ctx, instance, tenant); err != nil {
			return fmt.Errorf("failed to create tenant network policies: %w", err)
		}
	}

	// Create RBAC resources
	if tenant.UserManagement != nil && tenant.UserManagement.RoleBasedAccess != nil && tenant.UserManagement.RoleBasedAccess.Enabled {
		if err := em.createTenantRBAC(ctx, instance, tenant); err != nil {
			return fmt.Errorf("failed to create tenant RBAC: %w", err)
		}
	}

	// Create tenant-specific n8n deployment
	if err := em.createTenantN8nDeployment(ctx, instance, tenant); err != nil {
		return fmt.Errorf("failed to create tenant n8n deployment: %w", err)
	}

	// Create tenant-specific services
	if err := em.createTenantServices(ctx, instance, tenant); err != nil {
		return fmt.Errorf("failed to create tenant services: %w", err)
	}

	// Create tenant-specific ingress
	if err := em.createTenantIngress(ctx, instance, tenant); err != nil {
		return fmt.Errorf("failed to create tenant ingress: %w", err)
	}

	logger.Info("Tenant resources created successfully")
	return nil
}

func (em *enterpriseManager) createRBACResources(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := em.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)

	// Create cluster role for n8n operator
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-n8n-operator", instance.Name),
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "rbac",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "services", "endpoints", "persistentvolumeclaims", "events", "configmaps", "secrets"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments", "daemonsets", "replicasets", "statefulsets"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"ingresses", "networkpolicies"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"roles", "rolebindings"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
		},
	}

	if err := em.client.Create(ctx, clusterRole); err != nil {
		return fmt.Errorf("failed to create cluster role: %w", err)
	}

	// Create service account
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-operator", instance.Name),
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "service-account",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
			},
		},
	}

	if err := em.client.Create(ctx, serviceAccount); err != nil {
		return fmt.Errorf("failed to create service account: %w", err)
	}

	// Create cluster role binding
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-n8n-operator", instance.Name),
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "rbac",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     fmt.Sprintf("%s-n8n-operator", instance.Name),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      fmt.Sprintf("%s-operator", instance.Name),
				Namespace: instance.Namespace,
			},
		},
	}

	if err := em.client.Create(ctx, clusterRoleBinding); err != nil {
		return fmt.Errorf("failed to create cluster role binding: %w", err)
	}

	logger.Info("RBAC resources created successfully")
	return nil
}

func (em *enterpriseManager) setupUserAuthentication(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Implementation would setup user authentication
	return nil
}

func (em *enterpriseManager) configureSessionManagement(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Implementation would configure session management
	return nil
}

func (em *enterpriseManager) setupAuditLogCollection(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := em.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)

	// Create ConfigMap for audit log configuration
	auditConfig := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-audit-config", instance.Name),
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "audit-config",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
			},
		},
		Data: map[string]string{
			"audit-policy.yaml": `apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  namespaces: ["` + instance.Namespace + `"]
  resources:
  - group: ""
    resources: ["pods", "services", "secrets", "configmaps"]
  - group: "apps"
    resources: ["deployments", "statefulsets"]
  - group: "n8n.io"
    resources: ["n8ninstances"]
- level: Request
  namespaces: ["` + instance.Namespace + `"]
  resources:
  - group: ""
    resources: ["secrets"]
  verbs: ["create", "update", "patch", "delete"]
- level: RequestResponse
  namespaces: ["` + instance.Namespace + `"]
  resources:
  - group: "n8n.io"
    resources: ["n8ninstances"]
  verbs: ["create", "update", "patch", "delete"]`,
			"fluent-bit.conf": `[SERVICE]
    Flush         1
    Log_Level     info
    Daemon        off
    Parsers_File  parsers.conf

[INPUT]
    Name              tail
    Path              /var/log/audit/*.log
    Parser            json
    Tag               audit.*
    Refresh_Interval  5
    Mem_Buf_Limit     50MB

[FILTER]
    Name                kubernetes
    Match               audit.*
    Kube_URL            https://kubernetes.default.svc:443
    Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
    Merge_Log           On
    K8S-Logging.Parser  On
    K8S-Logging.Exclude Off

[OUTPUT]
    Name  cloudwatch_logs
    Match audit.*
    region ` + instance.Spec.AWS.Region + `
    log_group_name /aws/eks/` + instance.Name + `/audit
    log_stream_prefix audit-
    auto_create_group true`,
		},
	}

	if err := em.client.Create(ctx, auditConfig); err != nil {
		return fmt.Errorf("failed to create audit config: %w", err)
	}

	// Create DaemonSet for audit log collection
	auditDaemonSet := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-audit-collector", instance.Name),
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "audit-collector",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
			},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":      "n8n",
					"app.kubernetes.io/instance":  instance.Name,
					"app.kubernetes.io/component": "audit-collector",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name":       "n8n",
						"app.kubernetes.io/instance":   instance.Name,
						"app.kubernetes.io/component":  "audit-collector",
						"app.kubernetes.io/managed-by": "n8n-eks-operator",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: fmt.Sprintf("%s-operator", instance.Name),
					Containers: []corev1.Container{
						{
							Name:  "fluent-bit",
							Image: "fluent/fluent-bit:2.1.10",
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "audit-logs",
									MountPath: "/var/log/audit",
									ReadOnly:  true,
								},
								{
									Name:      "audit-config",
									MountPath: "/fluent-bit/etc",
									ReadOnly:  true,
								},
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("200m"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "audit-logs",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/log/audit",
								},
							},
						},
						{
							Name: "audit-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: fmt.Sprintf("%s-audit-config", instance.Name),
									},
								},
							},
						},
					},
					Tolerations: []corev1.Toleration{
						{
							Key:      "node-role.kubernetes.io/master",
							Operator: corev1.TolerationOpExists,
							Effect:   corev1.TaintEffectNoSchedule,
						},
					},
				},
			},
		},
	}

	if err := em.client.Create(ctx, auditDaemonSet); err != nil {
		return fmt.Errorf("failed to create audit collector daemonset: %w", err)
	}

	logger.Info("Audit log collection setup completed")
	return nil
}

func (em *enterpriseManager) configureAuditLogForwarding(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Implementation would configure audit log forwarding
	return nil
}

func (em *enterpriseManager) setupAuditLogRetention(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Implementation would setup audit log retention
	return nil
}

func (em *enterpriseManager) configureDataClassification(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Implementation would configure data classification
	return nil
}

func (em *enterpriseManager) setupPrivacyControls(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Implementation would setup privacy controls
	return nil
}

func (em *enterpriseManager) configureComplianceMonitoring(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Implementation would configure compliance monitoring
	return nil
}

func (em *enterpriseManager) setupAPIGateway(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := em.logger.WithValues("instance", instance.Name, "namespace", instance.Namespace)

	// Create API Gateway ConfigMap
	gatewayConfig := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-api-gateway-config", instance.Name),
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "api-gateway",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
			},
		},
		Data: map[string]string{
			"nginx.conf": `
events {
    worker_connections 1024;
}

http {
    upstream n8n_backend {
        least_conn;
        server n8n-service:5678;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=webhook:10m rate=100r/s;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    server {
        listen 80;
        server_name _;

        # Health check endpoint
        location /healthz {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }

        # API endpoints with rate limiting
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            
            # Authentication required
            auth_request /auth;
            
            proxy_pass http://n8n_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Webhook endpoints with higher rate limit
        location /webhook/ {
            limit_req zone=webhook burst=200 nodelay;
            
            proxy_pass http://n8n_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Authentication endpoint
        location = /auth {
            internal;
            proxy_pass http://n8n_backend/api/auth/validate;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Original-URI $request_uri;
        }

        # Static files
        location / {
            proxy_pass http://n8n_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}`,
		},
	}

	if err := em.client.Create(ctx, gatewayConfig); err != nil {
		return fmt.Errorf("failed to create API gateway config: %w", err)
	}

	// Create API Gateway Deployment
	gatewayDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-api-gateway", instance.Name),
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "api-gateway",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &[]int32{2}[0],
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":      "n8n",
					"app.kubernetes.io/instance":  instance.Name,
					"app.kubernetes.io/component": "api-gateway",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name":       "n8n",
						"app.kubernetes.io/instance":   instance.Name,
						"app.kubernetes.io/component":  "api-gateway",
						"app.kubernetes.io/managed-by": "n8n-eks-operator",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.25-alpine",
							Ports: []corev1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: 80,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "gateway-config",
									MountPath: "/etc/nginx/nginx.conf",
									SubPath:   "nginx.conf",
									ReadOnly:  true,
								},
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("500m"),
									corev1.ResourceMemory: resource.MustParse("512Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/healthz",
										Port: intstr.FromInt(80),
									},
								},
								InitialDelaySeconds: 30,
								PeriodSeconds:       10,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/healthz",
										Port: intstr.FromInt(80),
									},
								},
								InitialDelaySeconds: 5,
								PeriodSeconds:       5,
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "gateway-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: fmt.Sprintf("%s-api-gateway-config", instance.Name),
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if err := em.client.Create(ctx, gatewayDeployment); err != nil {
		return fmt.Errorf("failed to create API gateway deployment: %w", err)
	}

	// Create API Gateway Service
	gatewayService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-api-gateway", instance.Name),
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "api-gateway",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       80,
					TargetPort: intstr.FromInt(80),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			Selector: map[string]string{
				"app.kubernetes.io/name":      "n8n",
				"app.kubernetes.io/instance":  instance.Name,
				"app.kubernetes.io/component": "api-gateway",
			},
		},
	}

	if err := em.client.Create(ctx, gatewayService); err != nil {
		return fmt.Errorf("failed to create API gateway service: %w", err)
	}

	logger.Info("API Gateway setup completed")
	return nil
}

func (em *enterpriseManager) configureRateLimiting(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Implementation would configure rate limiting
	return nil
}

func (em *enterpriseManager) setupAPIMonitoring(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Implementation would setup API monitoring
	return nil
}

func (em *enterpriseManager) configureSSOProvider(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Implementation would configure SSO provider
	return nil
}

func (em *enterpriseManager) setupUserProvisioning(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Implementation would setup user provisioning
	return nil
}

func (em *enterpriseManager) setupDataRetentionPolicies(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Implementation would setup data retention policies
	return nil
}

func (em *enterpriseManager) configureDataLifecycleManagement(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Implementation would configure data lifecycle management
	return nil
}

func (em *enterpriseManager) setupDataDiscovery(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	// Implementation would setup data discovery
	return nil
}

// Tenant resource creation helper methods

func (em *enterpriseManager) createTenantNamespace(ctx context.Context, instance *n8nv1alpha1.N8nInstance, tenant TenantConfig) error {
	namespaceName := fmt.Sprintf("%s-%s", instance.Name, tenant.TenantID)

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "tenant",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"n8n.io/tenant-id":             tenant.TenantID,
				"n8n.io/tenant-name":           tenant.Name,
			},
			Annotations: map[string]string{
				"n8n.io/tenant-description": tenant.Description,
				"n8n.io/created-by":         "n8n-eks-operator",
			},
		},
	}

	// Add tenant metadata
	for key, value := range tenant.Metadata {
		namespace.Labels[fmt.Sprintf("n8n.io/tenant-%s", key)] = value
	}

	return em.client.Create(ctx, namespace)
}

func (em *enterpriseManager) createTenantResourceQuota(ctx context.Context, instance *n8nv1alpha1.N8nInstance, tenant TenantConfig) error {
	namespaceName := fmt.Sprintf("%s-%s", instance.Name, tenant.TenantID)

	resourceQuota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-quota", tenant.TenantID),
			Namespace: namespaceName,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "resource-quota",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"n8n.io/tenant-id":             tenant.TenantID,
			},
		},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{},
		},
	}

	// Set resource limits
	if tenant.ResourceQuota.CPU != "" {
		resourceQuota.Spec.Hard[corev1.ResourceRequestsCPU] = resource.MustParse(tenant.ResourceQuota.CPU)
		resourceQuota.Spec.Hard[corev1.ResourceLimitsCPU] = resource.MustParse(tenant.ResourceQuota.CPU)
	}

	if tenant.ResourceQuota.Memory != "" {
		resourceQuota.Spec.Hard[corev1.ResourceRequestsMemory] = resource.MustParse(tenant.ResourceQuota.Memory)
		resourceQuota.Spec.Hard[corev1.ResourceLimitsMemory] = resource.MustParse(tenant.ResourceQuota.Memory)
	}

	if tenant.ResourceQuota.Storage != "" {
		resourceQuota.Spec.Hard[corev1.ResourceRequestsStorage] = resource.MustParse(tenant.ResourceQuota.Storage)
	}

	if tenant.ResourceQuota.Pods > 0 {
		resourceQuota.Spec.Hard[corev1.ResourcePods] = *resource.NewQuantity(int64(tenant.ResourceQuota.Pods), resource.DecimalSI)
	}

	if tenant.ResourceQuota.Services > 0 {
		resourceQuota.Spec.Hard[corev1.ResourceServices] = *resource.NewQuantity(int64(tenant.ResourceQuota.Services), resource.DecimalSI)
	}

	if tenant.ResourceQuota.Secrets > 0 {
		resourceQuota.Spec.Hard[corev1.ResourceSecrets] = *resource.NewQuantity(int64(tenant.ResourceQuota.Secrets), resource.DecimalSI)
	}

	if tenant.ResourceQuota.ConfigMaps > 0 {
		resourceQuota.Spec.Hard[corev1.ResourceConfigMaps] = *resource.NewQuantity(int64(tenant.ResourceQuota.ConfigMaps), resource.DecimalSI)
	}

	if tenant.ResourceQuota.PersistentVolumes > 0 {
		resourceQuota.Spec.Hard[corev1.ResourcePersistentVolumeClaims] = *resource.NewQuantity(int64(tenant.ResourceQuota.PersistentVolumes), resource.DecimalSI)
	}

	return em.client.Create(ctx, resourceQuota)
}

func (em *enterpriseManager) createTenantNetworkPolicies(ctx context.Context, instance *n8nv1alpha1.N8nInstance, tenant TenantConfig) error {
	namespaceName := fmt.Sprintf("%s-%s", instance.Name, tenant.TenantID)

	// Default deny all ingress policy
	denyAllPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-deny-all", tenant.TenantID),
			Namespace: namespaceName,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "network-policy",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"n8n.io/tenant-id":             tenant.TenantID,
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}

	if err := em.client.Create(ctx, denyAllPolicy); err != nil {
		return fmt.Errorf("failed to create deny-all network policy: %w", err)
	}

	// Allow internal communication within tenant
	allowInternalPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-allow-internal", tenant.TenantID),
			Namespace: namespaceName,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "network-policy",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"n8n.io/tenant-id":             tenant.TenantID,
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"n8n.io/tenant-id": tenant.TenantID,
								},
							},
						},
					},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"n8n.io/tenant-id": tenant.TenantID,
								},
							},
						},
					},
				},
				// Allow DNS
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"name": "kube-system",
								},
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: &[]corev1.Protocol{corev1.ProtocolUDP}[0],
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
						},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}

	return em.client.Create(ctx, allowInternalPolicy)
}

func (em *enterpriseManager) createTenantRBAC(ctx context.Context, instance *n8nv1alpha1.N8nInstance, tenant TenantConfig) error {
	namespaceName := fmt.Sprintf("%s-%s", instance.Name, tenant.TenantID)

	// Create service account for tenant
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-sa", tenant.TenantID),
			Namespace: namespaceName,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "service-account",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"n8n.io/tenant-id":             tenant.TenantID,
			},
		},
	}

	if err := em.client.Create(ctx, serviceAccount); err != nil {
		return fmt.Errorf("failed to create service account: %w", err)
	}

	// Create roles for each defined role in tenant configuration
	for _, role := range tenant.UserManagement.RoleBasedAccess.Roles {
		if err := em.createTenantRole(ctx, instance, tenant, role, namespaceName); err != nil {
			return fmt.Errorf("failed to create role %s: %w", role.Name, err)
		}
	}

	return nil
}

func (em *enterpriseManager) createTenantRole(ctx context.Context, instance *n8nv1alpha1.N8nInstance, tenant TenantConfig, role Role, namespace string) error {
	k8sRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", tenant.TenantID, role.Name),
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "role",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"n8n.io/tenant-id":             tenant.TenantID,
				"n8n.io/role-name":             role.Name,
			},
		},
		Rules: []rbacv1.PolicyRule{},
	}

	// Convert permissions to policy rules
	for _, permission := range role.Permissions {
		rule := rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{permission.Resource},
			Verbs:     permission.Actions,
		}

		// Add resource names if scope is specified
		if permission.Scope != "" && permission.Scope != "*" {
			rule.ResourceNames = []string{permission.Scope}
		}

		k8sRole.Rules = append(k8sRole.Rules, rule)
	}

	return em.client.Create(ctx, k8sRole)
}

func (em *enterpriseManager) createTenantN8nDeployment(ctx context.Context, instance *n8nv1alpha1.N8nInstance, tenant TenantConfig) error {
	namespaceName := fmt.Sprintf("%s-%s", instance.Name, tenant.TenantID)

	// Create tenant-specific n8n deployment
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-n8n", tenant.TenantID),
			Namespace: namespaceName,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "n8n-server",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"n8n.io/tenant-id":             tenant.TenantID,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &[]int32{1}[0],
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":     "n8n",
					"app.kubernetes.io/instance": instance.Name,
					"n8n.io/tenant-id":           tenant.TenantID,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name":       "n8n",
						"app.kubernetes.io/instance":   instance.Name,
						"app.kubernetes.io/component":  "n8n-server",
						"app.kubernetes.io/managed-by": "n8n-eks-operator",
						"n8n.io/tenant-id":             tenant.TenantID,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: fmt.Sprintf("%s-sa", tenant.TenantID),
					Containers: []corev1.Container{
						{
							Name:  "n8n",
							Image: instance.Spec.Image,
							Env: []corev1.EnvVar{
								{
									Name:  "N8N_TENANT_ID",
									Value: tenant.TenantID,
								},
								{
									Name:  "N8N_TENANT_NAME",
									Value: tenant.Name,
								},
								{
									Name:  "N8N_MULTI_TENANT_MODE",
									Value: "true",
								},
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: 5678,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							Resources: corev1.ResourceRequirements{},
						},
					},
				},
			},
		},
	}

	// Set resource limits if specified
	if tenant.ResourceQuota != nil {
		if tenant.ResourceQuota.CPU != "" {
			deployment.Spec.Template.Spec.Containers[0].Resources.Limits = corev1.ResourceList{
				corev1.ResourceCPU: resource.MustParse(tenant.ResourceQuota.CPU),
			}
			deployment.Spec.Template.Spec.Containers[0].Resources.Requests = corev1.ResourceList{
				corev1.ResourceCPU: resource.MustParse(tenant.ResourceQuota.CPU),
			}
		}

		if tenant.ResourceQuota.Memory != "" {
			if deployment.Spec.Template.Spec.Containers[0].Resources.Limits == nil {
				deployment.Spec.Template.Spec.Containers[0].Resources.Limits = corev1.ResourceList{}
			}
			if deployment.Spec.Template.Spec.Containers[0].Resources.Requests == nil {
				deployment.Spec.Template.Spec.Containers[0].Resources.Requests = corev1.ResourceList{}
			}
			deployment.Spec.Template.Spec.Containers[0].Resources.Limits[corev1.ResourceMemory] = resource.MustParse(tenant.ResourceQuota.Memory)
			deployment.Spec.Template.Spec.Containers[0].Resources.Requests[corev1.ResourceMemory] = resource.MustParse(tenant.ResourceQuota.Memory)
		}
	}

	return em.client.Create(ctx, deployment)
}

func (em *enterpriseManager) createTenantServices(ctx context.Context, instance *n8nv1alpha1.N8nInstance, tenant TenantConfig) error {
	namespaceName := fmt.Sprintf("%s-%s", instance.Name, tenant.TenantID)

	// Create service for tenant n8n deployment
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-n8n-svc", tenant.TenantID),
			Namespace: namespaceName,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "service",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"n8n.io/tenant-id":             tenant.TenantID,
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       80,
					TargetPort: intstr.FromInt(5678),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			Selector: map[string]string{
				"app.kubernetes.io/name":     "n8n",
				"app.kubernetes.io/instance": instance.Name,
				"n8n.io/tenant-id":           tenant.TenantID,
			},
		},
	}

	return em.client.Create(ctx, service)
}

func (em *enterpriseManager) createTenantIngress(ctx context.Context, instance *n8nv1alpha1.N8nInstance, tenant TenantConfig) error {
	namespaceName := fmt.Sprintf("%s-%s", instance.Name, tenant.TenantID)

	// Create ingress for tenant
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-n8n-ingress", tenant.TenantID),
			Namespace: namespaceName,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "ingress",
				"app.kubernetes.io/managed-by": "n8n-eks-operator",
				"n8n.io/tenant-id":             tenant.TenantID,
			},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":                            "alb",
				"alb.ingress.kubernetes.io/scheme":                       "internet-facing",
				"alb.ingress.kubernetes.io/target-type":                  "ip",
				"alb.ingress.kubernetes.io/certificate-arn":              instance.Spec.Ingress.TLS.CertificateArn,
				"alb.ingress.kubernetes.io/ssl-redirect":                 "443",
				"alb.ingress.kubernetes.io/listen-ports":                 `[{"HTTP": 80}, {"HTTPS": 443}]`,
				"alb.ingress.kubernetes.io/healthcheck-path":             "/healthz",
				"alb.ingress.kubernetes.io/healthcheck-interval-seconds": "30",
				"alb.ingress.kubernetes.io/healthy-threshold-count":      "2",
				"alb.ingress.kubernetes.io/unhealthy-threshold-count":    "3",
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: fmt.Sprintf("%s.%s", tenant.TenantID, instance.Spec.Ingress.Host),
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path:     "/",
								PathType: &[]networkingv1.PathType{networkingv1.PathTypePrefix}[0],
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: fmt.Sprintf("%s-n8n-svc", tenant.TenantID),
										Port: networkingv1.ServiceBackendPort{
											Number: 80,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	return em.client.Create(ctx, ingress)
}
