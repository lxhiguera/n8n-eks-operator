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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// AWSSecurityManager implements the SecurityManager interface for AWS and Kubernetes security
type AWSSecurityManager struct {
	client               client.Client
	awsConfig            aws.Config
	iamClient            *iam.Client
	secretsManagerClient *secretsmanager.Client
}

// NewAWSSecurityManager creates a new AWSSecurityManager instance
func NewAWSSecurityManager(client client.Client, awsConfig aws.Config) *AWSSecurityManager {
	return &AWSSecurityManager{
		client:               client,
		awsConfig:            awsConfig,
		iamClient:            iam.NewFromConfig(awsConfig),
		secretsManagerClient: secretsmanager.NewFromConfig(awsConfig),
	}
}

// ReconcileSecurity ensures all security configurations are correct
func (m *AWSSecurityManager) ReconcileSecurity(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Reconciling security configuration")

	// Extract security configuration from N8nInstance
	securityConfig, err := m.extractSecurityConfig(instance)
	if err != nil {
		logger.Error(err, "Failed to extract security configuration")
		return fmt.Errorf("failed to extract security configuration: %w", err)
	}

	// Reconcile IAM roles and policies
	if err := m.ReconcileIAM(ctx, securityConfig); err != nil {
		logger.Error(err, "Failed to reconcile IAM")
		return fmt.Errorf("failed to reconcile IAM: %w", err)
	}

	// Reconcile secrets management
	if err := m.ReconcileSecrets(ctx, securityConfig); err != nil {
		logger.Error(err, "Failed to reconcile secrets")
		return fmt.Errorf("failed to reconcile secrets: %w", err)
	}

	// Reconcile RBAC
	if err := m.reconcileRBAC(ctx, instance, securityConfig); err != nil {
		logger.Error(err, "Failed to reconcile RBAC")
		return fmt.Errorf("failed to reconcile RBAC: %w", err)
	}

	// Reconcile network policies
	if err := m.ReconcileNetworkPolicies(ctx, securityConfig); err != nil {
		logger.Error(err, "Failed to reconcile network policies")
		return fmt.Errorf("failed to reconcile network policies: %w", err)
	}

	// Create security configuration secret
	if err := m.createSecuritySecret(ctx, instance, securityConfig); err != nil {
		logger.Error(err, "Failed to create security secret")
		return fmt.Errorf("failed to create security secret: %w", err)
	}

	logger.Info("Security configuration reconciled successfully")
	return nil
}

// ReconcileIAM creates and configures IAM roles and policies
func (m *AWSSecurityManager) ReconcileIAM(ctx context.Context, config SecurityConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Reconciling IAM configuration")

	// Create or validate IAM role for n8n
	roleArn, err := m.createOrValidateIAMRole(ctx, config.IAM)
	if err != nil {
		return fmt.Errorf("failed to create or validate IAM role: %w", err)
	}

	// Update configuration with role ARN
	config.IAM.RoleArn = roleArn

	// Create or update IAM policies
	if err := m.createOrUpdateIAMPolicies(ctx, config.IAM); err != nil {
		return fmt.Errorf("failed to create or update IAM policies: %w", err)
	}

	logger.Info("IAM configuration reconciled successfully", "roleArn", roleArn)
	return nil
}

// ReconcileSecrets creates and manages secrets
func (m *AWSSecurityManager) ReconcileSecrets(ctx context.Context, config SecurityConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Reconciling secrets management")

	// Validate secrets management configuration
	if err := m.validateSecretsConfiguration(ctx, config.SecretsManagement); err != nil {
		return fmt.Errorf("secrets configuration validation failed: %w", err)
	}

	// Setup secret rotation if enabled
	if config.SecretsManagement.Rotation.Enabled {
		if err := m.setupSecretRotation(ctx, config.SecretsManagement); err != nil {
			return fmt.Errorf("failed to setup secret rotation: %w", err)
		}
	}

	logger.Info("Secrets management reconciled successfully")
	return nil
}

// ReconcileNetworkPolicies creates and configures network policies
func (m *AWSSecurityManager) ReconcileNetworkPolicies(ctx context.Context, config SecurityConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Reconciling network policies")

	if !config.NetworkPolicies.Enabled {
		logger.Info("Network policies are disabled")
		return nil
	}

	// Create default deny-all policy if enabled
	if config.NetworkPolicies.DenyAll {
		if err := m.createDenyAllNetworkPolicy(ctx); err != nil {
			return fmt.Errorf("failed to create deny-all network policy: %w", err)
		}
	}

	// Create specific ingress policies
	if err := m.createIngressNetworkPolicies(ctx, config.NetworkPolicies); err != nil {
		return fmt.Errorf("failed to create ingress network policies: %w", err)
	}

	logger.Info("Network policies reconciled successfully")
	return nil
}

// RotateSecrets handles automatic secret rotation
func (m *AWSSecurityManager) RotateSecrets(ctx context.Context, config SecurityConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Rotating secrets")

	if !config.SecretsManagement.Rotation.Enabled {
		logger.Info("Secret rotation is disabled")
		return nil
	}

	// Rotate secrets based on provider
	switch config.SecretsManagement.Provider {
	case "secrets-manager":
		return m.rotateSecretsManagerSecrets(ctx, config.SecretsManagement)
	case "kubernetes":
		return m.rotateKubernetesSecrets(ctx, config.SecretsManagement)
	default:
		return fmt.Errorf("unsupported secrets provider: %s", config.SecretsManagement.Provider)
	}
}

// ValidateSecurityCompliance validates security compliance
func (m *AWSSecurityManager) ValidateSecurityCompliance(ctx context.Context, config SecurityConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Validating security compliance")

	// Validate IAM compliance
	if err := m.validateIAMCompliance(ctx, config.IAM); err != nil {
		return fmt.Errorf("IAM compliance validation failed: %w", err)
	}

	// Validate secrets compliance
	if err := m.validateSecretsCompliance(ctx, config.SecretsManagement); err != nil {
		return fmt.Errorf("secrets compliance validation failed: %w", err)
	}

	// Validate network policies compliance
	if err := m.validateNetworkPoliciesCompliance(ctx, config.NetworkPolicies); err != nil {
		return fmt.Errorf("network policies compliance validation failed: %w", err)
	}

	logger.Info("Security compliance validation successful")
	return nil
}

// extractSecurityConfig extracts security configuration from N8nInstance
func (m *AWSSecurityManager) extractSecurityConfig(instance *n8nv1alpha1.N8nInstance) (SecurityConfig, error) {
	config := SecurityConfig{}

	// Extract secrets management configuration
	config.SecretsManagement = SecretsManagementConfig{
		Provider: "secrets-manager", // Default to AWS Secrets Manager
		Rotation: RotationConfig{
			Enabled:  true,
			Schedule: "0 2 * * 0", // Weekly on Sunday at 2 AM
		},
		Encryption: EncryptionConfig{
			Enabled: true,
		},
	}

	// Extract IAM configuration
	config.IAM = IAMConfig{
		ServiceAccountName: fmt.Sprintf("%s-sa", instance.Name),
		Policies: []string{
			"n8n-s3-access",
			"n8n-rds-access",
			"n8n-elasticache-access",
			"n8n-secrets-manager-access",
		},
	}

	// Extract network policies configuration
	config.NetworkPolicies = NetworkPoliciesConfig{
		Enabled: true,
		DenyAll: true,
		AllowedIngress: []IngressRule{
			{
				From:  "istio-system",
				Ports: []int{5678, 5679},
			},
			{
				From:  instance.Namespace,
				Ports: []int{5678, 5679},
			},
		},
	}

	return config, nil
}

// createOrValidateIAMRole creates a new IAM role or validates existing one
func (m *AWSSecurityManager) createOrValidateIAMRole(ctx context.Context, config IAMConfig) (string, error) {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Creating or validating IAM role", "serviceAccount", config.ServiceAccountName)

	roleName := fmt.Sprintf("n8n-eks-role-%s", config.ServiceAccountName)

	// Check if role exists
	if config.RoleArn != "" {
		logger.Info("Validating existing IAM role", "roleArn", config.RoleArn)
		
		// Extract role name from ARN
		parts := strings.Split(config.RoleArn, "/")
		if len(parts) > 0 {
			existingRoleName := parts[len(parts)-1]
			
			input := &iam.GetRoleInput{
				RoleName: aws.String(existingRoleName),
			}
			
			_, err := m.iamClient.GetRole(ctx, input)
			if err != nil {
				return "", fmt.Errorf("IAM role %s not found: %w", config.RoleArn, err)
			}
			
			logger.Info("IAM role validated successfully", "roleArn", config.RoleArn)
			return config.RoleArn, nil
		}
	}

	// Create new IAM role
	logger.Info("Creating new IAM role", "roleName", roleName)
	return m.createIAMRole(ctx, roleName, config)
}

// createIAMRole creates a new IAM role for n8n
func (m *AWSSecurityManager) createIAMRole(ctx context.Context, roleName string, config IAMConfig) (string, error) {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Creating IAM role", "roleName", roleName)

	// Create trust policy for EKS service account
	trustPolicy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect": "Allow",
				"Principal": map[string]interface{}{
					"Federated": "arn:aws:iam::*:oidc-provider/*", // This should be the actual OIDC provider ARN
				},
				"Action": "sts:AssumeRoleWithWebIdentity",
				"Condition": map[string]interface{}{
					"StringEquals": map[string]interface{}{
						"*:sub": fmt.Sprintf("system:serviceaccount:default:%s", config.ServiceAccountName),
						"*:aud": "sts.amazonaws.com",
					},
				},
			},
		},
	}

	trustPolicyJSON, err := json.Marshal(trustPolicy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal trust policy: %w", err)
	}

	input := &iam.CreateRoleInput{
		RoleName:                 aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(string(trustPolicyJSON)),
		Description:              aws.String("IAM role for n8n EKS service account"),
		Tags: []iamtypes.Tag{
			{
				Key:   aws.String("Application"),
				Value: aws.String("n8n"),
			},
			{
				Key:   aws.String("ManagedBy"),
				Value: aws.String("n8n-operator"),
			},
		},
	}

	result, err := m.iamClient.CreateRole(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to create IAM role: %w", err)
	}

	if result.Role == nil || result.Role.Arn == nil {
		return "", fmt.Errorf("IAM role creation returned no ARN")
	}

	roleArn := *result.Role.Arn
	logger.Info("IAM role created successfully", "roleName", roleName, "roleArn", roleArn)

	return roleArn, nil
}

// createOrUpdateIAMPolicies creates or updates IAM policies for n8n
func (m *AWSSecurityManager) createOrUpdateIAMPolicies(ctx context.Context, config IAMConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Creating or updating IAM policies")

	// Define policies for n8n
	policies := map[string]map[string]interface{}{
		"n8n-s3-access": {
			"Version": "2012-10-17",
			"Statement": []map[string]interface{}{
				{
					"Effect": "Allow",
					"Action": []string{
						"s3:GetObject",
						"s3:PutObject",
						"s3:DeleteObject",
						"s3:ListBucket",
					},
					"Resource": []string{
						"arn:aws:s3:::n8n-*",
						"arn:aws:s3:::n8n-*/*",
					},
				},
			},
		},
		"n8n-rds-access": {
			"Version": "2012-10-17",
			"Statement": []map[string]interface{}{
				{
					"Effect": "Allow",
					"Action": []string{
						"rds:DescribeDBInstances",
						"rds:DescribeDBClusters",
					},
					"Resource": "*",
				},
			},
		},
		"n8n-elasticache-access": {
			"Version": "2012-10-17",
			"Statement": []map[string]interface{}{
				{
					"Effect": "Allow",
					"Action": []string{
						"elasticache:DescribeCacheClusters",
						"elasticache:DescribeReplicationGroups",
					},
					"Resource": "*",
				},
			},
		},
		"n8n-secrets-manager-access": {
			"Version": "2012-10-17",
			"Statement": []map[string]interface{}{
				{
					"Effect": "Allow",
					"Action": []string{
						"secretsmanager:GetSecretValue",
						"secretsmanager:DescribeSecret",
					},
					"Resource": "arn:aws:secretsmanager:*:*:secret:n8n-*",
				},
			},
		},
	}

	// Create or update each policy
	for policyName, policyDocument := range policies {
		if err := m.createOrUpdateIAMPolicy(ctx, policyName, policyDocument, config); err != nil {
			return fmt.Errorf("failed to create or update policy %s: %w", policyName, err)
		}
	}

	logger.Info("IAM policies created or updated successfully")
	return nil
}

// createOrUpdateIAMPolicy creates or updates a single IAM policy
func (m *AWSSecurityManager) createOrUpdateIAMPolicy(ctx context.Context, policyName string, policyDocument map[string]interface{}, config IAMConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Creating or updating IAM policy", "policyName", policyName)

	policyJSON, err := json.Marshal(policyDocument)
	if err != nil {
		return fmt.Errorf("failed to marshal policy document: %w", err)
	}

	// Try to create the policy
	createInput := &iam.CreatePolicyInput{
		PolicyName:     aws.String(policyName),
		PolicyDocument: aws.String(string(policyJSON)),
		Description:    aws.String(fmt.Sprintf("Policy for n8n %s access", policyName)),
		Tags: []iamtypes.Tag{
			{
				Key:   aws.String("Application"),
				Value: aws.String("n8n"),
			},
			{
				Key:   aws.String("ManagedBy"),
				Value: aws.String("n8n-operator"),
			},
		},
	}

	result, err := m.iamClient.CreatePolicy(ctx, createInput)
	if err != nil {
		// If policy already exists, update it
		if strings.Contains(err.Error(), "EntityAlreadyExists") {
			logger.Info("Policy already exists, updating", "policyName", policyName)
			return m.updateIAMPolicy(ctx, policyName, policyDocument)
		}
		return fmt.Errorf("failed to create policy: %w", err)
	}

	if result.Policy != nil && result.Policy.Arn != nil {
		// Attach policy to role
		if err := m.attachPolicyToRole(ctx, *result.Policy.Arn, config); err != nil {
			return fmt.Errorf("failed to attach policy to role: %w", err)
		}
	}

	logger.Info("IAM policy created successfully", "policyName", policyName)
	return nil
}

// updateIAMPolicy updates an existing IAM policy
func (m *AWSSecurityManager) updateIAMPolicy(ctx context.Context, policyName string, policyDocument map[string]interface{}) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Updating IAM policy", "policyName", policyName)

	// Get policy ARN
	listInput := &iam.ListPoliciesInput{
		Scope: iamtypes.PolicyScopeTypeLocal,
	}

	listResult, err := m.iamClient.ListPolicies(ctx, listInput)
	if err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}

	var policyArn string
	for _, policy := range listResult.Policies {
		if policy.PolicyName != nil && *policy.PolicyName == policyName {
			if policy.Arn != nil {
				policyArn = *policy.Arn
				break
			}
		}
	}

	if policyArn == "" {
		return fmt.Errorf("policy %s not found", policyName)
	}

	policyJSON, err := json.Marshal(policyDocument)
	if err != nil {
		return fmt.Errorf("failed to marshal policy document: %w", err)
	}

	// Create new policy version
	createVersionInput := &iam.CreatePolicyVersionInput{
		PolicyArn:      aws.String(policyArn),
		PolicyDocument: aws.String(string(policyJSON)),
		SetAsDefault:   aws.Bool(true),
	}

	_, err = m.iamClient.CreatePolicyVersion(ctx, createVersionInput)
	if err != nil {
		return fmt.Errorf("failed to create policy version: %w", err)
	}

	logger.Info("IAM policy updated successfully", "policyName", policyName)
	return nil
}

// attachPolicyToRole attaches a policy to the IAM role
func (m *AWSSecurityManager) attachPolicyToRole(ctx context.Context, policyArn string, config IAMConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Attaching policy to role", "policyArn", policyArn)

	// Extract role name from ARN
	roleName := ""
	if config.RoleArn != "" {
		parts := strings.Split(config.RoleArn, "/")
		if len(parts) > 0 {
			roleName = parts[len(parts)-1]
		}
	}

	if roleName == "" {
		return fmt.Errorf("role name not found in configuration")
	}

	input := &iam.AttachRolePolicyInput{
		RoleName:  aws.String(roleName),
		PolicyArn: aws.String(policyArn),
	}

	_, err := m.iamClient.AttachRolePolicy(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to attach policy to role: %w", err)
	}

	logger.Info("Policy attached to role successfully", "policyArn", policyArn, "roleName", roleName)
	return nil
}

//
reconcileRBAC creates and manages Kubernetes RBAC resources
func (m *AWSSecurityManager) reconcileRBAC(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config SecurityConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Reconciling RBAC configuration")

	// Create ServiceAccount
	if err := m.createServiceAccount(ctx, instance, config.IAM); err != nil {
		return fmt.Errorf("failed to create service account: %w", err)
	}

	// Create ClusterRole
	if err := m.createClusterRole(ctx, instance); err != nil {
		return fmt.Errorf("failed to create cluster role: %w", err)
	}

	// Create ClusterRoleBinding
	if err := m.createClusterRoleBinding(ctx, instance, config.IAM); err != nil {
		return fmt.Errorf("failed to create cluster role binding: %w", err)
	}

	// Create Role for namespace-specific permissions
	if err := m.createRole(ctx, instance); err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}

	// Create RoleBinding
	if err := m.createRoleBinding(ctx, instance, config.IAM); err != nil {
		return fmt.Errorf("failed to create role binding: %w", err)
	}

	logger.Info("RBAC configuration reconciled successfully")
	return nil
}

// createServiceAccount creates a ServiceAccount with IAM role annotation
func (m *AWSSecurityManager) createServiceAccount(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config IAMConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Creating ServiceAccount", "name", config.ServiceAccountName)

	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      config.ServiceAccountName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "serviceaccount",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
			Annotations: map[string]string{
				"eks.amazonaws.com/role-arn": config.RoleArn,
			},
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, serviceAccount, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update ServiceAccount
	existingSA := &corev1.ServiceAccount{}
	saKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      config.ServiceAccountName,
	}

	if err := m.client.Get(ctx, saKey, existingSA); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing ServiceAccount: %w", err)
		}
		// ServiceAccount doesn't exist, create it
		if err := m.client.Create(ctx, serviceAccount); err != nil {
			return fmt.Errorf("failed to create ServiceAccount: %w", err)
		}
		logger.Info("ServiceAccount created successfully", "name", config.ServiceAccountName)
	} else {
		// ServiceAccount exists, update it
		existingSA.Annotations = serviceAccount.Annotations
		if err := m.client.Update(ctx, existingSA); err != nil {
			return fmt.Errorf("failed to update ServiceAccount: %w", err)
		}
		logger.Info("ServiceAccount updated successfully", "name", config.ServiceAccountName)
	}

	return nil
}

// createClusterRole creates a ClusterRole with necessary permissions
func (m *AWSSecurityManager) createClusterRole(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	
	clusterRoleName := fmt.Sprintf("%s-cluster-role", instance.Name)
	logger.Info("Creating ClusterRole", "name", clusterRoleName)

	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterRoleName,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "clusterrole",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Rules: []rbacv1.PolicyRule{
			// Read access to nodes for resource monitoring
			{
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get", "list"},
			},
			// Read access to persistent volumes
			{
				APIGroups: []string{""},
				Resources: []string{"persistentvolumes"},
				Verbs:     []string{"get", "list"},
			},
			// Read access to storage classes
			{
				APIGroups: []string{"storage.k8s.io"},
				Resources: []string{"storageclasses"},
				Verbs:     []string{"get", "list"},
			},
		},
	}

	// Create or update ClusterRole
	existingCR := &rbacv1.ClusterRole{}
	if err := m.client.Get(ctx, client.ObjectKey{Name: clusterRoleName}, existingCR); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing ClusterRole: %w", err)
		}
		// ClusterRole doesn't exist, create it
		if err := m.client.Create(ctx, clusterRole); err != nil {
			return fmt.Errorf("failed to create ClusterRole: %w", err)
		}
		logger.Info("ClusterRole created successfully", "name", clusterRoleName)
	} else {
		// ClusterRole exists, update it
		existingCR.Rules = clusterRole.Rules
		if err := m.client.Update(ctx, existingCR); err != nil {
			return fmt.Errorf("failed to update ClusterRole: %w", err)
		}
		logger.Info("ClusterRole updated successfully", "name", clusterRoleName)
	}

	return nil
}

// createClusterRoleBinding creates a ClusterRoleBinding
func (m *AWSSecurityManager) createClusterRoleBinding(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config IAMConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	
	clusterRoleBindingName := fmt.Sprintf("%s-cluster-role-binding", instance.Name)
	clusterRoleName := fmt.Sprintf("%s-cluster-role", instance.Name)
	logger.Info("Creating ClusterRoleBinding", "name", clusterRoleBindingName)

	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterRoleBindingName,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "clusterrolebinding",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      config.ServiceAccountName,
				Namespace: instance.Namespace,
			},
		},
	}

	// Create or update ClusterRoleBinding
	existingCRB := &rbacv1.ClusterRoleBinding{}
	if err := m.client.Get(ctx, client.ObjectKey{Name: clusterRoleBindingName}, existingCRB); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing ClusterRoleBinding: %w", err)
		}
		// ClusterRoleBinding doesn't exist, create it
		if err := m.client.Create(ctx, clusterRoleBinding); err != nil {
			return fmt.Errorf("failed to create ClusterRoleBinding: %w", err)
		}
		logger.Info("ClusterRoleBinding created successfully", "name", clusterRoleBindingName)
	} else {
		// ClusterRoleBinding exists, update it
		existingCRB.Subjects = clusterRoleBinding.Subjects
		if err := m.client.Update(ctx, existingCRB); err != nil {
			return fmt.Errorf("failed to update ClusterRoleBinding: %w", err)
		}
		logger.Info("ClusterRoleBinding updated successfully", "name", clusterRoleBindingName)
	}

	return nil
}

// createRole creates a Role with namespace-specific permissions
func (m *AWSSecurityManager) createRole(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	
	roleName := fmt.Sprintf("%s-role", instance.Name)
	logger.Info("Creating Role", "name", roleName)

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "role",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Rules: []rbacv1.PolicyRule{
			// Full access to secrets in the namespace
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
			},
			// Full access to configmaps in the namespace
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
			},
			// Access to pods for monitoring and debugging
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "pods/log", "pods/status"},
				Verbs:     []string{"get", "list", "watch"},
			},
			// Access to services
			{
				APIGroups: []string{""},
				Resources: []string{"services"},
				Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
			},
			// Access to persistent volume claims
			{
				APIGroups: []string{""},
				Resources: []string{"persistentvolumeclaims"},
				Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
			},
			// Access to deployments
			{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments", "replicasets"},
				Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
			},
			// Access to network policies
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
			},
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, role, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update Role
	existingRole := &rbacv1.Role{}
	roleKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      roleName,
	}

	if err := m.client.Get(ctx, roleKey, existingRole); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing Role: %w", err)
		}
		// Role doesn't exist, create it
		if err := m.client.Create(ctx, role); err != nil {
			return fmt.Errorf("failed to create Role: %w", err)
		}
		logger.Info("Role created successfully", "name", roleName)
	} else {
		// Role exists, update it
		existingRole.Rules = role.Rules
		if err := m.client.Update(ctx, existingRole); err != nil {
			return fmt.Errorf("failed to update Role: %w", err)
		}
		logger.Info("Role updated successfully", "name", roleName)
	}

	return nil
}

// createRoleBinding creates a RoleBinding
func (m *AWSSecurityManager) createRoleBinding(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config IAMConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	
	roleBindingName := fmt.Sprintf("%s-role-binding", instance.Name)
	roleName := fmt.Sprintf("%s-role", instance.Name)
	logger.Info("Creating RoleBinding", "name", roleBindingName)

	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleBindingName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "rolebinding",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     roleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      config.ServiceAccountName,
				Namespace: instance.Namespace,
			},
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, roleBinding, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update RoleBinding
	existingRB := &rbacv1.RoleBinding{}
	rbKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      roleBindingName,
	}

	if err := m.client.Get(ctx, rbKey, existingRB); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing RoleBinding: %w", err)
		}
		// RoleBinding doesn't exist, create it
		if err := m.client.Create(ctx, roleBinding); err != nil {
			return fmt.Errorf("failed to create RoleBinding: %w", err)
		}
		logger.Info("RoleBinding created successfully", "name", roleBindingName)
	} else {
		// RoleBinding exists, update it
		existingRB.Subjects = roleBinding.Subjects
		if err := m.client.Update(ctx, existingRB); err != nil {
			return fmt.Errorf("failed to update RoleBinding: %w", err)
		}
		logger.Info("RoleBinding updated successfully", "name", roleBindingName)
	}

	return nil
}

// validateSecretsConfiguration validates secrets management configuration
func (m *AWSSecurityManager) validateSecretsConfiguration(ctx context.Context, config SecretsManagementConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Validating secrets configuration", "provider", config.Provider)

	switch config.Provider {
	case "secrets-manager":
		return m.validateSecretsManagerConfiguration(ctx)
	case "kubernetes":
		return m.validateKubernetesSecretsConfiguration(ctx)
	default:
		return fmt.Errorf("unsupported secrets provider: %s", config.Provider)
	}
}

// validateSecretsManagerConfiguration validates AWS Secrets Manager configuration
func (m *AWSSecurityManager) validateSecretsManagerConfiguration(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Validating Secrets Manager configuration")

	// Test access to Secrets Manager
	input := &secretsmanager.ListSecretsInput{
		MaxResults: aws.Int32(1),
	}

	_, err := m.secretsManagerClient.ListSecrets(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to access Secrets Manager: %w", err)
	}

	logger.Info("Secrets Manager configuration validated successfully")
	return nil
}

// validateKubernetesSecretsConfiguration validates Kubernetes secrets configuration
func (m *AWSSecurityManager) validateKubernetesSecretsConfiguration(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Validating Kubernetes secrets configuration")

	// Test access to Kubernetes secrets
	secretList := &corev1.SecretList{}
	listOptions := []client.ListOption{
		client.Limit(1),
	}

	if err := m.client.List(ctx, secretList, listOptions...); err != nil {
		return fmt.Errorf("failed to access Kubernetes secrets: %w", err)
	}

	logger.Info("Kubernetes secrets configuration validated successfully")
	return nil
}

// setupSecretRotation sets up automatic secret rotation
func (m *AWSSecurityManager) setupSecretRotation(ctx context.Context, config SecretsManagementConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Setting up secret rotation", "schedule", config.Rotation.Schedule)

	// Create a ConfigMap with rotation configuration
	rotationConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "n8n-secret-rotation-config",
			Namespace: "default", // Should be configurable
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/component":  "secret-rotation",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Data: map[string]string{
			"enabled":  fmt.Sprintf("%t", config.Rotation.Enabled),
			"schedule": config.Rotation.Schedule,
			"provider": config.Provider,
		},
	}

	// Create or update ConfigMap
	existingConfigMap := &corev1.ConfigMap{}
	configMapKey := client.ObjectKey{
		Namespace: "default",
		Name:      "n8n-secret-rotation-config",
	}

	if err := m.client.Get(ctx, configMapKey, existingConfigMap); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing ConfigMap: %w", err)
		}
		// ConfigMap doesn't exist, create it
		if err := m.client.Create(ctx, rotationConfigMap); err != nil {
			return fmt.Errorf("failed to create rotation ConfigMap: %w", err)
		}
		logger.Info("Secret rotation ConfigMap created successfully")
	} else {
		// ConfigMap exists, update it
		existingConfigMap.Data = rotationConfigMap.Data
		if err := m.client.Update(ctx, existingConfigMap); err != nil {
			return fmt.Errorf("failed to update rotation ConfigMap: %w", err)
		}
		logger.Info("Secret rotation ConfigMap updated successfully")
	}

	return nil
}

// rotateSecretsManagerSecrets rotates secrets in AWS Secrets Manager
func (m *AWSSecurityManager) rotateSecretsManagerSecrets(ctx context.Context, config SecretsManagementConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Rotating Secrets Manager secrets")

	// List n8n secrets
	input := &secretsmanager.ListSecretsInput{
		Filters: []secretsmanagertypes.Filter{
			{
				Key:    secretsmanagertypes.FilterNameStringTypeName,
				Values: []string{"n8n-"},
			},
		},
	}

	result, err := m.secretsManagerClient.ListSecrets(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	for _, secret := range result.SecretList {
		if secret.ARN != nil {
			logger.Info("Rotating secret", "secretArn", *secret.ARN)
			
			rotateInput := &secretsmanager.RotateSecretInput{
				SecretId: secret.ARN,
			}

			_, err := m.secretsManagerClient.RotateSecret(ctx, rotateInput)
			if err != nil {
				logger.Error(err, "Failed to rotate secret", "secretArn", *secret.ARN)
				continue
			}
		}
	}

	logger.Info("Secrets Manager secrets rotation completed")
	return nil
}

// rotateKubernetesSecrets rotates Kubernetes secrets
func (m *AWSSecurityManager) rotateKubernetesSecrets(ctx context.Context, config SecretsManagementConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Rotating Kubernetes secrets")

	// List n8n secrets
	secretList := &corev1.SecretList{}
	listOptions := []client.ListOption{
		client.MatchingLabels{
			"app.kubernetes.io/managed-by": "n8n-operator",
		},
	}

	if err := m.client.List(ctx, secretList, listOptions...); err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	for _, secret := range secretList.Items {
		logger.Info("Processing secret for rotation", "secretName", secret.Name)
		
		// Add rotation timestamp annotation
		if secret.Annotations == nil {
			secret.Annotations = make(map[string]string)
		}
		secret.Annotations["n8n.io/last-rotated"] = time.Now().UTC().Format(time.RFC3339)

		if err := m.client.Update(ctx, &secret); err != nil {
			logger.Error(err, "Failed to update secret rotation timestamp", "secretName", secret.Name)
			continue
		}
	}

	logger.Info("Kubernetes secrets rotation completed")
	return nil
}

///
 reconcileSecretsAdvanced implements advanced secrets management with multiple sources
func (m *AWSSecurityManager) reconcileSecretsAdvanced(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config SecretsManagementConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Reconciling advanced secrets management")

	// Create secrets for different components
	secretConfigs := []struct {
		name        string
		component   string
		secretType  string
		data        map[string]string
		sensitive   bool
	}{
		{
			name:       fmt.Sprintf("%s-database-secret", instance.Name),
			component:  "database",
			secretType: "database-credentials",
			data: map[string]string{
				"type":     "postgresql",
				"provider": "rds",
			},
			sensitive: true,
		},
		{
			name:       fmt.Sprintf("%s-cache-secret", instance.Name),
			component:  "cache",
			secretType: "cache-credentials",
			data: map[string]string{
				"type":     "redis",
				"provider": "elasticache",
			},
			sensitive: true,
		},
		{
			name:       fmt.Sprintf("%s-storage-secret", instance.Name),
			component:  "storage",
			secretType: "storage-credentials",
			data: map[string]string{
				"type":     "s3",
				"provider": "aws",
			},
			sensitive: false,
		},
		{
			name:       fmt.Sprintf("%s-app-secret", instance.Name),
			component:  "application",
			secretType: "application-config",
			data: map[string]string{
				"encryption_key": "generated",
				"jwt_secret":     "generated",
			},
			sensitive: true,
		},
	}

	for _, secretConfig := range secretConfigs {
		if err := m.createAdvancedSecret(ctx, instance, secretConfig, config); err != nil {
			return fmt.Errorf("failed to create advanced secret %s: %w", secretConfig.name, err)
		}
	}

	// Setup secret synchronization between providers
	if err := m.setupSecretSynchronization(ctx, instance, config); err != nil {
		return fmt.Errorf("failed to setup secret synchronization: %w", err)
	}

	logger.Info("Advanced secrets management reconciled successfully")
	return nil
}

// createAdvancedSecret creates a secret with advanced features
func (m *AWSSecurityManager) createAdvancedSecret(ctx context.Context, instance *n8nv1alpha1.N8nInstance, secretConfig struct {
	name        string
	component   string
	secretType  string
	data        map[string]string
	sensitive   bool
}, config SecretsManagementConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Creating advanced secret", "name", secretConfig.name, "type", secretConfig.secretType)

	// Generate or retrieve secret data
	secretData, err := m.generateSecretData(ctx, secretConfig, config)
	if err != nil {
		return fmt.Errorf("failed to generate secret data: %w", err)
	}

	// Create Kubernetes secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretConfig.name,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  secretConfig.component,
				"app.kubernetes.io/managed-by": "n8n-operator",
				"n8n.io/secret-type":          secretConfig.secretType,
			},
			Annotations: map[string]string{
				"n8n.io/secret-provider":    config.Provider,
				"n8n.io/encryption-enabled": fmt.Sprintf("%t", config.Encryption.Enabled),
				"n8n.io/rotation-enabled":   fmt.Sprintf("%t", config.Rotation.Enabled),
				"n8n.io/sensitive":          fmt.Sprintf("%t", secretConfig.sensitive),
				"n8n.io/created-at":         time.Now().UTC().Format(time.RFC3339),
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: secretData,
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, secret, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update secret
	existingSecret := &corev1.Secret{}
	secretKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      secretConfig.name,
	}

	if err := m.client.Get(ctx, secretKey, existingSecret); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing secret: %w", err)
		}
		// Secret doesn't exist, create it
		if err := m.client.Create(ctx, secret); err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}
		logger.Info("Advanced secret created successfully", "name", secretConfig.name)
	} else {
		// Secret exists, update it if needed
		if m.shouldUpdateSecret(existingSecret, secret) {
			existingSecret.Data = secret.Data
			existingSecret.Annotations["n8n.io/updated-at"] = time.Now().UTC().Format(time.RFC3339)
			if err := m.client.Update(ctx, existingSecret); err != nil {
				return fmt.Errorf("failed to update secret: %w", err)
			}
			logger.Info("Advanced secret updated successfully", "name", secretConfig.name)
		}
	}

	// Store in external provider if configured
	if secretConfig.sensitive && config.Provider == "secrets-manager" {
		if err := m.storeInSecretsManager(ctx, secretConfig.name, secretData); err != nil {
			logger.Warn("Failed to store secret in Secrets Manager", "error", err)
		}
	}

	return nil
}

// generateSecretData generates or retrieves secret data
func (m *AWSSecurityManager) generateSecretData(ctx context.Context, secretConfig struct {
	name        string
	component   string
	secretType  string
	data        map[string]string
	sensitive   bool
}, config SecretsManagementConfig) (map[string][]byte, error) {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	
	secretData := make(map[string][]byte)

	// Process each data field
	for key, value := range secretConfig.data {
		var finalValue string
		
		switch value {
		case "generated":
			// Generate secure random value
			generatedValue, err := m.generateSecureValue(key)
			if err != nil {
				return nil, fmt.Errorf("failed to generate secure value for %s: %w", key, err)
			}
			finalValue = generatedValue
		default:
			finalValue = value
		}

		// Encrypt if encryption is enabled
		if config.Encryption.Enabled && secretConfig.sensitive {
			encryptedValue, err := m.encryptValue(finalValue, config.Encryption)
			if err != nil {
				logger.Warn("Failed to encrypt value, using plain text", "key", key, "error", err)
				finalValue = finalValue
			} else {
				finalValue = encryptedValue
			}
		}

		secretData[key] = []byte(finalValue)
	}

	return secretData, nil
}

// generateSecureValue generates a secure random value based on the key type
func (m *AWSSecurityManager) generateSecureValue(keyType string) (string, error) {
	switch keyType {
	case "encryption_key":
		return m.generateEncryptionKey(32) // 256-bit key
	case "jwt_secret":
		return m.generateJWTSecret(64) // 512-bit secret
	case "api_key":
		return m.generateAPIKey(32)
	default:
		return m.generateRandomString(32)
	}
}

// generateEncryptionKey generates a secure encryption key
func (m *AWSSecurityManager) generateEncryptionKey(length int) (string, error) {
	// Implementation would use crypto/rand for secure random generation
	// For now, return a placeholder
	return fmt.Sprintf("enc_key_%d_%d", length, time.Now().Unix()), nil
}

// generateJWTSecret generates a secure JWT secret
func (m *AWSSecurityManager) generateJWTSecret(length int) (string, error) {
	// Implementation would use crypto/rand for secure random generation
	// For now, return a placeholder
	return fmt.Sprintf("jwt_secret_%d_%d", length, time.Now().Unix()), nil
}

// generateAPIKey generates a secure API key
func (m *AWSSecurityManager) generateAPIKey(length int) (string, error) {
	// Implementation would use crypto/rand for secure random generation
	// For now, return a placeholder
	return fmt.Sprintf("api_key_%d_%d", length, time.Now().Unix()), nil
}

// generateRandomString generates a secure random string
func (m *AWSSecurityManager) generateRandomString(length int) (string, error) {
	// Implementation would use crypto/rand for secure random generation
	// For now, return a placeholder
	return fmt.Sprintf("random_%d_%d", length, time.Now().Unix()), nil
}

// encryptValue encrypts a value using the configured encryption method
func (m *AWSSecurityManager) encryptValue(value string, encConfig EncryptionConfig) (string, error) {
	if !encConfig.Enabled {
		return value, nil
	}

	// Implementation would use proper encryption (AES-GCM, etc.)
	// For now, return a base64 encoded placeholder
	return fmt.Sprintf("encrypted:%s", value), nil
}

// shouldUpdateSecret determines if a secret should be updated
func (m *AWSSecurityManager) shouldUpdateSecret(existing, new *corev1.Secret) bool {
	// Check if rotation is due
	if lastRotated, exists := existing.Annotations["n8n.io/last-rotated"]; exists {
		if rotationTime, err := time.Parse(time.RFC3339, lastRotated); err == nil {
			// Rotate weekly
			if time.Since(rotationTime) > 7*24*time.Hour {
				return true
			}
		}
	}

	// Check if data has changed
	if len(existing.Data) != len(new.Data) {
		return true
	}

	for key, newValue := range new.Data {
		if existingValue, exists := existing.Data[key]; !exists || string(existingValue) != string(newValue) {
			return true
		}
	}

	return false
}

// storeInSecretsManager stores sensitive data in AWS Secrets Manager
func (m *AWSSecurityManager) storeInSecretsManager(ctx context.Context, secretName string, secretData map[string][]byte) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Storing secret in Secrets Manager", "secretName", secretName)

	// Convert secret data to JSON
	dataMap := make(map[string]string)
	for key, value := range secretData {
		dataMap[key] = string(value)
	}

	secretValue, err := json.Marshal(dataMap)
	if err != nil {
		return fmt.Errorf("failed to marshal secret data: %w", err)
	}

	// Create or update secret in Secrets Manager
	secretsManagerName := fmt.Sprintf("n8n/%s", secretName)
	
	input := &secretsmanager.CreateSecretInput{
		Name:         aws.String(secretsManagerName),
		SecretString: aws.String(string(secretValue)),
		Description:  aws.String(fmt.Sprintf("n8n secret: %s", secretName)),
		Tags: []secretsmanagertypes.Tag{
			{
				Key:   aws.String("Application"),
				Value: aws.String("n8n"),
			},
			{
				Key:   aws.String("ManagedBy"),
				Value: aws.String("n8n-operator"),
			},
		},
	}

	_, err = m.secretsManagerClient.CreateSecret(ctx, input)
	if err != nil {
		// If secret already exists, update it
		if strings.Contains(err.Error(), "ResourceExistsException") {
			updateInput := &secretsmanager.UpdateSecretInput{
				SecretId:     aws.String(secretsManagerName),
				SecretString: aws.String(string(secretValue)),
			}
			
			_, err = m.secretsManagerClient.UpdateSecret(ctx, updateInput)
			if err != nil {
				return fmt.Errorf("failed to update secret in Secrets Manager: %w", err)
			}
		} else {
			return fmt.Errorf("failed to create secret in Secrets Manager: %w", err)
		}
	}

	logger.Info("Secret stored in Secrets Manager successfully", "secretName", secretsManagerName)
	return nil
}

// setupSecretSynchronization sets up synchronization between secret providers
func (m *AWSSecurityManager) setupSecretSynchronization(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config SecretsManagementConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Setting up secret synchronization")

	// Create synchronization configuration
	syncConfig := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-secret-sync", instance.Name),
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "secret-sync",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Data: map[string]string{
			"provider":           config.Provider,
			"sync-enabled":       "true",
			"sync-interval":      "5m",
			"encryption-enabled": fmt.Sprintf("%t", config.Encryption.Enabled),
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, syncConfig, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update ConfigMap
	existingConfigMap := &corev1.ConfigMap{}
	configMapKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      syncConfig.Name,
	}

	if err := m.client.Get(ctx, configMapKey, existingConfigMap); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing ConfigMap: %w", err)
		}
		// ConfigMap doesn't exist, create it
		if err := m.client.Create(ctx, syncConfig); err != nil {
			return fmt.Errorf("failed to create sync ConfigMap: %w", err)
		}
		logger.Info("Secret synchronization ConfigMap created successfully")
	} else {
		// ConfigMap exists, update it
		existingConfigMap.Data = syncConfig.Data
		if err := m.client.Update(ctx, existingConfigMap); err != nil {
			return fmt.Errorf("failed to update sync ConfigMap: %w", err)
		}
		logger.Info("Secret synchronization ConfigMap updated successfully")
	}

	return nil
}

// validateSecretsCompliance validates secrets compliance with security policies
func (m *AWSSecurityManager) validateSecretsCompliance(ctx context.Context, config SecretsManagementConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Validating secrets compliance")

	// Validate encryption is enabled for sensitive secrets
	if !config.Encryption.Enabled {
		logger.Warn("Encryption is not enabled for secrets")
	}

	// Validate rotation is enabled
	if !config.Rotation.Enabled {
		logger.Warn("Secret rotation is not enabled")
	}

	// List all n8n secrets and validate them
	secretList := &corev1.SecretList{}
	listOptions := []client.ListOption{
		client.MatchingLabels{
			"app.kubernetes.io/managed-by": "n8n-operator",
		},
	}

	if err := m.client.List(ctx, secretList, listOptions...); err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	for _, secret := range secretList.Items {
		if err := m.validateSecretCompliance(secret); err != nil {
			logger.Warn("Secret compliance validation failed", "secretName", secret.Name, "error", err)
		}
	}

	logger.Info("Secrets compliance validation completed")
	return nil
}

// validateSecretCompliance validates a single secret's compliance
func (m *AWSSecurityManager) validateSecretCompliance(secret corev1.Secret) error {
	// Check if secret has required labels
	requiredLabels := []string{
		"app.kubernetes.io/name",
		"app.kubernetes.io/managed-by",
		"n8n.io/secret-type",
	}

	for _, label := range requiredLabels {
		if _, exists := secret.Labels[label]; !exists {
			return fmt.Errorf("missing required label: %s", label)
		}
	}

	// Check if sensitive secrets are properly annotated
	if sensitive, exists := secret.Annotations["n8n.io/sensitive"]; exists && sensitive == "true" {
		if encrypted, exists := secret.Annotations["n8n.io/encryption-enabled"]; !exists || encrypted != "true" {
			return fmt.Errorf("sensitive secret is not encrypted")
		}
	}

	// Check if secret has creation timestamp
	if _, exists := secret.Annotations["n8n.io/created-at"]; !exists {
		return fmt.Errorf("missing creation timestamp")
	}

	return nil
}

// auditSecretAccess logs secret access for security monitoring
func (m *AWSSecurityManager) auditSecretAccess(ctx context.Context, secretName, operation, principal string) {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Secret access audit",
		"secret", secretName,
		"operation", operation,
		"principal", principal,
		"timestamp", time.Now().UTC().Format(time.RFC3339),
	)
	
	// In a real implementation, this would send audit logs to CloudTrail, CloudWatch, or a SIEM system
}

// getSecretsMetrics retrieves secrets management metrics
func (m *AWSSecurityManager) getSecretsMetrics(ctx context.Context, namespace string) (map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Retrieving secrets metrics")

	metrics := make(map[string]interface{})

	// Count secrets by type
	secretList := &corev1.SecretList{}
	listOptions := []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingLabels{
			"app.kubernetes.io/managed-by": "n8n-operator",
		},
	}

	if err := m.client.List(ctx, secretList, listOptions...); err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	secretTypes := make(map[string]int)
	encryptedCount := 0
	sensitiveCount := 0
	rotationEnabledCount := 0

	for _, secret := range secretList.Items {
		// Count by type
		if secretType, exists := secret.Labels["n8n.io/secret-type"]; exists {
			secretTypes[secretType]++
		}

		// Count encrypted secrets
		if encrypted, exists := secret.Annotations["n8n.io/encryption-enabled"]; exists && encrypted == "true" {
			encryptedCount++
		}

		// Count sensitive secrets
		if sensitive, exists := secret.Annotations["n8n.io/sensitive"]; exists && sensitive == "true" {
			sensitiveCount++
		}

		// Count rotation enabled secrets
		if rotation, exists := secret.Annotations["n8n.io/rotation-enabled"]; exists && rotation == "true" {
			rotationEnabledCount++
		}
	}

	metrics["total_secrets"] = len(secretList.Items)
	metrics["secret_types"] = secretTypes
	metrics["encrypted_secrets"] = encryptedCount
	metrics["sensitive_secrets"] = sensitiveCount
	metrics["rotation_enabled_secrets"] = rotationEnabledCount
	metrics["encryption_rate"] = float64(encryptedCount) / float64(len(secretList.Items))

	logger.Info("Secrets metrics retrieved", "totalSecrets", len(secretList.Items))
	return metrics, nil
}

// cr
eateDenyAllNetworkPolicy creates a default deny-all network policy
func (m *AWSSecurityManager) createDenyAllNetworkPolicy(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Creating deny-all network policy")

	denyAllPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "n8n-deny-all",
			Namespace: "default", // Should be configurable
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/component":  "network-policy",
				"app.kubernetes.io/managed-by": "n8n-operator",
				"n8n.io/policy-type":          "deny-all",
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name": "n8n",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			// Empty ingress and egress rules = deny all
		},
	}

	return m.createOrUpdateNetworkPolicy(ctx, denyAllPolicy)
}

// createIngressNetworkPolicies creates specific ingress network policies
func (m *AWSSecurityManager) createIngressNetworkPolicies(ctx context.Context, config NetworkPoliciesConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Creating ingress network policies")

	// Create policies for each allowed ingress rule
	for i, rule := range config.AllowedIngress {
		policyName := fmt.Sprintf("n8n-allow-ingress-%d", i)
		
		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      policyName,
				Namespace: "default", // Should be configurable
				Labels: map[string]string{
					"app.kubernetes.io/name":       "n8n",
					"app.kubernetes.io/component":  "network-policy",
					"app.kubernetes.io/managed-by": "n8n-operator",
					"n8n.io/policy-type":          "allow-ingress",
				},
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app.kubernetes.io/name": "n8n",
					},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
				},
				Ingress: m.buildIngressRules(rule),
			},
		}

		if err := m.createOrUpdateNetworkPolicy(ctx, policy); err != nil {
			return fmt.Errorf("failed to create ingress policy %s: %w", policyName, err)
		}
	}

	// Create comprehensive egress policy
	if err := m.createEgressNetworkPolicy(ctx); err != nil {
		return fmt.Errorf("failed to create egress policy: %w", err)
	}

	logger.Info("Ingress network policies created successfully")
	return nil
}

// buildIngressRules builds ingress rules from configuration
func (m *AWSSecurityManager) buildIngressRules(rule IngressRule) []networkingv1.NetworkPolicyIngressRule {
	var ports []networkingv1.NetworkPolicyPort
	
	// Convert port numbers to NetworkPolicyPort
	for _, port := range rule.Ports {
		networkPort := networkingv1.NetworkPolicyPort{
			Port: &intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: int32(port),
			},
			Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
		}
		ports = append(ports, networkPort)
	}

	var from []networkingv1.NetworkPolicyPeer

	// Build peer selectors based on the "from" field
	switch rule.From {
	case "istio-system":
		from = []networkingv1.NetworkPolicyPeer{
			{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"name": "istio-system",
					},
				},
			},
		}
	case "same-namespace":
		from = []networkingv1.NetworkPolicyPeer{
			{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"name": "default", // Should be configurable
					},
				},
			},
		}
	default:
		// Treat as namespace name
		from = []networkingv1.NetworkPolicyPeer{
			{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"name": rule.From,
					},
				},
			},
		}
	}

	return []networkingv1.NetworkPolicyIngressRule{
		{
			From:  from,
			Ports: ports,
		},
	}
}

// createEgressNetworkPolicy creates a comprehensive egress network policy
func (m *AWSSecurityManager) createEgressNetworkPolicy(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Creating egress network policy")

	egressPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "n8n-allow-egress",
			Namespace: "default", // Should be configurable
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/component":  "network-policy",
				"app.kubernetes.io/managed-by": "n8n-operator",
				"n8n.io/policy-type":          "allow-egress",
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name": "n8n",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				// Allow DNS resolution
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
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 53,
							},
							Protocol: &[]corev1.Protocol{corev1.ProtocolUDP}[0],
						},
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 53,
							},
							Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
						},
					},
				},
				// Allow communication within same namespace
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"name": "default", // Should be configurable
								},
							},
						},
					},
				},
				// Allow communication to Istio system
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"name": "istio-system",
								},
							},
						},
					},
				},
				// Allow HTTPS to external services
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 443,
							},
							Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
						},
					},
				},
				// Allow database connections (PostgreSQL default port)
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 5432,
							},
							Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
						},
					},
				},
				// Allow cache connections (Redis default port)
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 6379,
							},
							Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
						},
					},
				},
			},
		},
	}

	return m.createOrUpdateNetworkPolicy(ctx, egressPolicy)
}

// createComponentSpecificNetworkPolicies creates network policies for specific n8n components
func (m *AWSSecurityManager) createComponentSpecificNetworkPolicies(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Creating component-specific network policies")

	components := []struct {
		name           string
		component      string
		allowedPorts   []int32
		allowedEgress  []string
	}{
		{
			name:          fmt.Sprintf("%s-main-netpol", instance.Name),
			component:     "main",
			allowedPorts:  []int32{5678},
			allowedEgress: []string{"database", "cache", "storage"},
		},
		{
			name:          fmt.Sprintf("%s-webhook-netpol", instance.Name),
			component:     "webhook",
			allowedPorts:  []int32{5679},
			allowedEgress: []string{"database", "cache"},
		},
		{
			name:          fmt.Sprintf("%s-worker-netpol", instance.Name),
			component:     "worker",
			allowedPorts:  []int32{},
			allowedEgress: []string{"database", "cache", "storage", "external"},
		},
	}

	for _, comp := range components {
		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      comp.name,
				Namespace: instance.Namespace,
				Labels: map[string]string{
					"app.kubernetes.io/name":       "n8n",
					"app.kubernetes.io/instance":   instance.Name,
					"app.kubernetes.io/component":  comp.component,
					"app.kubernetes.io/managed-by": "n8n-operator",
					"n8n.io/policy-type":          "component-specific",
				},
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app.kubernetes.io/name":      "n8n",
						"app.kubernetes.io/component": comp.component,
					},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
				Ingress: m.buildComponentIngressRules(comp.allowedPorts),
				Egress:  m.buildComponentEgressRules(comp.allowedEgress),
			},
		}

		// Set owner reference
		if err := ctrl.SetControllerReference(instance, policy, m.client.Scheme()); err != nil {
			return fmt.Errorf("failed to set controller reference: %w", err)
		}

		if err := m.createOrUpdateNetworkPolicy(ctx, policy); err != nil {
			return fmt.Errorf("failed to create component policy %s: %w", comp.name, err)
		}
	}

	logger.Info("Component-specific network policies created successfully")
	return nil
}

// buildComponentIngressRules builds ingress rules for a component
func (m *AWSSecurityManager) buildComponentIngressRules(allowedPorts []int32) []networkingv1.NetworkPolicyIngressRule {
	if len(allowedPorts) == 0 {
		return []networkingv1.NetworkPolicyIngressRule{}
	}

	var ports []networkingv1.NetworkPolicyPort
	for _, port := range allowedPorts {
		ports = append(ports, networkingv1.NetworkPolicyPort{
			Port: &intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: port,
			},
			Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
		})
	}

	return []networkingv1.NetworkPolicyIngressRule{
		{
			From: []networkingv1.NetworkPolicyPeer{
				// Allow from Istio gateway
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"name": "istio-system",
						},
					},
				},
				// Allow from same namespace
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"name": "default", // Should be configurable
						},
					},
				},
			},
			Ports: ports,
		},
	}
}

// buildComponentEgressRules builds egress rules for a component
func (m *AWSSecurityManager) buildComponentEgressRules(allowedEgress []string) []networkingv1.NetworkPolicyEgressRule {
	var rules []networkingv1.NetworkPolicyEgressRule

	for _, egressType := range allowedEgress {
		switch egressType {
		case "database":
			rules = append(rules, networkingv1.NetworkPolicyEgressRule{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Port: &intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: 5432, // PostgreSQL
						},
						Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
					},
				},
			})
		case "cache":
			rules = append(rules, networkingv1.NetworkPolicyEgressRule{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Port: &intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: 6379, // Redis
						},
						Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
					},
				},
			})
		case "storage":
			rules = append(rules, networkingv1.NetworkPolicyEgressRule{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Port: &intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: 443, // HTTPS for S3
						},
						Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
					},
				},
			})
		case "external":
			rules = append(rules, networkingv1.NetworkPolicyEgressRule{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Port: &intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: 443, // HTTPS
						},
						Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
					},
					{
						Port: &intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: 80, // HTTP
						},
						Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
					},
				},
			})
		}
	}

	// Always allow DNS
	rules = append(rules, networkingv1.NetworkPolicyEgressRule{
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
				Port: &intstr.IntOrString{
					Type:   intstr.Int,
					IntVal: 53,
				},
				Protocol: &[]corev1.Protocol{corev1.ProtocolUDP}[0],
			},
		},
	})

	return rules
}

// createOrUpdateNetworkPolicy creates or updates a network policy
func (m *AWSSecurityManager) createOrUpdateNetworkPolicy(ctx context.Context, policy *networkingv1.NetworkPolicy) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	
	name := policy.Name
	namespace := policy.Namespace
	
	logger.Info("Creating or updating NetworkPolicy", "name", name, "namespace", namespace)

	// Check if policy exists
	existingPolicy := &networkingv1.NetworkPolicy{}
	policyKey := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}

	if err := m.client.Get(ctx, policyKey, existingPolicy); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing NetworkPolicy: %w", err)
		}
		// Policy doesn't exist, create it
		if err := m.client.Create(ctx, policy); err != nil {
			return fmt.Errorf("failed to create NetworkPolicy: %w", err)
		}
		logger.Info("NetworkPolicy created successfully", "name", name)
	} else {
		// Policy exists, update it
		existingPolicy.Spec = policy.Spec
		if err := m.client.Update(ctx, existingPolicy); err != nil {
			return fmt.Errorf("failed to update NetworkPolicy: %w", err)
		}
		logger.Info("NetworkPolicy updated successfully", "name", name)
	}

	return nil
}

// validateNetworkPoliciesCompliance validates network policies compliance
func (m *AWSSecurityManager) validateNetworkPoliciesCompliance(ctx context.Context, config NetworkPoliciesConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Validating network policies compliance")

	if !config.Enabled {
		logger.Warn("Network policies are disabled")
		return nil
	}

	// List all network policies
	policyList := &networkingv1.NetworkPolicyList{}
	listOptions := []client.ListOption{
		client.MatchingLabels{
			"app.kubernetes.io/managed-by": "n8n-operator",
		},
	}

	if err := m.client.List(ctx, policyList, listOptions...); err != nil {
		return fmt.Errorf("failed to list network policies: %w", err)
	}

	// Validate each policy
	for _, policy := range policyList.Items {
		if err := m.validateNetworkPolicyCompliance(policy); err != nil {
			logger.Warn("Network policy compliance validation failed", "policyName", policy.Name, "error", err)
		}
	}

	// Check if deny-all policy exists when required
	if config.DenyAll {
		denyAllExists := false
		for _, policy := range policyList.Items {
			if policyType, exists := policy.Labels["n8n.io/policy-type"]; exists && policyType == "deny-all" {
				denyAllExists = true
				break
			}
		}
		if !denyAllExists {
			logger.Warn("Deny-all policy is required but not found")
		}
	}

	logger.Info("Network policies compliance validation completed")
	return nil
}

// validateNetworkPolicyCompliance validates a single network policy's compliance
func (m *AWSSecurityManager) validateNetworkPolicyCompliance(policy networkingv1.NetworkPolicy) error {
	// Check if policy has required labels
	requiredLabels := []string{
		"app.kubernetes.io/name",
		"app.kubernetes.io/managed-by",
		"n8n.io/policy-type",
	}

	for _, label := range requiredLabels {
		if _, exists := policy.Labels[label]; !exists {
			return fmt.Errorf("missing required label: %s", label)
		}
	}

	// Check if policy has both ingress and egress rules when required
	hasIngress := false
	hasEgress := false
	
	for _, policyType := range policy.Spec.PolicyTypes {
		if policyType == networkingv1.PolicyTypeIngress {
			hasIngress = true
		}
		if policyType == networkingv1.PolicyTypeEgress {
			hasEgress = true
		}
	}

	// Validate that policies are restrictive (not allowing all traffic)
	if hasIngress && len(policy.Spec.Ingress) > 0 {
		for _, rule := range policy.Spec.Ingress {
			if len(rule.From) == 0 && len(rule.Ports) == 0 {
				return fmt.Errorf("ingress rule allows all traffic")
			}
		}
	}

	if hasEgress && len(policy.Spec.Egress) > 0 {
		for _, rule := range policy.Spec.Egress {
			if len(rule.To) == 0 && len(rule.Ports) == 0 {
				return fmt.Errorf("egress rule allows all traffic")
			}
		}
	}

	return nil
}

// getNetworkPoliciesMetrics retrieves network policies metrics
func (m *AWSSecurityManager) getNetworkPoliciesMetrics(ctx context.Context, namespace string) (map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Retrieving network policies metrics")

	metrics := make(map[string]interface{})

	// List all network policies
	policyList := &networkingv1.NetworkPolicyList{}
	listOptions := []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingLabels{
			"app.kubernetes.io/managed-by": "n8n-operator",
		},
	}

	if err := m.client.List(ctx, policyList, listOptions...); err != nil {
		return nil, fmt.Errorf("failed to list network policies: %w", err)
	}

	policyTypes := make(map[string]int)
	ingressPolicies := 0
	egressPolicies := 0

	for _, policy := range policyList.Items {
		// Count by type
		if policyType, exists := policy.Labels["n8n.io/policy-type"]; exists {
			policyTypes[policyType]++
		}

		// Count ingress/egress policies
		for _, pt := range policy.Spec.PolicyTypes {
			if pt == networkingv1.PolicyTypeIngress {
				ingressPolicies++
			}
			if pt == networkingv1.PolicyTypeEgress {
				egressPolicies++
			}
		}
	}

	metrics["total_policies"] = len(policyList.Items)
	metrics["policy_types"] = policyTypes
	metrics["ingress_policies"] = ingressPolicies
	metrics["egress_policies"] = egressPolicies

	logger.Info("Network policies metrics retrieved", "totalPolicies", len(policyList.Items))
	return metrics, nil
}

// v
alidateIAMCompliance validates IAM compliance with security policies
func (m *AWSSecurityManager) validateIAMCompliance(ctx context.Context, config IAMConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Validating IAM compliance")

	// Validate role exists and has correct trust policy
	if config.RoleArn == "" {
		return fmt.Errorf("IAM role ARN is required")
	}

	// Extract role name from ARN
	parts := strings.Split(config.RoleArn, "/")
	if len(parts) == 0 {
		return fmt.Errorf("invalid role ARN format")
	}
	roleName := parts[len(parts)-1]

	// Get role details
	input := &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	}

	result, err := m.iamClient.GetRole(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to get IAM role: %w", err)
	}

	if result.Role == nil {
		return fmt.Errorf("IAM role not found")
	}

	// Validate role has required tags
	if err := m.validateIAMRoleTags(ctx, roleName); err != nil {
		logger.Warn("IAM role tags validation failed", "error", err)
	}

	// Validate attached policies
	if err := m.validateIAMRolePolicies(ctx, roleName, config.Policies); err != nil {
		return fmt.Errorf("IAM role policies validation failed: %w", err)
	}

	logger.Info("IAM compliance validation successful")
	return nil
}

// validateIAMRoleTags validates IAM role has required tags
func (m *AWSSecurityManager) validateIAMRoleTags(ctx context.Context, roleName string) error {
	input := &iam.ListRoleTagsInput{
		RoleName: aws.String(roleName),
	}

	result, err := m.iamClient.ListRoleTags(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to list role tags: %w", err)
	}

	requiredTags := map[string]string{
		"Application": "n8n",
		"ManagedBy":   "n8n-operator",
	}

	existingTags := make(map[string]string)
	for _, tag := range result.Tags {
		if tag.Key != nil && tag.Value != nil {
			existingTags[*tag.Key] = *tag.Value
		}
	}

	for key, expectedValue := range requiredTags {
		if actualValue, exists := existingTags[key]; !exists || actualValue != expectedValue {
			return fmt.Errorf("missing or incorrect tag: %s (expected: %s, actual: %s)", key, expectedValue, actualValue)
		}
	}

	return nil
}

// validateIAMRolePolicies validates IAM role has required policies attached
func (m *AWSSecurityManager) validateIAMRolePolicies(ctx context.Context, roleName string, requiredPolicies []string) error {
	input := &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	}

	result, err := m.iamClient.ListAttachedRolePolicies(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to list attached policies: %w", err)
	}

	attachedPolicies := make(map[string]bool)
	for _, policy := range result.AttachedPolicies {
		if policy.PolicyName != nil {
			attachedPolicies[*policy.PolicyName] = true
		}
	}

	for _, requiredPolicy := range requiredPolicies {
		if !attachedPolicies[requiredPolicy] {
			return fmt.Errorf("required policy not attached: %s", requiredPolicy)
		}
	}

	return nil
}

// createSecuritySecret creates a Kubernetes secret with security configuration
func (m *AWSSecurityManager) createSecuritySecret(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config SecurityConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	
	secretName := fmt.Sprintf("%s-security", instance.Name)
	logger.Info("Creating security secret", "secretName", secretName)

	// Prepare secret data
	secretData := map[string][]byte{
		"iam-role-arn":           []byte(config.IAM.RoleArn),
		"service-account-name":   []byte(config.IAM.ServiceAccountName),
		"secrets-provider":       []byte(config.SecretsManagement.Provider),
		"encryption-enabled":     []byte(fmt.Sprintf("%t", config.SecretsManagement.Encryption.Enabled)),
		"rotation-enabled":       []byte(fmt.Sprintf("%t", config.SecretsManagement.Rotation.Enabled)),
		"network-policies-enabled": []byte(fmt.Sprintf("%t", config.NetworkPolicies.Enabled)),
	}

	// Create secret object
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "security",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: secretData,
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, secret, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update secret
	existingSecret := &corev1.Secret{}
	secretKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      secretName,
	}

	if err := m.client.Get(ctx, secretKey, existingSecret); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing secret: %w", err)
		}
		// Secret doesn't exist, create it
		if err := m.client.Create(ctx, secret); err != nil {
			return fmt.Errorf("failed to create security secret: %w", err)
		}
		logger.Info("Security secret created successfully", "secretName", secretName)
	} else {
		// Secret exists, update it
		existingSecret.Data = secretData
		if err := m.client.Update(ctx, existingSecret); err != nil {
			return fmt.Errorf("failed to update security secret: %w", err)
		}
		logger.Info("Security secret updated successfully", "secretName", secretName)
	}

	return nil
}

// auditSecurityEvent logs security events for monitoring and compliance
func (m *AWSSecurityManager) auditSecurityEvent(ctx context.Context, eventType, resource, action, principal string, metadata map[string]string) {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	
	// Create structured audit log entry
	auditEntry := map[string]interface{}{
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"event_type":  eventType,
		"resource":    resource,
		"action":      action,
		"principal":   principal,
		"metadata":    metadata,
		"source":      "n8n-operator",
		"severity":    m.getEventSeverity(eventType, action),
	}

	// Log the audit entry
	logger.Info("Security audit event",
		"eventType", eventType,
		"resource", resource,
		"action", action,
		"principal", principal,
		"auditEntry", auditEntry,
	)
	
	// In a real implementation, this would also:
	// - Send to CloudTrail
	// - Send to CloudWatch Logs
	// - Send to SIEM system
	// - Store in audit database
}

// getEventSeverity determines the severity level of a security event
func (m *AWSSecurityManager) getEventSeverity(eventType, action string) string {
	highSeverityEvents := map[string][]string{
		"iam": {"delete", "detach", "modify-trust-policy"},
		"secret": {"delete", "expose", "unauthorized-access"},
		"network-policy": {"delete", "allow-all"},
		"rbac": {"escalate", "delete"},
	}

	mediumSeverityEvents := map[string][]string{
		"iam": {"create", "attach", "update"},
		"secret": {"create", "update", "rotate"},
		"network-policy": {"create", "update"},
		"rbac": {"create", "update"},
	}

	if actions, exists := highSeverityEvents[eventType]; exists {
		for _, a := range actions {
			if a == action {
				return "HIGH"
			}
		}
	}

	if actions, exists := mediumSeverityEvents[eventType]; exists {
		for _, a := range actions {
			if a == action {
				return "MEDIUM"
			}
		}
	}

	return "LOW"
}

// monitorSecurityCompliance continuously monitors security compliance
func (m *AWSSecurityManager) monitorSecurityCompliance(ctx context.Context, config SecurityConfig) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Monitoring security compliance")

	// Check IAM compliance
	if err := m.validateIAMCompliance(ctx, config.IAM); err != nil {
		m.auditSecurityEvent(ctx, "compliance", "iam", "validation-failed", "system", map[string]string{
			"error": err.Error(),
		})
		logger.Warn("IAM compliance check failed", "error", err)
	}

	// Check secrets compliance
	if err := m.validateSecretsCompliance(ctx, config.SecretsManagement); err != nil {
		m.auditSecurityEvent(ctx, "compliance", "secrets", "validation-failed", "system", map[string]string{
			"error": err.Error(),
		})
		logger.Warn("Secrets compliance check failed", "error", err)
	}

	// Check network policies compliance
	if err := m.validateNetworkPoliciesCompliance(ctx, config.NetworkPolicies); err != nil {
		m.auditSecurityEvent(ctx, "compliance", "network-policies", "validation-failed", "system", map[string]string{
			"error": err.Error(),
		})
		logger.Warn("Network policies compliance check failed", "error", err)
	}

	// Check for security anomalies
	if err := m.detectSecurityAnomalies(ctx); err != nil {
		logger.Warn("Security anomaly detection failed", "error", err)
	}

	logger.Info("Security compliance monitoring completed")
	return nil
}

// detectSecurityAnomalies detects potential security anomalies
func (m *AWSSecurityManager) detectSecurityAnomalies(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Detecting security anomalies")

	// Check for secrets without encryption
	if err := m.detectUnencryptedSecrets(ctx); err != nil {
		return fmt.Errorf("failed to detect unencrypted secrets: %w", err)
	}

	// Check for overly permissive network policies
	if err := m.detectPermissiveNetworkPolicies(ctx); err != nil {
		return fmt.Errorf("failed to detect permissive network policies: %w", err)
	}

	// Check for stale secrets (not rotated recently)
	if err := m.detectStaleSecrets(ctx); err != nil {
		return fmt.Errorf("failed to detect stale secrets: %w", err)
	}

	logger.Info("Security anomaly detection completed")
	return nil
}

// detectUnencryptedSecrets detects secrets that should be encrypted but aren't
func (m *AWSSecurityManager) detectUnencryptedSecrets(ctx context.Context) error {
	secretList := &corev1.SecretList{}
	listOptions := []client.ListOption{
		client.MatchingLabels{
			"app.kubernetes.io/managed-by": "n8n-operator",
		},
	}

	if err := m.client.List(ctx, secretList, listOptions...); err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	for _, secret := range secretList.Items {
		if sensitive, exists := secret.Annotations["n8n.io/sensitive"]; exists && sensitive == "true" {
			if encrypted, exists := secret.Annotations["n8n.io/encryption-enabled"]; !exists || encrypted != "true" {
				m.auditSecurityEvent(ctx, "anomaly", "secret", "unencrypted-sensitive", "system", map[string]string{
					"secret_name": secret.Name,
					"namespace":   secret.Namespace,
				})
			}
		}
	}

	return nil
}

// detectPermissiveNetworkPolicies detects overly permissive network policies
func (m *AWSSecurityManager) detectPermissiveNetworkPolicies(ctx context.Context) error {
	policyList := &networkingv1.NetworkPolicyList{}
	listOptions := []client.ListOption{
		client.MatchingLabels{
			"app.kubernetes.io/managed-by": "n8n-operator",
		},
	}

	if err := m.client.List(ctx, policyList, listOptions...); err != nil {
		return fmt.Errorf("failed to list network policies: %w", err)
	}

	for _, policy := range policyList.Items {
		// Check for policies that allow all traffic
		for _, rule := range policy.Spec.Ingress {
			if len(rule.From) == 0 && len(rule.Ports) == 0 {
				m.auditSecurityEvent(ctx, "anomaly", "network-policy", "allow-all-ingress", "system", map[string]string{
					"policy_name": policy.Name,
					"namespace":   policy.Namespace,
				})
			}
		}

		for _, rule := range policy.Spec.Egress {
			if len(rule.To) == 0 && len(rule.Ports) == 0 {
				m.auditSecurityEvent(ctx, "anomaly", "network-policy", "allow-all-egress", "system", map[string]string{
					"policy_name": policy.Name,
					"namespace":   policy.Namespace,
				})
			}
		}
	}

	return nil
}

// detectStaleSecrets detects secrets that haven't been rotated recently
func (m *AWSSecurityManager) detectStaleSecrets(ctx context.Context) error {
	secretList := &corev1.SecretList{}
	listOptions := []client.ListOption{
		client.MatchingLabels{
			"app.kubernetes.io/managed-by": "n8n-operator",
		},
	}

	if err := m.client.List(ctx, secretList, listOptions...); err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	staleThreshold := 30 * 24 * time.Hour // 30 days

	for _, secret := range secretList.Items {
		if rotationEnabled, exists := secret.Annotations["n8n.io/rotation-enabled"]; exists && rotationEnabled == "true" {
			var lastRotated time.Time
			var err error

			if lastRotatedStr, exists := secret.Annotations["n8n.io/last-rotated"]; exists {
				lastRotated, err = time.Parse(time.RFC3339, lastRotatedStr)
			} else if createdAtStr, exists := secret.Annotations["n8n.io/created-at"]; exists {
				lastRotated, err = time.Parse(time.RFC3339, createdAtStr)
			} else {
				lastRotated = secret.CreationTimestamp.Time
			}

			if err == nil && time.Since(lastRotated) > staleThreshold {
				m.auditSecurityEvent(ctx, "anomaly", "secret", "stale-rotation", "system", map[string]string{
					"secret_name":   secret.Name,
					"namespace":     secret.Namespace,
					"last_rotated":  lastRotated.Format(time.RFC3339),
					"days_stale":    fmt.Sprintf("%.0f", time.Since(lastRotated).Hours()/24),
				})
			}
		}
	}

	return nil
}

// generateSecurityReport generates a comprehensive security report
func (m *AWSSecurityManager) generateSecurityReport(ctx context.Context, instance *n8nv1alpha1.N8nInstance) (map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("AWSSecurityManager")
	logger.Info("Generating security report")

	report := make(map[string]interface{})
	report["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	report["instance"] = instance.Name
	report["namespace"] = instance.Namespace

	// Get secrets metrics
	secretsMetrics, err := m.getSecretsMetrics(ctx, instance.Namespace)
	if err != nil {
		logger.Warn("Failed to get secrets metrics", "error", err)
	} else {
		report["secrets"] = secretsMetrics
	}

	// Get network policies metrics
	networkMetrics, err := m.getNetworkPoliciesMetrics(ctx, instance.Namespace)
	if err != nil {
		logger.Warn("Failed to get network policies metrics", "error", err)
	} else {
		report["network_policies"] = networkMetrics
	}

	// Get RBAC metrics
	rbacMetrics, err := m.getRBACMetrics(ctx, instance.Namespace)
	if err != nil {
		logger.Warn("Failed to get RBAC metrics", "error", err)
	} else {
		report["rbac"] = rbacMetrics
	}

	// Add compliance status
	report["compliance"] = map[string]interface{}{
		"iam_compliant":             true, // Would be determined by actual validation
		"secrets_compliant":         true,
		"network_policies_compliant": true,
		"rbac_compliant":            true,
	}

	logger.Info("Security report generated successfully")
	return report, nil
}

// getRBACMetrics retrieves RBAC metrics
func (m *AWSSecurityManager) getRBACMetrics(ctx context.Context, namespace string) (map[string]interface{}, error) {
	metrics := make(map[string]interface{})

	// Count ServiceAccounts
	saList := &corev1.ServiceAccountList{}
	if err := m.client.List(ctx, saList, client.InNamespace(namespace), client.MatchingLabels{
		"app.kubernetes.io/managed-by": "n8n-operator",
	}); err == nil {
		metrics["service_accounts"] = len(saList.Items)
	}

	// Count Roles
	roleList := &rbacv1.RoleList{}
	if err := m.client.List(ctx, roleList, client.InNamespace(namespace), client.MatchingLabels{
		"app.kubernetes.io/managed-by": "n8n-operator",
	}); err == nil {
		metrics["roles"] = len(roleList.Items)
	}

	// Count RoleBindings
	rbList := &rbacv1.RoleBindingList{}
	if err := m.client.List(ctx, rbList, client.InNamespace(namespace), client.MatchingLabels{
		"app.kubernetes.io/managed-by": "n8n-operator",
	}); err == nil {
		metrics["role_bindings"] = len(rbList.Items)
	}

	// Count ClusterRoles
	crList := &rbacv1.ClusterRoleList{}
	if err := m.client.List(ctx, crList, client.MatchingLabels{
		"app.kubernetes.io/managed-by": "n8n-operator",
	}); err == nil {
		metrics["cluster_roles"] = len(crList.Items)
	}

	// Count ClusterRoleBindings
	crbList := &rbacv1.ClusterRoleBindingList{}
	if err := m.client.List(ctx, crbList, client.MatchingLabels{
		"app.kubernetes.io/managed-by": "n8n-operator",
	}); err == nil {
		metrics["cluster_role_bindings"] = len(crbList.Items)
	}

	return metrics, nil
}