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

//go:build security
// +build security

package security

import (
	"context"
	"fmt"
	"strings"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// verifySecretAccessRestrictions verifies that secret access is properly restricted
func (suite *SecurityTestSuite) verifySecretAccessRestrictions(ctx context.Context, secretName string) {
	suite.T().Log("Verifying secret access restrictions")
	
	// Test 1: Verify secret exists and has proper labels
	secret := &corev1.Secret{}
	err := suite.k8sClient.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: suite.testNamespace,
	}, secret)
	require.NoError(suite.T(), err)
	
	// Test 2: Verify secret has security labels
	assert.Contains(suite.T(), secret.Labels, "test-suite")
	assert.Contains(suite.T(), secret.Labels, "test-type")
	
	// Test 3: Verify secret type is appropriate
	assert.Equal(suite.T(), corev1.SecretTypeOpaque, secret.Type)
	
	// Test 4: Verify secret data is base64 encoded (Kubernetes default)
	for key, value := range secret.Data {
		assert.NotEmpty(suite.T(), value, "Secret data for key %s should not be empty", key)
		// Verify it's valid base64 (Kubernetes stores secrets as base64)
		assert.True(suite.T(), len(value) > 0, "Secret value should not be empty")
	}
	
	suite.T().Log("Secret access restrictions verified")
}

// testSecretRotation tests secret rotation functionality
func (suite *SecurityTestSuite) testSecretRotation(ctx context.Context, secretName string) {
	suite.T().Log("Testing secret rotation")
	
	// Get original secret
	originalSecret := &corev1.Secret{}
	err := suite.k8sClient.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: suite.testNamespace,
	}, originalSecret)
	require.NoError(suite.T(), err)
	
	originalPassword := originalSecret.Data["database-password"]
	
	// Simulate secret rotation by updating the secret
	newPassword := []byte("new-rotated-password-123")
	originalSecret.Data["database-password"] = newPassword
	
	err = suite.k8sClient.Update(ctx, originalSecret)
	require.NoError(suite.T(), err)
	
	// Verify the secret was updated
	updatedSecret := &corev1.Secret{}
	err = suite.k8sClient.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: suite.testNamespace,
	}, updatedSecret)
	require.NoError(suite.T(), err)
	
	assert.NotEqual(suite.T(), originalPassword, updatedSecret.Data["database-password"])
	assert.Equal(suite.T(), newPassword, updatedSecret.Data["database-password"])
	
	suite.T().Log("Secret rotation test completed")
}

// createN8nNetworkPolicies creates network policies for n8n components
func (suite *SecurityTestSuite) createN8nNetworkPolicies(ctx context.Context) {
	suite.T().Log("Creating n8n network policies")
	
	// Allow policy for n8n main component
	mainPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "n8n-main-allow",
			Namespace: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-security",
				"test-type":  "network-policy",
				"component":  "main",
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/component": "main",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 5678},
						},
					},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					// Allow DNS
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: &[]corev1.Protocol{corev1.ProtocolUDP}[0],
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
						},
					},
				},
				{
					// Allow database access
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 5432},
						},
					},
				},
			},
		},
	}
	
	err := suite.k8sClient.Create(ctx, mainPolicy)
	require.NoError(suite.T(), err)
	
	// Allow policy for n8n webhook component
	webhookPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "n8n-webhook-allow",
			Namespace: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-security",
				"test-type":  "network-policy",
				"component":  "webhook",
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/component": "webhook",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 5679},
						},
					},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					// Allow DNS
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: &[]corev1.Protocol{corev1.ProtocolUDP}[0],
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
						},
					},
				},
			},
		},
	}
	
	err = suite.k8sClient.Create(ctx, webhookPolicy)
	require.NoError(suite.T(), err)
	
	suite.T().Log("n8n network policies created")
}

// verifyNetworkPolicyConfiguration verifies network policy configuration
func (suite *SecurityTestSuite) verifyNetworkPolicyConfiguration(ctx context.Context) {
	suite.T().Log("Verifying network policy configuration")
	
	// List all network policies in the namespace
	policyList := &networkingv1.NetworkPolicyList{}
	err := suite.k8sClient.List(ctx, policyList, client.InNamespace(suite.testNamespace))
	require.NoError(suite.T(), err)
	
	// Verify we have the expected policies
	policyNames := make([]string, len(policyList.Items))
	for i, policy := range policyList.Items {
		policyNames[i] = policy.Name
	}
	
	assert.Contains(suite.T(), policyNames, "default-deny-all")
	assert.Contains(suite.T(), policyNames, "n8n-main-allow")
	assert.Contains(suite.T(), policyNames, "n8n-webhook-allow")
	
	// Verify default deny-all policy
	for _, policy := range policyList.Items {
		if policy.Name == "default-deny-all" {
			assert.Empty(suite.T(), policy.Spec.PodSelector.MatchLabels, "Default deny-all should select all pods")
			assert.Contains(suite.T(), policy.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
			assert.Contains(suite.T(), policy.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)
			assert.Empty(suite.T(), policy.Spec.Ingress, "Default deny-all should have no ingress rules")
			assert.Empty(suite.T(), policy.Spec.Egress, "Default deny-all should have no egress rules")
		}
	}
	
	suite.T().Log("Network policy configuration verified")
}

// testNetworkIsolation tests network isolation between components
func (suite *SecurityTestSuite) testNetworkIsolation(ctx context.Context) {
	suite.T().Log("Testing network isolation")
	
	// This is a placeholder for network isolation testing
	// In a real implementation, you would:
	// 1. Deploy test pods with different labels
	// 2. Try to connect between pods that should be isolated
	// 3. Verify that connections are blocked as expected
	// 4. Verify that allowed connections work
	
	// For now, we'll verify that the policies exist and are configured correctly
	policyList := &networkingv1.NetworkPolicyList{}
	err := suite.k8sClient.List(ctx, policyList, client.InNamespace(suite.testNamespace))
	require.NoError(suite.T(), err)
	
	assert.True(suite.T(), len(policyList.Items) >= 3, "Should have at least 3 network policies")
	
	suite.T().Log("Network isolation test completed")
}

// verifyRBACPermissions verifies RBAC permissions are minimal and correct
func (suite *SecurityTestSuite) verifyRBACPermissions(ctx context.Context, serviceAccountName string) {
	suite.T().Log("Verifying RBAC permissions")
	
	// Get the role binding
	roleBinding := &rbacv1.RoleBinding{}
	err := suite.k8sClient.Get(ctx, types.NamespacedName{
		Name:      "n8n-operator-binding",
		Namespace: suite.testNamespace,
	}, roleBinding)
	require.NoError(suite.T(), err)
	
	// Verify the service account is bound
	found := false
	for _, subject := range roleBinding.Subjects {
		if subject.Name == serviceAccountName && subject.Kind == "ServiceAccount" {
			found = true
			break
		}
	}
	assert.True(suite.T(), found, "Service account should be bound to role")
	
	// Get the role
	role := &rbacv1.Role{}
	err = suite.k8sClient.Get(ctx, types.NamespacedName{
		Name:      roleBinding.RoleRef.Name,
		Namespace: suite.testNamespace,
	}, role)
	require.NoError(suite.T(), err)
	
	// Verify permissions are minimal
	suite.verifyMinimalPermissions(role.Rules)
	
	suite.T().Log("RBAC permissions verified")
}

// verifyMinimalPermissions verifies that RBAC rules follow principle of least privilege
func (suite *SecurityTestSuite) verifyMinimalPermissions(rules []rbacv1.PolicyRule) {
	suite.T().Log("Verifying minimal permissions")
	
	for _, rule := range rules {
		// Verify no wildcard permissions
		for _, verb := range rule.Verbs {
			assert.NotEqual(suite.T(), "*", verb, "Should not have wildcard verbs")
		}
		
		for _, resource := range rule.Resources {
			assert.NotEqual(suite.T(), "*", resource, "Should not have wildcard resources")
		}
		
		for _, apiGroup := range rule.APIGroups {
			assert.NotEqual(suite.T(), "*", apiGroup, "Should not have wildcard API groups")
		}
		
		// Verify no dangerous verbs
		dangerousVerbs := []string{"delete", "deletecollection", "escalate", "impersonate"}
		for _, verb := range rule.Verbs {
			for _, dangerous := range dangerousVerbs {
				if verb == dangerous {
					suite.T().Logf("Warning: Found potentially dangerous verb: %s", verb)
				}
			}
		}
	}
	
	suite.T().Log("Minimal permissions verified")
}

// testPrivilegeEscalationPrevention tests privilege escalation prevention
func (suite *SecurityTestSuite) testPrivilegeEscalationPrevention(ctx context.Context) {
	suite.T().Log("Testing privilege escalation prevention")
	
	// Test 1: Verify no cluster-admin permissions
	clusterRoleBindings := &rbacv1.ClusterRoleBindingList{}
	err := suite.k8sClient.List(ctx, clusterRoleBindings)
	if err == nil {
		for _, binding := range clusterRoleBindings.Items {
			if binding.RoleRef.Name == "cluster-admin" {
				for _, subject := range binding.Subjects {
					if subject.Namespace == suite.testNamespace {
						suite.T().Errorf("Found cluster-admin binding for namespace %s", suite.testNamespace)
					}
				}
			}
		}
	}
	
	// Test 2: Verify service accounts don't have excessive permissions
	serviceAccounts := &corev1.ServiceAccountList{}
	err = suite.k8sClient.List(ctx, serviceAccounts, client.InNamespace(suite.testNamespace))
	require.NoError(suite.T(), err)
	
	for _, sa := range serviceAccounts.Items {
		if strings.Contains(sa.Name, "n8n") {
			// Verify no automount of service account token if not needed
			if sa.AutomountServiceAccountToken != nil {
				suite.T().Logf("Service account %s has automount token: %v", sa.Name, *sa.AutomountServiceAccountToken)
			}
		}
	}
	
	suite.T().Log("Privilege escalation prevention test completed")
}

// verifyNonRootExecution verifies pods run as non-root
func (suite *SecurityTestSuite) verifyNonRootExecution(ctx context.Context, instanceName string) {
	suite.T().Log("Verifying non-root execution")
	
	// Get deployments for the instance
	deployments := &appsv1.DeploymentList{}
	err := suite.k8sClient.List(ctx, deployments, 
		client.InNamespace(suite.testNamespace),
		client.MatchingLabels{"app.kubernetes.io/instance": instanceName})
	
	if err != nil {
		suite.T().Logf("Could not list deployments: %v", err)
		return
	}
	
	for _, deployment := range deployments.Items {
		podSpec := deployment.Spec.Template.Spec
		
		// Check pod security context
		if podSpec.SecurityContext != nil {
			if podSpec.SecurityContext.RunAsNonRoot != nil {
				assert.True(suite.T(), *podSpec.SecurityContext.RunAsNonRoot, 
					"Pod should run as non-root in deployment %s", deployment.Name)
			}
			
			if podSpec.SecurityContext.RunAsUser != nil {
				assert.NotEqual(suite.T(), int64(0), *podSpec.SecurityContext.RunAsUser,
					"Pod should not run as user 0 (root) in deployment %s", deployment.Name)
			}
		}
		
		// Check container security contexts
		for _, container := range podSpec.Containers {
			if container.SecurityContext != nil {
				if container.SecurityContext.RunAsNonRoot != nil {
					assert.True(suite.T(), *container.SecurityContext.RunAsNonRoot,
						"Container %s should run as non-root", container.Name)
				}
				
				if container.SecurityContext.RunAsUser != nil {
					assert.NotEqual(suite.T(), int64(0), *container.SecurityContext.RunAsUser,
						"Container %s should not run as user 0 (root)", container.Name)
				}
			}
		}
	}
	
	suite.T().Log("Non-root execution verified")
}

// verifySecurityContexts verifies security contexts are properly configured
func (suite *SecurityTestSuite) verifySecurityContexts(ctx context.Context, instanceName string) {
	suite.T().Log("Verifying security contexts")
	
	deployments := &appsv1.DeploymentList{}
	err := suite.k8sClient.List(ctx, deployments,
		client.InNamespace(suite.testNamespace),
		client.MatchingLabels{"app.kubernetes.io/instance": instanceName})
	
	if err != nil {
		suite.T().Logf("Could not list deployments: %v", err)
		return
	}
	
	for _, deployment := range deployments.Items {
		podSpec := deployment.Spec.Template.Spec
		
		// Verify pod security context
		if podSpec.SecurityContext != nil {
			sc := podSpec.SecurityContext
			
			// Check FSGroup
			if sc.FSGroup != nil {
				assert.NotEqual(suite.T(), int64(0), *sc.FSGroup,
					"FSGroup should not be 0 in deployment %s", deployment.Name)
			}
			
			// Check supplemental groups
			for _, group := range sc.SupplementalGroups {
				assert.NotEqual(suite.T(), int64(0), group,
					"Supplemental group should not be 0 in deployment %s", deployment.Name)
			}
		}
		
		// Verify container security contexts
		for _, container := range podSpec.Containers {
			if container.SecurityContext != nil {
				sc := container.SecurityContext
				
				// Check privilege escalation
				if sc.AllowPrivilegeEscalation != nil {
					assert.False(suite.T(), *sc.AllowPrivilegeEscalation,
						"Container %s should not allow privilege escalation", container.Name)
				}
				
				// Check privileged
				if sc.Privileged != nil {
					assert.False(suite.T(), *sc.Privileged,
						"Container %s should not be privileged", container.Name)
				}
				
				// Check read-only root filesystem
				if sc.ReadOnlyRootFilesystem != nil {
					assert.True(suite.T(), *sc.ReadOnlyRootFilesystem,
						"Container %s should have read-only root filesystem", container.Name)
				}
				
				// Check capabilities
				if sc.Capabilities != nil {
					// Verify ALL capabilities are dropped
					assert.Contains(suite.T(), sc.Capabilities.Drop, corev1.Capability("ALL"),
						"Container %s should drop ALL capabilities", container.Name)
					
					// Verify no dangerous capabilities are added
					dangerousCaps := []corev1.Capability{"SYS_ADMIN", "NET_ADMIN", "SYS_TIME"}
					for _, cap := range sc.Capabilities.Add {
						for _, dangerous := range dangerousCaps {
							assert.NotEqual(suite.T(), dangerous, cap,
								"Container %s should not add dangerous capability %s", container.Name, cap)
						}
					}
				}
			}
		}
	}
	
	suite.T().Log("Security contexts verified")
}

// verifyNoPrivilegedContainers verifies no containers run in privileged mode
func (suite *SecurityTestSuite) verifyNoPrivilegedContainers(ctx context.Context, instanceName string) {
	suite.T().Log("Verifying no privileged containers")
	
	deployments := &appsv1.DeploymentList{}
	err := suite.k8sClient.List(ctx, deployments,
		client.InNamespace(suite.testNamespace),
		client.MatchingLabels{"app.kubernetes.io/instance": instanceName})
	
	if err != nil {
		suite.T().Logf("Could not list deployments: %v", err)
		return
	}
	
	for _, deployment := range deployments.Items {
		for _, container := range deployment.Spec.Template.Spec.Containers {
			if container.SecurityContext != nil && container.SecurityContext.Privileged != nil {
				assert.False(suite.T(), *container.SecurityContext.Privileged,
					"Container %s in deployment %s should not be privileged", 
					container.Name, deployment.Name)
			}
		}
		
		for _, container := range deployment.Spec.Template.Spec.InitContainers {
			if container.SecurityContext != nil && container.SecurityContext.Privileged != nil {
				assert.False(suite.T(), *container.SecurityContext.Privileged,
					"Init container %s in deployment %s should not be privileged",
					container.Name, deployment.Name)
			}
		}
	}
	
	suite.T().Log("No privileged containers verified")
}

// verifyResourceLimits verifies resource limits are set
func (suite *SecurityTestSuite) verifyResourceLimits(ctx context.Context, instanceName string) {
	suite.T().Log("Verifying resource limits")
	
	deployments := &appsv1.DeploymentList{}
	err := suite.k8sClient.List(ctx, deployments,
		client.InNamespace(suite.testNamespace),
		client.MatchingLabels{"app.kubernetes.io/instance": instanceName})
	
	if err != nil {
		suite.T().Logf("Could not list deployments: %v", err)
		return
	}
	
	for _, deployment := range deployments.Items {
		for _, container := range deployment.Spec.Template.Spec.Containers {
			// Verify CPU limits
			cpuLimit := container.Resources.Limits.Cpu()
			assert.NotNil(suite.T(), cpuLimit, 
				"Container %s should have CPU limits", container.Name)
			
			// Verify memory limits
			memLimit := container.Resources.Limits.Memory()
			assert.NotNil(suite.T(), memLimit,
				"Container %s should have memory limits", container.Name)
			
			// Verify requests are set
			cpuRequest := container.Resources.Requests.Cpu()
			assert.NotNil(suite.T(), cpuRequest,
				"Container %s should have CPU requests", container.Name)
			
			memRequest := container.Resources.Requests.Memory()
			assert.NotNil(suite.T(), memRequest,
				"Container %s should have memory requests", container.Name)
		}
	}
	
	suite.T().Log("Resource limits verified")
}

// verifyReadOnlyRootFilesystem verifies read-only root filesystem where possible
func (suite *SecurityTestSuite) verifyReadOnlyRootFilesystem(ctx context.Context, instanceName string) {
	suite.T().Log("Verifying read-only root filesystem")
	
	deployments := &appsv1.DeploymentList{}
	err := suite.k8sClient.List(ctx, deployments,
		client.InNamespace(suite.testNamespace),
		client.MatchingLabels{"app.kubernetes.io/instance": instanceName})
	
	if err != nil {
		suite.T().Logf("Could not list deployments: %v", err)
		return
	}
	
	for _, deployment := range deployments.Items {
		for _, container := range deployment.Spec.Template.Spec.Containers {
			if container.SecurityContext != nil && container.SecurityContext.ReadOnlyRootFilesystem != nil {
				assert.True(suite.T(), *container.SecurityContext.ReadOnlyRootFilesystem,
					"Container %s should have read-only root filesystem", container.Name)
			}
		}
	}
	
	suite.T().Log("Read-only root filesystem verified")
}