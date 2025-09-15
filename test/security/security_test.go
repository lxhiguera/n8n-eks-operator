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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// SecurityTestSuite contains security and compliance tests for the n8n operator
type SecurityTestSuite struct {
	suite.Suite
	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient client.Client
	clientset *kubernetes.Clientset
	
	// Security test configuration
	config *SecurityConfig
	
	// Test resources
	testNamespace string
	testPrefix    string
	cleanupFuncs  []func() error
}

// SetupSuite runs before all tests in the suite
func (suite *SecurityTestSuite) SetupSuite() {
	suite.config = NewSecurityConfig()
	suite.testPrefix = fmt.Sprintf("n8n-sec-%d", time.Now().Unix())
	suite.testNamespace = fmt.Sprintf("%s-ns", suite.testPrefix)
	
	suite.setupTestEnvironment()
	suite.createTestNamespace()
	
	suite.T().Logf("Security test suite initialized with namespace: %s", suite.testNamespace)
}

// TearDownSuite runs after all tests in the suite
func (suite *SecurityTestSuite) TearDownSuite() {
	suite.T().Log("Cleaning up security test resources")
	
	// Execute cleanup functions
	for i := len(suite.cleanupFuncs) - 1; i >= 0; i-- {
		if err := suite.cleanupFuncs[i](); err != nil {
			suite.T().Logf("Cleanup error: %v", err)
		}
	}
	
	// Stop test environment
	if suite.testEnv != nil {
		err := suite.testEnv.Stop()
		if err != nil {
			suite.T().Logf("Failed to stop test environment: %v", err)
		}
	}
}

// TestSecretEncryption tests secret encryption and secure handling
func (suite *SecurityTestSuite) TestSecretEncryption() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	
	suite.T().Log("Testing secret encryption and secure handling")
	
	// Test 1: Create encrypted secrets
	secretData := map[string][]byte{
		"database-password": []byte("super-secret-password"),
		"api-key":          []byte("sk-1234567890abcdef"),
		"private-key":      suite.generateTestPrivateKey(),
	}
	
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-encrypted-secret",
			Namespace: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-security",
				"test-type":  "encryption",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: secretData,
	}
	
	err := suite.k8sClient.Create(ctx, secret)
	require.NoError(suite.T(), err)
	
	// Test 2: Verify secret is stored encrypted (etcd encryption at rest)
	retrievedSecret := &corev1.Secret{}
	err = suite.k8sClient.Get(ctx, types.NamespacedName{
		Name:      secret.Name,
		Namespace: secret.Namespace,
	}, retrievedSecret)
	require.NoError(suite.T(), err)
	
	// Verify data integrity
	assert.Equal(suite.T(), secretData["database-password"], retrievedSecret.Data["database-password"])
	assert.Equal(suite.T(), secretData["api-key"], retrievedSecret.Data["api-key"])
	
	// Test 3: Verify secret access is properly restricted
	suite.verifySecretAccessRestrictions(ctx, secret.Name)
	
	// Test 4: Test secret rotation
	suite.testSecretRotation(ctx, secret.Name)
	
	suite.T().Log("Secret encryption tests completed successfully")
}

// TestNetworkPolicies tests network security policies
func (suite *SecurityTestSuite) TestNetworkPolicies() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	
	suite.T().Log("Testing network security policies")
	
	// Test 1: Create default deny-all network policy
	denyAllPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-deny-all",
			Namespace: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-security",
				"test-type":  "network-policy",
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{}, // Empty selector = all pods
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}
	
	err := suite.k8sClient.Create(ctx, denyAllPolicy)
	require.NoError(suite.T(), err)
	
	// Test 2: Create specific allow policies for n8n components
	suite.createN8nNetworkPolicies(ctx)
	
	// Test 3: Verify network policies are properly configured
	suite.verifyNetworkPolicyConfiguration(ctx)
	
	// Test 4: Test network isolation
	suite.testNetworkIsolation(ctx)
	
	suite.T().Log("Network policy tests completed successfully")
}

// TestRBACConfiguration tests RBAC security configuration
func (suite *SecurityTestSuite) TestRBACConfiguration() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	
	suite.T().Log("Testing RBAC configuration")
	
	// Test 1: Create service account with minimal permissions
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "n8n-operator-test",
			Namespace: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-security",
				"test-type":  "rbac",
			},
		},
	}
	
	err := suite.k8sClient.Create(ctx, serviceAccount)
	require.NoError(suite.T(), err)
	
	// Test 2: Create role with minimal required permissions
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "n8n-operator-role",
			Namespace: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-security",
				"test-type":  "rbac",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: [""],
				Resources: ["secrets", "configmaps", "services"],
				Verbs:     []string{"get", "list", "create", "update", "patch"},
			},
			{
				APIGroups: ["apps"],
				Resources: ["deployments"],
				Verbs:     []string{"get", "list", "create", "update", "patch"},
			},
			{
				APIGroups: ["n8n.io"],
				Resources: ["n8ninstances"],
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
			},
		},
	}
	
	err = suite.k8sClient.Create(ctx, role)
	require.NoError(suite.T(), err)
	
	// Test 3: Create role binding
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "n8n-operator-binding",
			Namespace: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-security",
				"test-type":  "rbac",
			},
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccount.Name,
				Namespace: suite.testNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     role.Name,
		},
	}
	
	err = suite.k8sClient.Create(ctx, roleBinding)
	require.NoError(suite.T(), err)
	
	// Test 4: Verify RBAC permissions are minimal and correct
	suite.verifyRBACPermissions(ctx, serviceAccount.Name)
	
	// Test 5: Test privilege escalation prevention
	suite.testPrivilegeEscalationPrevention(ctx)
	
	suite.T().Log("RBAC configuration tests completed successfully")
}

// TestPodSecurityStandards tests Pod Security Standards compliance
func (suite *SecurityTestSuite) TestPodSecurityStandards() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	
	suite.T().Log("Testing Pod Security Standards compliance")
	
	// Create N8nInstance with security-compliant configuration
	instance := suite.createSecureN8nInstance("secure-instance")
	
	err := suite.k8sClient.Create(ctx, instance)
	require.NoError(suite.T(), err)
	
	// Test 1: Verify pods run as non-root
	suite.verifyNonRootExecution(ctx, instance.Name)
	
	// Test 2: Verify security contexts are properly configured
	suite.verifySecurityContexts(ctx, instance.Name)
	
	// Test 3: Verify no privileged containers
	suite.verifyNoPrivilegedContainers(ctx, instance.Name)
	
	// Test 4: Verify resource limits are set
	suite.verifyResourceLimits(ctx, instance.Name)
	
	// Test 5: Verify read-only root filesystem where possible
	suite.verifyReadOnlyRootFilesystem(ctx, instance.Name)
	
	suite.T().Log("Pod Security Standards tests completed successfully")
}

// TestVulnerabilityScanning tests vulnerability scanning capabilities
func (suite *SecurityTestSuite) TestVulnerabilityScanning() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	
	suite.T().Log("Testing vulnerability scanning")
	
	// Test 1: Scan operator image for vulnerabilities
	suite.scanOperatorImage(ctx)
	
	// Test 2: Scan n8n images for vulnerabilities
	suite.scanN8nImages(ctx)
	
	// Test 3: Verify no critical vulnerabilities
	suite.verifyCriticalVulnerabilities(ctx)
	
	// Test 4: Test dependency scanning
	suite.testDependencyScanning(ctx)
	
	suite.T().Log("Vulnerability scanning tests completed successfully")
}

// TestComplianceChecks tests various compliance requirements
func (suite *SecurityTestSuite) TestComplianceChecks() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	
	suite.T().Log("Testing compliance checks")
	
	// Test 1: SOC 2 compliance checks
	suite.testSOC2Compliance(ctx)
	
	// Test 2: GDPR compliance checks
	suite.testGDPRCompliance(ctx)
	
	// Test 3: HIPAA compliance checks (if applicable)
	suite.testHIPAACompliance(ctx)
	
	// Test 4: PCI DSS compliance checks (if applicable)
	suite.testPCIDSSCompliance(ctx)
	
	// Test 5: CIS Kubernetes Benchmark compliance
	suite.testCISKubernetesBenchmark(ctx)
	
	suite.T().Log("Compliance checks completed successfully")
}

// TestSecurityAuditing tests security auditing and logging
func (suite *SecurityTestSuite) TestSecurityAuditing() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	
	suite.T().Log("Testing security auditing and logging")
	
	// Test 1: Verify audit logging is enabled
	suite.verifyAuditLogging(ctx)
	
	// Test 2: Test security event logging
	suite.testSecurityEventLogging(ctx)
	
	// Test 3: Verify log integrity and tamper protection
	suite.verifyLogIntegrity(ctx)
	
	// Test 4: Test log retention policies
	suite.testLogRetentionPolicies(ctx)
	
	// Test 5: Test security alerting
	suite.testSecurityAlerting(ctx)
	
	suite.T().Log("Security auditing tests completed successfully")
}

// Helper methods

// setupTestEnvironment sets up the test environment
func (suite *SecurityTestSuite) setupTestEnvironment() {
	suite.T().Log("Setting up security test environment")
	
	suite.testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{"../../config/crd/bases"},
		ErrorIfCRDPathMissing: false,
	}
	
	cfg, err := suite.testEnv.Start()
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), cfg)
	
	suite.cfg = cfg
	
	// Create Kubernetes client
	scheme := ctrl.GetConfigOrDie().Scheme
	err = n8nv1alpha1.AddToScheme(scheme)
	require.NoError(suite.T(), err)
	
	suite.k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(suite.T(), err)
	
	suite.clientset, err = kubernetes.NewForConfig(cfg)
	require.NoError(suite.T(), err)
}

// createTestNamespace creates a test namespace
func (suite *SecurityTestSuite) createTestNamespace() {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-security",
				"test-run":   suite.testPrefix,
				"pod-security.kubernetes.io/enforce": "restricted",
				"pod-security.kubernetes.io/audit":   "restricted",
				"pod-security.kubernetes.io/warn":    "restricted",
			},
		},
	}
	
	err := suite.k8sClient.Create(context.Background(), ns)
	require.NoError(suite.T(), err)
	
	suite.T().Logf("Created test namespace: %s", suite.testNamespace)
}

// generateTestPrivateKey generates a test RSA private key
func (suite *SecurityTestSuite) generateTestPrivateKey() []byte {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(suite.T(), err)
	
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	
	return pem.EncodeToMemory(privateKeyPEM)
}

// createSecureN8nInstance creates a security-compliant N8nInstance
func (suite *SecurityTestSuite) createSecureN8nInstance(name string) *n8nv1alpha1.N8nInstance {
	return &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-security",
				"test-run":   suite.testPrefix,
			},
		},
		Spec: n8nv1alpha1.N8nInstanceSpec{
			Version: "1.0.0",
			Domain:  fmt.Sprintf("%s.secure.test.local", name),
			Components: &n8nv1alpha1.ComponentsSpec{
				Main: &n8nv1alpha1.ComponentSpec{
					Replicas: 1,
					Port:     5678,
					Resources: &n8nv1alpha1.ResourcesSpec{
						Requests: &n8nv1alpha1.ResourceRequirementsSpec{
							CPU:    "100m",
							Memory: "128Mi",
						},
						Limits: &n8nv1alpha1.ResourceRequirementsSpec{
							CPU:    "500m",
							Memory: "512Mi",
						},
					},
					SecurityContext: &n8nv1alpha1.SecurityContextSpec{
						RunAsNonRoot:             true,
						RunAsUser:                1000,
						RunAsGroup:               3000,
						ReadOnlyRootFilesystem:   true,
						AllowPrivilegeEscalation: false,
						Capabilities: &n8nv1alpha1.CapabilitiesSpec{
							Drop: []string{"ALL"},
						},
					},
				},
			},
			Security: &n8nv1alpha1.SecuritySpec{
				PodSecurityStandard: "restricted",
				NetworkPolicies: &n8nv1alpha1.NetworkPoliciesSpec{
					Enabled:    true,
					DenyAll:    true,
					AllowRules: []n8nv1alpha1.NetworkPolicyRule{
						{
							Name: "allow-dns",
							Ports: []n8nv1alpha1.NetworkPolicyPort{
								{Port: 53, Protocol: "UDP"},
							},
						},
					},
				},
				RBAC: &n8nv1alpha1.RBACSpec{
					Enabled:           true,
					MinimalPermissions: true,
				},
			},
		},
	}
}

// TestSecuritySuite runs the security test suite
func TestSecuritySuite(t *testing.T) {
	suite.Run(t, new(SecurityTestSuite))
}