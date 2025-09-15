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

//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// E2ETestSuite contains end-to-end tests for the n8n operator
type E2ETestSuite struct {
	suite.Suite
	client       client.Client
	k8sClient    kubernetes.Interface
	restConfig   *rest.Config
	testNamespace string
	testInstance  string
	cleanup       []func() error
	timeout       time.Duration
}

// SetupSuite runs before all tests in the suite
func (suite *E2ETestSuite) SetupSuite() {
	// Skip if not running E2E tests
	if os.Getenv("RUN_E2E_TESTS") != "true" {
		suite.T().Skip("Skipping E2E tests. Set RUN_E2E_TESTS=true to run.")
	}

	// Load Kubernetes configuration
	cfg, err := config.GetConfig()
	require.NoError(suite.T(), err, "Failed to get Kubernetes config")
	suite.restConfig = cfg

	// Create controller-runtime client
	scheme := runtime.NewScheme()
	_ = n8nv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(suite.T(), err, "Failed to create Kubernetes client")
	suite.client = k8sClient

	// Create standard Kubernetes client
	clientset, err := kubernetes.NewForConfig(cfg)
	require.NoError(suite.T(), err, "Failed to create Kubernetes clientset")
	suite.k8sClient = clientset

	// Setup test environment
	suite.testNamespace = fmt.Sprintf("n8n-e2e-test-%d", time.Now().Unix())
	suite.testInstance = "test-n8n-instance"
	suite.timeout = time.Minute * 30

	// Create test namespace
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: suite.testNamespace,
			Labels: map[string]string{
				"test-type": "e2e",
				"operator":  "n8n-eks-operator",
			},
		},
	}

	err = suite.client.Create(context.Background(), namespace)
	require.NoError(suite.T(), err, "Failed to create test namespace")

	// Add cleanup for namespace
	suite.cleanup = append(suite.cleanup, func() error {
		return suite.client.Delete(context.Background(), namespace)
	})

	suite.T().Logf("E2E test environment setup completed")
	suite.T().Logf("  Test namespace: %s", suite.testNamespace)
	suite.T().Logf("  Test instance: %s", suite.testInstance)
	suite.T().Logf("  Timeout: %v", suite.timeout)
}

// TearDownSuite runs after all tests in the suite
func (suite *E2ETestSuite) TearDownSuite() {
	suite.T().Log("Cleaning up E2E test resources")

	// Execute cleanup functions in reverse order
	for i := len(suite.cleanup) - 1; i >= 0; i-- {
		if err := suite.cleanup[i](); err != nil {
			suite.T().Logf("Cleanup error: %v", err)
		}
	}

	suite.T().Log("E2E test cleanup completed")
}

// TestCompleteN8nDeployment tests the complete deployment lifecycle
func (suite *E2ETestSuite) TestCompleteN8nDeployment() {
	ctx := context.Background()

	// Create N8nInstance
	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suite.testInstance,
			Namespace: suite.testNamespace,
		},
		Spec: n8nv1alpha1.N8nInstanceSpec{
			Version: "1.0.0",
			Domain:  "n8n-test.example.com",
			Database: &n8nv1alpha1.DatabaseSpec{
				Type: "rds-postgresql",
				RDS: &n8nv1alpha1.RDSSpec{
					Endpoint:          os.Getenv("TEST_RDS_ENDPOINT"),
					Port:              5432,
					DatabaseName:      "n8n",
					CredentialsSource: "secrets-manager",
					SecretsManagerArn: os.Getenv("TEST_DB_SECRET_ARN"),
					SSLMode:           "require",
				},
			},
			Cache: &n8nv1alpha1.CacheSpec{
				Type: "elasticache-redis",
				Redis: &n8nv1alpha1.RedisSpec{
					Endpoint:          os.Getenv("TEST_REDIS_ENDPOINT"),
					Port:              6379,
					AuthEnabled:       true,
					CredentialsSource: "secrets-manager",
					SecretsManagerArn: os.Getenv("TEST_CACHE_SECRET_ARN"),
					TLSEnabled:        true,
					TTLDefault:        "1h",
				},
			},
			Storage: &n8nv1alpha1.StorageSpec{
				Workflows: &n8nv1alpha1.WorkflowsStorageSpec{
					Type: "s3",
					S3: &n8nv1alpha1.S3Spec{
						BucketName: fmt.Sprintf("n8n-e2e-workflows-%d", time.Now().Unix()),
						Region:     "us-west-2",
					},
				},
				Assets: &n8nv1alpha1.AssetsStorageSpec{
					Type: "s3-cloudfront",
					S3: &n8nv1alpha1.S3Spec{
						BucketName:       fmt.Sprintf("n8n-e2e-assets-%d", time.Now().Unix()),
						Region:           "us-west-2",
						AllowedFileTypes: []string{"jpg", "png", "pdf"},
						MaxFileSize:      "10MB",
					},
					CloudFront: &n8nv1alpha1.CloudFrontSpec{
						Enabled: true,
					},
				},
			},
		},
	}

	// Skip test if required resources are not configured
	if instance.Spec.Database.RDS.Endpoint == "" || instance.Spec.Cache.Redis.Endpoint == "" {
		suite.T().Skip("Skipping E2E test - TEST_RDS_ENDPOINT and TEST_REDIS_ENDPOINT must be set")
	}

	suite.T().Log("Creating N8nInstance")
	err := suite.client.Create(ctx, instance)
	require.NoError(suite.T(), err)

	// Add cleanup for instance
	suite.cleanup = append(suite.cleanup, func() error {
		return suite.client.Delete(ctx, instance)
	})

	// Wait for instance to be ready
	suite.T().Log("Waiting for N8nInstance to become ready...")
	err = suite.waitForInstanceReady(ctx, instance)
	require.NoError(suite.T(), err)

	// Validate all components are deployed
	suite.validateComponentsDeployed(ctx, instance)

	// Validate services are accessible
	suite.validateServicesAccessible(ctx, instance)

	// Validate endpoints are working
	suite.validateEndpointsWorking(ctx, instance)

	suite.T().Log("Complete N8n deployment test passed successfully")
}

// TestN8nInstanceLifecycle tests the complete lifecycle of an N8nInstance
func (suite *E2ETestSuite) TestN8nInstanceLifecycle() {
	ctx := context.Background()

	// Test phases: Create -> Update -> Delete
	suite.T().Log("Testing N8nInstance lifecycle: Create -> Update -> Delete")

	// Phase 1: Create
	instance := suite.createMinimalN8nInstance()
	
	// Wait for ready state
	err := suite.waitForInstanceReady(ctx, instance)
	require.NoError(suite.T(), err)

	// Phase 2: Update
	suite.T().Log("Testing N8nInstance update")
	
	// Get current instance
	err = suite.client.Get(ctx, types.NamespacedName{
		Name:      instance.Name,
		Namespace: instance.Namespace,
	}, instance)
	require.NoError(suite.T(), err)

	// Update replica count
	originalReplicas := instance.Spec.Components.Main.Replicas
	instance.Spec.Components.Main.Replicas = originalReplicas + 1

	err = suite.client.Update(ctx, instance)
	require.NoError(suite.T(), err)

	// Wait for update to complete
	err = suite.waitForInstanceReady(ctx, instance)
	require.NoError(suite.T(), err)

	// Validate update was applied
	suite.validateReplicaUpdate(ctx, instance, originalReplicas+1)

	// Phase 3: Delete
	suite.T().Log("Testing N8nInstance deletion")
	err = suite.client.Delete(ctx, instance)
	require.NoError(suite.T(), err)

	// Wait for deletion to complete
	err = suite.waitForInstanceDeleted(ctx, instance)
	require.NoError(suite.T(), err)

	suite.T().Log("N8nInstance lifecycle test completed successfully")
}

// TestN8nFunctionality tests basic n8n functionality
func (suite *E2ETestSuite) TestN8nFunctionality() {
	ctx := context.Background()

	// Create instance
	instance := suite.createMinimalN8nInstance()
	
	// Wait for ready state
	err := suite.waitForInstanceReady(ctx, instance)
	require.NoError(suite.T(), err)

	// Get instance with updated status
	err = suite.client.Get(ctx, types.NamespacedName{
		Name:      instance.Name,
		Namespace: instance.Namespace,
	}, instance)
	require.NoError(suite.T(), err)

	// Test n8n API accessibility
	if instance.Status.Endpoints != nil && instance.Status.Endpoints.Main != "" {
		suite.testN8nAPIAccess(instance.Status.Endpoints.Main)
	}

	// Test webhook endpoint accessibility
	if instance.Status.Endpoints != nil && instance.Status.Endpoints.Webhook != "" {
		suite.testWebhookAccess(instance.Status.Endpoints.Webhook)
	}

	// Clean up
	err = suite.client.Delete(ctx, instance)
	require.NoError(suite.T(), err)

	suite.T().Log("N8n functionality test completed successfully")
}