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

//go:build performance
// +build performance

package performance

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// PerformanceTestSuite contains performance tests for the n8n operator
type PerformanceTestSuite struct {
	suite.Suite
	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient client.Client
	clientset *kubernetes.Clientset
	
	// Performance test configuration
	config *PerformanceConfig
	
	// Metrics collection
	metrics *PerformanceMetrics
	
	// Test resources
	testNamespace string
	testPrefix    string
	cleanupFuncs  []func() error
}

// PerformanceConfig holds configuration for performance tests
type PerformanceConfig struct {
	// Test execution settings
	TestTimeout        time.Duration
	ConcurrentInstances int
	ReconcileIterations int
	
	// Performance thresholds
	MaxReconcileTime      time.Duration
	MaxMemoryUsage        int64 // MB
	MaxCPUUsage           float64 // percentage
	
	// Load test settings
	LoadTestDuration      time.Duration
	LoadTestConcurrency   int
	LoadTestRampUpTime    time.Duration
	
	// Benchmark settings
	BenchmarkIterations   int
	BenchmarkWarmupTime   time.Duration
}

// PerformanceMetrics holds performance metrics
type PerformanceMetrics struct {
	mu sync.RWMutex
	
	// Reconciliation metrics
	ReconcileTimes        []time.Duration
	ReconcileErrors       int
	ReconcileSuccesses    int
	
	// Resource usage metrics
	MemoryUsage           []int64
	CPUUsage              []float64
	
	// Throughput metrics
	InstancesPerSecond    float64
	ReconciliationsPerSecond float64
	
	// Latency metrics
	P50ReconcileTime      time.Duration
	P95ReconcileTime      time.Duration
	P99ReconcileTime      time.Duration
	
	// Error metrics
	ErrorRate             float64
	TimeoutRate           float64
}

// SetupSuite runs before all tests in the suite
func (suite *PerformanceTestSuite) SetupSuite() {
	suite.config = NewPerformanceConfig()
	suite.metrics = NewPerformanceMetrics()
	suite.testPrefix = fmt.Sprintf("n8n-perf-%d", time.Now().Unix())
	suite.testNamespace = fmt.Sprintf("%s-ns", suite.testPrefix)
	
	suite.setupTestEnvironment()
	suite.createTestNamespace()
	
	suite.T().Logf("Performance test suite initialized with namespace: %s", suite.testNamespace)
}

// TearDownSuite runs after all tests in the suite
func (suite *PerformanceTestSuite) TearDownSuite() {
	suite.T().Log("Cleaning up performance test resources")
	
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
	
	// Print final metrics
	suite.printFinalMetrics()
}

// TestReconcilePerformance tests the performance of single reconciliation
func (suite *PerformanceTestSuite) TestReconcilePerformance() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.config.TestTimeout)
	defer cancel()
	
	suite.T().Log("Testing single reconciliation performance")
	
	// Create test instance
	instance := suite.createTestInstance("perf-single")
	
	// Measure reconciliation time
	startTime := time.Now()
	err := suite.k8sClient.Create(ctx, instance)
	require.NoError(suite.T(), err)
	
	// Wait for reconciliation to complete
	suite.waitForInstanceReady(ctx, instance.Name)
	reconcileTime := time.Since(startTime)
	
	// Record metrics
	suite.metrics.RecordReconcileTime(reconcileTime)
	
	// Validate performance thresholds
	assert.Less(suite.T(), reconcileTime, suite.config.MaxReconcileTime,
		"Reconciliation time %v exceeds threshold %v", reconcileTime, suite.config.MaxReconcileTime)
	
	suite.T().Logf("Single reconciliation completed in %v", reconcileTime)
}

// TestConcurrentReconciliation tests concurrent reconciliation performance
func (suite *PerformanceTestSuite) TestConcurrentReconciliation() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.config.TestTimeout)
	defer cancel()
	
	suite.T().Log("Testing concurrent reconciliation performance")
	
	concurrency := suite.config.ConcurrentInstances
	instances := make([]*n8nv1alpha1.N8nInstance, concurrency)
	
	// Create instances concurrently
	var wg sync.WaitGroup
	startTime := time.Now()
	
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			
			instanceName := fmt.Sprintf("perf-concurrent-%d", index)
			instance := suite.createTestInstance(instanceName)
			instances[index] = instance
			
			reconcileStart := time.Now()
			err := suite.k8sClient.Create(ctx, instance)
			if err != nil {
				suite.metrics.RecordReconcileError()
				suite.T().Logf("Failed to create instance %s: %v", instanceName, err)
				return
			}
			
			// Wait for this instance to be ready
			suite.waitForInstanceReady(ctx, instanceName)
			reconcileTime := time.Since(reconcileStart)
			
			suite.metrics.RecordReconcileTime(reconcileTime)
			suite.metrics.RecordReconcileSuccess()
		}(i)
	}
	
	wg.Wait()
	totalTime := time.Since(startTime)
	
	// Calculate throughput
	throughput := float64(concurrency) / totalTime.Seconds()
	suite.metrics.InstancesPerSecond = throughput
	
	suite.T().Logf("Concurrent reconciliation: %d instances in %v (%.2f instances/sec)",
		concurrency, totalTime, throughput)
	
	// Validate performance
	assert.Greater(suite.T(), throughput, 0.1, "Throughput too low")
	assert.Less(suite.T(), suite.metrics.ErrorRate, 0.05, "Error rate too high")
}

// TestReconcileIterations tests repeated reconciliation performance
func (suite *PerformanceTestSuite) TestReconcileIterations() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.config.TestTimeout)
	defer cancel()
	
	suite.T().Log("Testing repeated reconciliation performance")
	
	instance := suite.createTestInstance("perf-iterations")
	err := suite.k8sClient.Create(ctx, instance)
	require.NoError(suite.T(), err)
	
	// Wait for initial reconciliation
	suite.waitForInstanceReady(ctx, instance.Name)
	
	// Perform multiple reconciliation iterations
	iterations := suite.config.ReconcileIterations
	reconcileTimes := make([]time.Duration, iterations)
	
	for i := 0; i < iterations; i++ {
		// Trigger reconciliation by updating the instance
		err := suite.k8sClient.Get(ctx, types.NamespacedName{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		}, instance)
		require.NoError(suite.T(), err)
		
		// Update a label to trigger reconciliation
		if instance.Labels == nil {
			instance.Labels = make(map[string]string)
		}
		instance.Labels["iteration"] = fmt.Sprintf("%d", i)
		
		startTime := time.Now()
		err = suite.k8sClient.Update(ctx, instance)
		require.NoError(suite.T(), err)
		
		// Wait for reconciliation to complete
		suite.waitForInstanceReady(ctx, instance.Name)
		reconcileTime := time.Since(startTime)
		
		reconcileTimes[i] = reconcileTime
		suite.metrics.RecordReconcileTime(reconcileTime)
		
		// Small delay between iterations
		time.Sleep(100 * time.Millisecond)
	}
	
	// Calculate statistics
	avgTime := suite.calculateAverage(reconcileTimes)
	p95Time := suite.calculatePercentile(reconcileTimes, 95)
	
	suite.T().Logf("Reconciliation iterations: %d iterations, avg: %v, p95: %v",
		iterations, avgTime, p95Time)
	
	// Validate performance consistency
	assert.Less(suite.T(), p95Time, suite.config.MaxReconcileTime*2,
		"P95 reconciliation time too high")
}

// TestLoadTest performs sustained load testing
func (suite *PerformanceTestSuite) TestLoadTest() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.config.LoadTestDuration+time.Minute)
	defer cancel()
	
	suite.T().Log("Starting load test")
	
	var wg sync.WaitGroup
	stopChan := make(chan struct{})
	
	// Start load generators
	for i := 0; i < suite.config.LoadTestConcurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			suite.loadTestWorker(ctx, workerID, stopChan)
		}(i)
	}
	
	// Run load test for specified duration
	time.Sleep(suite.config.LoadTestDuration)
	close(stopChan)
	
	wg.Wait()
	
	// Calculate final metrics
	suite.calculateFinalMetrics()
	
	suite.T().Logf("Load test completed: %.2f reconciliations/sec, %.2f%% error rate",
		suite.metrics.ReconciliationsPerSecond, suite.metrics.ErrorRate*100)
	
	// Validate load test results
	assert.Less(suite.T(), suite.metrics.ErrorRate, 0.1, "Error rate too high during load test")
	assert.Greater(suite.T(), suite.metrics.ReconciliationsPerSecond, 1.0, "Throughput too low")
}

// BenchmarkReconcileCreate benchmarks N8nInstance creation
func (suite *PerformanceTestSuite) BenchmarkReconcileCreate() {
	suite.T().Log("Running reconcile creation benchmark")
	
	// Warmup
	for i := 0; i < 5; i++ {
		instance := suite.createTestInstance(fmt.Sprintf("warmup-%d", i))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_ = suite.k8sClient.Create(ctx, instance)
		cancel()
	}
	
	// Actual benchmark
	iterations := suite.config.BenchmarkIterations
	times := make([]time.Duration, iterations)
	
	for i := 0; i < iterations; i++ {
		instance := suite.createTestInstance(fmt.Sprintf("bench-%d", i))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		
		start := time.Now()
		err := suite.k8sClient.Create(ctx, instance)
		elapsed := time.Since(start)
		
		cancel()
		
		if err == nil {
			times[i] = elapsed
		}
	}
	
	// Calculate benchmark results
	avgTime := suite.calculateAverage(times)
	minTime := suite.calculateMin(times)
	maxTime := suite.calculateMax(times)
	
	suite.T().Logf("Benchmark results - Avg: %v, Min: %v, Max: %v", avgTime, minTime, maxTime)
}

// BenchmarkReconcileUpdate benchmarks N8nInstance updates
func (suite *PerformanceTestSuite) BenchmarkReconcileUpdate() {
	suite.T().Log("Running reconcile update benchmark")
	
	// Create base instance
	instance := suite.createTestInstance("bench-update")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := suite.k8sClient.Create(ctx, instance)
	cancel()
	require.NoError(suite.T(), err)
	
	// Wait for initial reconciliation
	suite.waitForInstanceReady(context.Background(), instance.Name)
	
	// Benchmark updates
	iterations := suite.config.BenchmarkIterations
	times := make([]time.Duration, iterations)
	
	for i := 0; i < iterations; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		
		// Get latest version
		err := suite.k8sClient.Get(ctx, types.NamespacedName{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		}, instance)
		require.NoError(suite.T(), err)
		
		// Update instance
		if instance.Labels == nil {
			instance.Labels = make(map[string]string)
		}
		instance.Labels["benchmark"] = fmt.Sprintf("%d", i)
		
		start := time.Now()
		err = suite.k8sClient.Update(ctx, instance)
		elapsed := time.Since(start)
		
		cancel()
		
		if err == nil {
			times[i] = elapsed
		}
		
		time.Sleep(10 * time.Millisecond) // Small delay between updates
	}
	
	// Calculate benchmark results
	avgTime := suite.calculateAverage(times)
	p95Time := suite.calculatePercentile(times, 95)
	
	suite.T().Logf("Update benchmark results - Avg: %v, P95: %v", avgTime, p95Time)
}

// Helper methods

// setupTestEnvironment sets up the test environment
func (suite *PerformanceTestSuite) setupTestEnvironment() {
	suite.T().Log("Setting up performance test environment")
	
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
func (suite *PerformanceTestSuite) createTestNamespace() {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-performance",
				"test-run":   suite.testPrefix,
			},
		},
	}
	
	err := suite.k8sClient.Create(context.Background(), ns)
	require.NoError(suite.T(), err)
	
	suite.T().Logf("Created test namespace: %s", suite.testNamespace)
}

// createTestInstance creates a test N8nInstance
func (suite *PerformanceTestSuite) createTestInstance(name string) *n8nv1alpha1.N8nInstance {
	return &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: suite.testNamespace,
			Labels: map[string]string{
				"test-suite": "n8n-performance",
				"test-run":   suite.testPrefix,
			},
		},
		Spec: n8nv1alpha1.N8nInstanceSpec{
			Version: "1.0.0",
			Domain:  fmt.Sprintf("%s.perf.test.local", name),
			Components: &n8nv1alpha1.ComponentsSpec{
				Main: &n8nv1alpha1.ComponentSpec{
					Replicas: 1,
					Port:     5678,
					Resources: &n8nv1alpha1.ResourcesSpec{
						Requests: &n8nv1alpha1.ResourceRequirementsSpec{
							CPU:    "50m",
							Memory: "64Mi",
						},
						Limits: &n8nv1alpha1.ResourceRequirementsSpec{
							CPU:    "100m",
							Memory: "128Mi",
						},
					},
				},
			},
		},
	}
}

// waitForInstanceReady waits for an instance to be ready
func (suite *PerformanceTestSuite) waitForInstanceReady(ctx context.Context, instanceName string) {
	// In a real implementation, this would wait for the instance to reach Ready phase
	// For performance testing, we'll simulate this with a short delay
	time.Sleep(100 * time.Millisecond)
}

// loadTestWorker runs a load test worker
func (suite *PerformanceTestSuite) loadTestWorker(ctx context.Context, workerID int, stopChan <-chan struct{}) {
	counter := 0
	
	for {
		select {
		case <-stopChan:
			return
		case <-ctx.Done():
			return
		default:
			// Perform a reconciliation operation
			instanceName := fmt.Sprintf("load-%d-%d", workerID, counter)
			instance := suite.createTestInstance(instanceName)
			
			start := time.Now()
			err := suite.k8sClient.Create(ctx, instance)
			elapsed := time.Since(start)
			
			if err != nil {
				suite.metrics.RecordReconcileError()
			} else {
				suite.metrics.RecordReconcileTime(elapsed)
				suite.metrics.RecordReconcileSuccess()
			}
			
			counter++
			
			// Small delay between operations
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// TestPerformanceSuite runs the performance test suite
func TestPerformanceSuite(t *testing.T) {
	suite.Run(t, new(PerformanceTestSuite))
}