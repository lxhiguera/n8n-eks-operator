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
	"fmt"
	"os"
	"strconv"
	"time"
)

// E2EConfig holds configuration for E2E tests
type E2EConfig struct {
	// Test execution settings
	RunE2ETests     bool
	UseRealCluster  bool
	TestTimeout     time.Duration
	PollInterval    time.Duration
	
	// Cluster settings
	Kubeconfig      string
	TestNamespace   string
	OperatorImage   string
	
	// AWS settings
	AWSRegion       string
	AWSProfile      string
	
	// Test resource settings
	TestPrefix      string
	CleanupTimeout  time.Duration
	
	// Debugging settings
	VerboseLogging  bool
	KeepResources   bool
	
	// Performance settings
	ParallelTests   int
	MaxRetries      int
}

// NewE2EConfig creates a new E2E configuration from environment variables
func NewE2EConfig() *E2EConfig {
	config := &E2EConfig{
		// Default values
		RunE2ETests:    false,
		UseRealCluster: false,
		TestTimeout:    30 * time.Minute,
		PollInterval:   10 * time.Second,
		CleanupTimeout: 10 * time.Minute,
		ParallelTests:  1,
		MaxRetries:     3,
		VerboseLogging: false,
		KeepResources:  false,
	}
	
	// Load from environment variables
	config.loadFromEnv()
	
	return config
}

// loadFromEnv loads configuration from environment variables
func (c *E2EConfig) loadFromEnv() {
	// Test execution settings
	if val := os.Getenv("RUN_E2E_TESTS"); val != "" {
		c.RunE2ETests = val == "true"
	}
	
	if val := os.Getenv("USE_REAL_CLUSTER"); val != "" {
		c.UseRealCluster = val == "true"
	}
	
	if val := os.Getenv("TEST_TIMEOUT"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			c.TestTimeout = duration
		}
	}
	
	if val := os.Getenv("POLL_INTERVAL"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			c.PollInterval = duration
		}
	}
	
	// Cluster settings
	if val := os.Getenv("KUBECONFIG"); val != "" {
		c.Kubeconfig = val
	}
	
	if val := os.Getenv("TEST_NAMESPACE"); val != "" {
		c.TestNamespace = val
	} else {
		c.TestNamespace = "n8n-e2e-test"
	}
	
	if val := os.Getenv("OPERATOR_IMAGE"); val != "" {
		c.OperatorImage = val
	}
	
	// AWS settings
	if val := os.Getenv("AWS_REGION"); val != "" {
		c.AWSRegion = val
	} else {
		c.AWSRegion = "us-west-2"
	}
	
	if val := os.Getenv("AWS_PROFILE"); val != "" {
		c.AWSProfile = val
	}
	
	// Test resource settings
	if val := os.Getenv("TEST_PREFIX"); val != "" {
		c.TestPrefix = val
	}
	
	if val := os.Getenv("CLEANUP_TIMEOUT"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			c.CleanupTimeout = duration
		}
	}
	
	// Debugging settings
	if val := os.Getenv("VERBOSE_LOGGING"); val != "" {
		c.VerboseLogging = val == "true"
	}
	
	if val := os.Getenv("KEEP_RESOURCES"); val != "" {
		c.KeepResources = val == "true"
	}
	
	// Performance settings
	if val := os.Getenv("PARALLEL_TESTS"); val != "" {
		if num, err := strconv.Atoi(val); err == nil && num > 0 {
			c.ParallelTests = num
		}
	}
	
	if val := os.Getenv("MAX_RETRIES"); val != "" {
		if num, err := strconv.Atoi(val); err == nil && num >= 0 {
			c.MaxRetries = num
		}
	}
}

// Validate checks if the configuration is valid
func (c *E2EConfig) Validate() error {
	if !c.RunE2ETests {
		return nil // Skip validation if tests are disabled
	}
	
	if c.TestTimeout <= 0 {
		return fmt.Errorf("test timeout must be positive")
	}
	
	if c.PollInterval <= 0 {
		return fmt.Errorf("poll interval must be positive")
	}
	
	if c.TestNamespace == "" {
		return fmt.Errorf("test namespace cannot be empty")
	}
	
	if c.ParallelTests <= 0 {
		return fmt.Errorf("parallel tests must be positive")
	}
	
	if c.MaxRetries < 0 {
		return fmt.Errorf("max retries cannot be negative")
	}
	
	return nil
}

// GetTestLabels returns standard labels for test resources
func (c *E2EConfig) GetTestLabels(testRun string) map[string]string {
	labels := map[string]string{
		"test-suite": "n8n-e2e",
		"managed-by": "n8n-e2e-tests",
	}
	
	if testRun != "" {
		labels["test-run"] = testRun
	}
	
	if c.TestPrefix != "" {
		labels["test-prefix"] = c.TestPrefix
	}
	
	return labels
}

// GetTestAnnotations returns standard annotations for test resources
func (c *E2EConfig) GetTestAnnotations() map[string]string {
	annotations := map[string]string{
		"test.n8n.io/created-by": "e2e-tests",
		"test.n8n.io/timestamp":  time.Now().Format(time.RFC3339),
	}
	
	if c.UseRealCluster {
		annotations["test.n8n.io/cluster-type"] = "real"
	} else {
		annotations["test.n8n.io/cluster-type"] = "envtest"
	}
	
	return annotations
}

// ShouldSkipTest determines if a test should be skipped based on configuration
func (c *E2EConfig) ShouldSkipTest(testType string) bool {
	if !c.RunE2ETests {
		return true
	}
	
	// Skip monitoring tests in envtest mode (no real metrics)
	if testType == "monitoring" && !c.UseRealCluster {
		return true
	}
	
	// Skip AWS integration tests without real cluster
	if testType == "aws-integration" && !c.UseRealCluster {
		return true
	}
	
	return false
}

// GetRetryConfig returns retry configuration for operations
func (c *E2EConfig) GetRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:   c.MaxRetries,
		InitialDelay: 1 * time.Second,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
	}
}

// RetryConfig holds retry configuration
type RetryConfig struct {
	MaxRetries   int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
}

// TestResourceLimits defines resource limits for test instances
type TestResourceLimits struct {
	CPU    string
	Memory string
}

// GetDefaultResourceLimits returns default resource limits for test instances
func (c *E2EConfig) GetDefaultResourceLimits() map[string]TestResourceLimits {
	return map[string]TestResourceLimits{
		"small": {
			CPU:    "100m",
			Memory: "128Mi",
		},
		"medium": {
			CPU:    "200m",
			Memory: "256Mi",
		},
		"large": {
			CPU:    "500m",
			Memory: "512Mi",
		},
	}
}

// TestScenario defines a test scenario configuration
type TestScenario struct {
	Name        string
	Description string
	Timeout     time.Duration
	Retries     int
	Parallel    bool
	Tags        []string
}

// GetTestScenarios returns predefined test scenarios
func (c *E2EConfig) GetTestScenarios() []TestScenario {
	baseTimeout := c.TestTimeout / 4 // Divide total timeout among scenarios
	
	return []TestScenario{
		{
			Name:        "lifecycle",
			Description: "Complete N8nInstance lifecycle test",
			Timeout:     baseTimeout,
			Retries:     c.MaxRetries,
			Parallel:    false,
			Tags:        []string{"core", "lifecycle"},
		},
		{
			Name:        "custom-config",
			Description: "Custom configuration test",
			Timeout:     baseTimeout,
			Retries:     c.MaxRetries,
			Parallel:    true,
			Tags:        []string{"config", "scaling"},
		},
		{
			Name:        "error-handling",
			Description: "Error handling and recovery test",
			Timeout:     baseTimeout / 2,
			Retries:     1, // Don't retry error tests
			Parallel:    true,
			Tags:        []string{"error", "validation"},
		},
		{
			Name:        "monitoring",
			Description: "Monitoring and observability test",
			Timeout:     baseTimeout,
			Retries:     c.MaxRetries,
			Parallel:    false, // Monitoring tests may conflict
			Tags:        []string{"monitoring", "metrics"},
		},
	}
}

// IsVerbose returns whether verbose logging is enabled
func (c *E2EConfig) IsVerbose() bool {
	return c.VerboseLogging
}

// ShouldKeepResources returns whether to keep resources after tests
func (c *E2EConfig) ShouldKeepResources() bool {
	return c.KeepResources
}

// GetCleanupGracePeriod returns the grace period for resource cleanup
func (c *E2EConfig) GetCleanupGracePeriod() time.Duration {
	return 30 * time.Second
}

// GetWaitTimeout returns timeout for waiting operations
func (c *E2EConfig) GetWaitTimeout(operation string) time.Duration {
	switch operation {
	case "create":
		return 5 * time.Minute
	case "ready":
		return 10 * time.Minute
	case "update":
		return 5 * time.Minute
	case "delete":
		return c.CleanupTimeout
	case "scale":
		return 5 * time.Minute
	default:
		return 2 * time.Minute
	}
}