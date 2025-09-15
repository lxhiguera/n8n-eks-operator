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
	"fmt"
	"os"
	"strconv"
	"time"
)

// NewPerformanceConfig creates a new performance test configuration
func NewPerformanceConfig() *PerformanceConfig {
	config := &PerformanceConfig{
		// Default values
		TestTimeout:           30 * time.Minute,
		ConcurrentInstances:   10,
		ReconcileIterations:   50,
		MaxReconcileTime:      30 * time.Second,
		MaxMemoryUsage:        512, // MB
		MaxCPUUsage:           80.0, // percentage
		LoadTestDuration:      5 * time.Minute,
		LoadTestConcurrency:   5,
		LoadTestRampUpTime:    30 * time.Second,
		BenchmarkIterations:   100,
		BenchmarkWarmupTime:   10 * time.Second,
	}
	
	// Load from environment variables
	config.loadFromEnv()
	
	return config
}

// loadFromEnv loads configuration from environment variables
func (c *PerformanceConfig) loadFromEnv() {
	if val := os.Getenv("PERF_TEST_TIMEOUT"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			c.TestTimeout = duration
		}
	}
	
	if val := os.Getenv("PERF_CONCURRENT_INSTANCES"); val != "" {
		if num, err := strconv.Atoi(val); err == nil && num > 0 {
			c.ConcurrentInstances = num
		}
	}
	
	if val := os.Getenv("PERF_RECONCILE_ITERATIONS"); val != "" {
		if num, err := strconv.Atoi(val); err == nil && num > 0 {
			c.ReconcileIterations = num
		}
	}
	
	if val := os.Getenv("PERF_MAX_RECONCILE_TIME"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			c.MaxReconcileTime = duration
		}
	}
	
	if val := os.Getenv("PERF_MAX_MEMORY_MB"); val != "" {
		if num, err := strconv.ParseInt(val, 10, 64); err == nil && num > 0 {
			c.MaxMemoryUsage = num
		}
	}
	
	if val := os.Getenv("PERF_MAX_CPU_PERCENT"); val != "" {
		if num, err := strconv.ParseFloat(val, 64); err == nil && num > 0 {
			c.MaxCPUUsage = num
		}
	}
	
	if val := os.Getenv("PERF_LOAD_TEST_DURATION"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			c.LoadTestDuration = duration
		}
	}
	
	if val := os.Getenv("PERF_LOAD_TEST_CONCURRENCY"); val != "" {
		if num, err := strconv.Atoi(val); err == nil && num > 0 {
			c.LoadTestConcurrency = num
		}
	}
	
	if val := os.Getenv("PERF_LOAD_TEST_RAMPUP"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			c.LoadTestRampUpTime = duration
		}
	}
	
	if val := os.Getenv("PERF_BENCHMARK_ITERATIONS"); val != "" {
		if num, err := strconv.Atoi(val); err == nil && num > 0 {
			c.BenchmarkIterations = num
		}
	}
	
	if val := os.Getenv("PERF_BENCHMARK_WARMUP"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			c.BenchmarkWarmupTime = duration
		}
	}
}

// GetTestScenarios returns predefined performance test scenarios
func (c *PerformanceConfig) GetTestScenarios() []PerformanceScenario {
	return []PerformanceScenario{
		{
			Name:        "light-load",
			Description: "Light load scenario for basic performance validation",
			Config: PerformanceConfig{
				ConcurrentInstances: 5,
				ReconcileIterations: 20,
				LoadTestDuration:    2 * time.Minute,
				LoadTestConcurrency: 2,
			},
		},
		{
			Name:        "medium-load",
			Description: "Medium load scenario for typical usage patterns",
			Config: PerformanceConfig{
				ConcurrentInstances: 15,
				ReconcileIterations: 50,
				LoadTestDuration:    5 * time.Minute,
				LoadTestConcurrency: 5,
			},
		},
		{
			Name:        "heavy-load",
			Description: "Heavy load scenario for stress testing",
			Config: PerformanceConfig{
				ConcurrentInstances: 50,
				ReconcileIterations: 100,
				LoadTestDuration:    10 * time.Minute,
				LoadTestConcurrency: 10,
			},
		},
		{
			Name:        "burst-load",
			Description: "Burst load scenario for peak traffic simulation",
			Config: PerformanceConfig{
				ConcurrentInstances: 100,
				ReconcileIterations: 200,
				LoadTestDuration:    3 * time.Minute,
				LoadTestConcurrency: 20,
			},
		},
	}
}

// PerformanceScenario defines a performance test scenario
type PerformanceScenario struct {
	Name        string
	Description string
	Config      PerformanceConfig
}

// ResourceLimits defines resource limits for performance tests
type ResourceLimits struct {
	MaxCPUCores    float64
	MaxMemoryMB    int64
	MaxDiskIOPS    int64
	MaxNetworkMbps int64
}

// GetResourceLimits returns resource limits for different test scenarios
func (c *PerformanceConfig) GetResourceLimits() map[string]ResourceLimits {
	return map[string]ResourceLimits{
		"light": {
			MaxCPUCores:    2.0,
			MaxMemoryMB:    1024,
			MaxDiskIOPS:    1000,
			MaxNetworkMbps: 100,
		},
		"medium": {
			MaxCPUCores:    4.0,
			MaxMemoryMB:    2048,
			MaxDiskIOPS:    2000,
			MaxNetworkMbps: 500,
		},
		"heavy": {
			MaxCPUCores:    8.0,
			MaxMemoryMB:    4096,
			MaxDiskIOPS:    5000,
			MaxNetworkMbps: 1000,
		},
	}
}

// PerformanceThresholds defines performance thresholds
type PerformanceThresholds struct {
	MaxReconcileTimeP50 time.Duration
	MaxReconcileTimeP95 time.Duration
	MaxReconcileTimeP99 time.Duration
	MinThroughputRPS    float64
	MaxErrorRate        float64
	MaxMemoryUsageMB    int64
	MaxCPUUsagePercent  float64
}

// GetPerformanceThresholds returns performance thresholds for different scenarios
func (c *PerformanceConfig) GetPerformanceThresholds() map[string]PerformanceThresholds {
	return map[string]PerformanceThresholds{
		"light": {
			MaxReconcileTimeP50: 5 * time.Second,
			MaxReconcileTimeP95: 15 * time.Second,
			MaxReconcileTimeP99: 30 * time.Second,
			MinThroughputRPS:    2.0,
			MaxErrorRate:        0.01, // 1%
			MaxMemoryUsageMB:    512,
			MaxCPUUsagePercent:  50.0,
		},
		"medium": {
			MaxReconcileTimeP50: 10 * time.Second,
			MaxReconcileTimeP95: 30 * time.Second,
			MaxReconcileTimeP99: 60 * time.Second,
			MinThroughputRPS:    1.5,
			MaxErrorRate:        0.02, // 2%
			MaxMemoryUsageMB:    1024,
			MaxCPUUsagePercent:  70.0,
		},
		"heavy": {
			MaxReconcileTimeP50: 20 * time.Second,
			MaxReconcileTimeP95: 60 * time.Second,
			MaxReconcileTimeP99: 120 * time.Second,
			MinThroughputRPS:    1.0,
			MaxErrorRate:        0.05, // 5%
			MaxMemoryUsageMB:    2048,
			MaxCPUUsagePercent:  85.0,
		},
	}
}

// TestProfile defines a complete test profile
type TestProfile struct {
	Name        string
	Description string
	Scenario    PerformanceScenario
	Limits      ResourceLimits
	Thresholds  PerformanceThresholds
	Duration    time.Duration
}

// GetTestProfiles returns predefined test profiles
func (c *PerformanceConfig) GetTestProfiles() []TestProfile {
	scenarios := c.GetTestScenarios()
	limits := c.GetResourceLimits()
	thresholds := c.GetPerformanceThresholds()
	
	return []TestProfile{
		{
			Name:        "quick-validation",
			Description: "Quick performance validation for CI/CD",
			Scenario:    scenarios[0], // light-load
			Limits:      limits["light"],
			Thresholds:  thresholds["light"],
			Duration:    2 * time.Minute,
		},
		{
			Name:        "standard-performance",
			Description: "Standard performance test for regular validation",
			Scenario:    scenarios[1], // medium-load
			Limits:      limits["medium"],
			Thresholds:  thresholds["medium"],
			Duration:    10 * time.Minute,
		},
		{
			Name:        "stress-test",
			Description: "Stress test for maximum load validation",
			Scenario:    scenarios[2], // heavy-load
			Limits:      limits["heavy"],
			Thresholds:  thresholds["heavy"],
			Duration:    30 * time.Minute,
		},
		{
			Name:        "burst-capacity",
			Description: "Burst capacity test for peak load handling",
			Scenario:    scenarios[3], // burst-load
			Limits:      limits["heavy"],
			Thresholds:  thresholds["heavy"],
			Duration:    5 * time.Minute,
		},
	}
}

// Validate validates the performance configuration
func (c *PerformanceConfig) Validate() error {
	if c.TestTimeout <= 0 {
		return fmt.Errorf("test timeout must be positive")
	}
	
	if c.ConcurrentInstances <= 0 {
		return fmt.Errorf("concurrent instances must be positive")
	}
	
	if c.ReconcileIterations <= 0 {
		return fmt.Errorf("reconcile iterations must be positive")
	}
	
	if c.MaxReconcileTime <= 0 {
		return fmt.Errorf("max reconcile time must be positive")
	}
	
	if c.LoadTestDuration <= 0 {
		return fmt.Errorf("load test duration must be positive")
	}
	
	if c.LoadTestConcurrency <= 0 {
		return fmt.Errorf("load test concurrency must be positive")
	}
	
	if c.BenchmarkIterations <= 0 {
		return fmt.Errorf("benchmark iterations must be positive")
	}
	
	return nil
}

// GetRecommendedSettings returns recommended settings based on cluster size
func (c *PerformanceConfig) GetRecommendedSettings(clusterSize string) *PerformanceConfig {
	switch clusterSize {
	case "small":
		return &PerformanceConfig{
			TestTimeout:         15 * time.Minute,
			ConcurrentInstances: 5,
			ReconcileIterations: 20,
			MaxReconcileTime:    20 * time.Second,
			LoadTestDuration:    2 * time.Minute,
			LoadTestConcurrency: 2,
			BenchmarkIterations: 50,
		}
	case "medium":
		return &PerformanceConfig{
			TestTimeout:         30 * time.Minute,
			ConcurrentInstances: 15,
			ReconcileIterations: 50,
			MaxReconcileTime:    30 * time.Second,
			LoadTestDuration:    5 * time.Minute,
			LoadTestConcurrency: 5,
			BenchmarkIterations: 100,
		}
	case "large":
		return &PerformanceConfig{
			TestTimeout:         60 * time.Minute,
			ConcurrentInstances: 50,
			ReconcileIterations: 100,
			MaxReconcileTime:    60 * time.Second,
			LoadTestDuration:    10 * time.Minute,
			LoadTestConcurrency: 10,
			BenchmarkIterations: 200,
		}
	default:
		return c // Return current config as default
	}
}