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

package integration

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// TestConfig holds configuration for integration tests
type TestConfig struct {
	AWSConfig  aws.Config
	Region     string
	TestPrefix string
	Timeout    time.Duration

	// Test resource identifiers
	RDSClusterID         string
	ElastiCacheClusterID string
	Route53HostedZoneID  string
	DBSecretARN          string
	CacheSecretARN       string

	// Test flags
	RunIntegrationTests bool
	CleanupResources    bool
	SkipSlowTests       bool
}

// LoadTestConfig loads configuration from environment variables
func LoadTestConfig() (*TestConfig, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	testConfig := &TestConfig{
		AWSConfig:            cfg,
		Region:               getEnvOrDefault("AWS_REGION", "us-west-2"),
		TestPrefix:           fmt.Sprintf("n8n-test-%d", time.Now().Unix()),
		Timeout:              time.Minute * 30,
		RDSClusterID:         os.Getenv("TEST_RDS_CLUSTER_ID"),
		ElastiCacheClusterID: os.Getenv("TEST_ELASTICACHE_CLUSTER_ID"),
		Route53HostedZoneID:  os.Getenv("TEST_ROUTE53_HOSTED_ZONE_ID"),
		DBSecretARN:          os.Getenv("TEST_DB_SECRET_ARN"),
		CacheSecretARN:       os.Getenv("TEST_CACHE_SECRET_ARN"),
		RunIntegrationTests:  os.Getenv("RUN_INTEGRATION_TESTS") == "true",
		CleanupResources:     getEnvOrDefault("CLEANUP_TEST_RESOURCES", "true") == "true",
		SkipSlowTests:        os.Getenv("SKIP_SLOW_TESTS") == "true",
	}

	return testConfig, nil
}

// getEnvOrDefault returns environment variable value or default if not set
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// ValidateTestConfig validates that required test configuration is present
func (tc *TestConfig) ValidateTestConfig() error {
	if !tc.RunIntegrationTests {
		return fmt.Errorf("integration tests are disabled, set RUN_INTEGRATION_TESTS=true to enable")
	}

	if tc.Region == "" {
		return fmt.Errorf("AWS region is required")
	}

	return nil
}

// GetTestResourceName returns a test resource name with the test prefix
func (tc *TestConfig) GetTestResourceName(resourceType string) string {
	return fmt.Sprintf("%s-%s", tc.TestPrefix, resourceType)
}

// ShouldSkipTest determines if a test should be skipped based on configuration
func (tc *TestConfig) ShouldSkipTest(testType string) bool {
	switch testType {
	case "rds":
		return tc.RDSClusterID == ""
	case "elasticache":
		return tc.ElastiCacheClusterID == ""
	case "route53":
		return tc.Route53HostedZoneID == ""
	case "secrets":
		return tc.DBSecretARN == "" && tc.CacheSecretARN == ""
	case "slow":
		return tc.SkipSlowTests
	default:
		return false
	}
}
