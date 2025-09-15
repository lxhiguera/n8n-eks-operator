# Integration Tests Makefile

# Default values
AWS_REGION ?= us-west-2
TEST_TIMEOUT ?= 30m

# Test flags
INTEGRATION_FLAGS = -tags=integration -timeout=$(TEST_TIMEOUT)
VERBOSE_FLAGS = -v
RACE_FLAGS = -race

# Environment setup
.PHONY: setup-env
setup-env:
	@echo "Setting up integration test environment..."
	@echo "AWS_REGION: $(AWS_REGION)"
	@echo "RUN_INTEGRATION_TESTS: $(RUN_INTEGRATION_TESTS)"
	@echo "TEST_RDS_CLUSTER_ID: $(TEST_RDS_CLUSTER_ID)"
	@echo "TEST_ELASTICACHE_CLUSTER_ID: $(TEST_ELASTICACHE_CLUSTER_ID)"

# Run all integration tests
.PHONY: test-integration
test-integration:
	@echo "Running all integration tests..."
	RUN_INTEGRATION_TESTS=true go test $(INTEGRATION_FLAGS) $(VERBOSE_FLAGS) ./...

# Run integration tests with race detection
.PHONY: test-integration-race
test-integration-race:
	@echo "Running integration tests with race detection..."
	RUN_INTEGRATION_TESTS=true go test $(INTEGRATION_FLAGS) $(VERBOSE_FLAGS) $(RACE_FLAGS) ./...

# Run specific test suites
.PHONY: test-rds
test-rds:
	@echo "Running RDS integration tests..."
	RUN_INTEGRATION_TESTS=true go test $(INTEGRATION_FLAGS) $(VERBOSE_FLAGS) -run TestRDS ./...

.PHONY: test-elasticache
test-elasticache:
	@echo "Running ElastiCache integration tests..."
	RUN_INTEGRATION_TESTS=true go test $(INTEGRATION_FLAGS) $(VERBOSE_FLAGS) -run TestElastiCache ./...

.PHONY: test-s3
test-s3:
	@echo "Running S3 integration tests..."
	RUN_INTEGRATION_TESTS=true go test $(INTEGRATION_FLAGS) $(VERBOSE_FLAGS) -run TestS3 ./...

.PHONY: test-secrets
test-secrets:
	@echo "Running Secrets Manager integration tests..."
	RUN_INTEGRATION_TESTS=true go test $(INTEGRATION_FLAGS) $(VERBOSE_FLAGS) -run TestSecrets ./...

# Run fast tests only (skip slow connectivity tests)
.PHONY: test-fast
test-fast:
	@echo "Running fast integration tests..."
	RUN_INTEGRATION_TESTS=true SKIP_SLOW_TESTS=true go test $(INTEGRATION_FLAGS) $(VERBOSE_FLAGS) ./...

# Validate test environment
.PHONY: validate-env
validate-env:
	@echo "Validating test environment..."
	@if [ -z "$(RUN_INTEGRATION_TESTS)" ]; then \
		echo "❌ RUN_INTEGRATION_TESTS not set. Set to 'true' to enable integration tests."; \
		exit 1; \
	fi
	@if [ "$(RUN_INTEGRATION_TESTS)" != "true" ]; then \
		echo "❌ RUN_INTEGRATION_TESTS must be set to 'true'"; \
		exit 1; \
	fi
	@echo "✅ RUN_INTEGRATION_TESTS is set to true"
	@aws sts get-caller-identity > /dev/null 2>&1 || (echo "❌ AWS credentials not configured" && exit 1)
	@echo "✅ AWS credentials are configured"
	@echo "✅ Environment validation passed"

# Check AWS resources
.PHONY: check-resources
check-resources:
	@echo "Checking AWS test resources..."
	@if [ -n "$(TEST_RDS_CLUSTER_ID)" ]; then \
		echo "Checking RDS cluster: $(TEST_RDS_CLUSTER_ID)"; \
		aws rds describe-db-clusters --db-cluster-identifier $(TEST_RDS_CLUSTER_ID) --region $(AWS_REGION) > /dev/null 2>&1 && \
		echo "✅ RDS cluster $(TEST_RDS_CLUSTER_ID) found" || \
		echo "❌ RDS cluster $(TEST_RDS_CLUSTER_ID) not found"; \
	fi
	@if [ -n "$(TEST_ELASTICACHE_CLUSTER_ID)" ]; then \
		echo "Checking ElastiCache cluster: $(TEST_ELASTICACHE_CLUSTER_ID)"; \
		aws elasticache describe-cache-clusters --cache-cluster-id $(TEST_ELASTICACHE_CLUSTER_ID) --region $(AWS_REGION) > /dev/null 2>&1 && \
		echo "✅ ElastiCache cluster $(TEST_ELASTICACHE_CLUSTER_ID) found" || \
		echo "❌ ElastiCache cluster $(TEST_ELASTICACHE_CLUSTER_ID) not found"; \
	fi
	@if [ -n "$(TEST_DB_SECRET_ARN)" ]; then \
		echo "Checking DB secret: $(TEST_DB_SECRET_ARN)"; \
		aws secretsmanager get-secret-value --secret-id $(TEST_DB_SECRET_ARN) --region $(AWS_REGION) > /dev/null 2>&1 && \
		echo "✅ DB secret $(TEST_DB_SECRET_ARN) found" || \
		echo "❌ DB secret $(TEST_DB_SECRET_ARN) not found"; \
	fi

# Clean up test resources (use with caution)
.PHONY: cleanup-test-resources
cleanup-test-resources:
	@echo "⚠️  This will delete test resources. Are you sure? (y/N)"
	@read -r response; \
	if [ "$$response" = "y" ] || [ "$$response" = "Y" ]; then \
		echo "Cleaning up test resources..."; \
		if [ -n "$(TEST_S3_BUCKET_PREFIX)" ]; then \
			echo "Deleting S3 buckets with prefix: $(TEST_S3_BUCKET_PREFIX)"; \
			aws s3api list-buckets --query "Buckets[?starts_with(Name, '$(TEST_S3_BUCKET_PREFIX)')].Name" --output text | \
			xargs -I {} aws s3 rb s3://{} --force; \
		fi; \
		echo "Cleanup completed"; \
	else \
		echo "Cleanup cancelled"; \
	fi

# Generate test report
.PHONY: test-report
test-report:
	@echo "Generating integration test report..."
	RUN_INTEGRATION_TESTS=true go test $(INTEGRATION_FLAGS) -json ./... > test-results.json
	@echo "Test results saved to test-results.json"

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running integration tests with coverage..."
	RUN_INTEGRATION_TESTS=true go test $(INTEGRATION_FLAGS) -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report saved to coverage.html"

# Benchmark tests
.PHONY: test-bench
test-bench:
	@echo "Running integration benchmarks..."
	RUN_INTEGRATION_TESTS=true go test $(INTEGRATION_FLAGS) -bench=. -benchmem ./...

# Help
.PHONY: help
help:
	@echo "Integration Tests Makefile"
	@echo ""
	@echo "Environment Variables:"
	@echo "  AWS_REGION                    - AWS region for tests (default: us-west-2)"
	@echo "  RUN_INTEGRATION_TESTS         - Set to 'true' to enable integration tests"
	@echo "  TEST_RDS_CLUSTER_ID          - RDS cluster ID for testing"
	@echo "  TEST_ELASTICACHE_CLUSTER_ID  - ElastiCache cluster ID for testing"
	@echo "  TEST_DB_SECRET_ARN           - Database secret ARN for testing"
	@echo "  TEST_CACHE_SECRET_ARN        - Cache secret ARN for testing"
	@echo "  SKIP_SLOW_TESTS              - Set to 'true' to skip slow tests"
	@echo ""
	@echo "Targets:"
	@echo "  setup-env                    - Display environment configuration"
	@echo "  validate-env                 - Validate test environment setup"
	@echo "  check-resources              - Check if AWS test resources exist"
	@echo "  test-integration             - Run all integration tests"
	@echo "  test-integration-race        - Run integration tests with race detection"
	@echo "  test-rds                     - Run RDS integration tests only"
	@echo "  test-elasticache             - Run ElastiCache integration tests only"
	@echo "  test-s3                      - Run S3 integration tests only"
	@echo "  test-secrets                 - Run Secrets Manager integration tests only"
	@echo "  test-fast                    - Run fast integration tests (skip slow tests)"
	@echo "  test-report                  - Generate JSON test report"
	@echo "  test-coverage                - Run tests with coverage report"
	@echo "  test-bench                   - Run integration benchmarks"
	@echo "  cleanup-test-resources       - Clean up test resources (use with caution)"
	@echo "  help                         - Show this help message"
	@echo ""
	@echo "Example usage:"
	@echo "  make validate-env"
	@echo "  make check-resources"
	@echo "  make test-integration"
	@echo "  make test-fast"

.DEFAULT_GOAL := help