# E2E Test Makefile for n8n EKS Operator

# Variables
NAMESPACE ?= n8n-e2e-test
TIMEOUT ?= 30m
KUBECONFIG ?= ~/.kube/config
USE_REAL_CLUSTER ?= false
RUN_E2E_TESTS ?= true

# Test binary
TEST_BINARY = e2e.test

# Go test flags
GO_TEST_FLAGS = -v -timeout=$(TIMEOUT) -tags=e2e

# Environment variables for tests
TEST_ENV_VARS = \
	RUN_E2E_TESTS=$(RUN_E2E_TESTS) \
	USE_REAL_CLUSTER=$(USE_REAL_CLUSTER) \
	KUBECONFIG=$(KUBECONFIG) \
	TEST_NAMESPACE=$(NAMESPACE)

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: build
build: ## Build E2E test binary
	@echo "Building E2E test binary..."
	go test -c $(GO_TEST_FLAGS) -o $(TEST_BINARY) .

.PHONY: clean
clean: ## Clean test artifacts
	@echo "Cleaning E2E test artifacts..."
	rm -f $(TEST_BINARY)
	rm -f *.log
	rm -f coverage.out

##@ Testing

.PHONY: test
test: ## Run E2E tests with envtest
	@echo "Running E2E tests with envtest..."
	$(TEST_ENV_VARS) USE_REAL_CLUSTER=false go test $(GO_TEST_FLAGS) ./...

.PHONY: test-real
test-real: ## Run E2E tests against real cluster
	@echo "Running E2E tests against real Kubernetes cluster..."
	@echo "Make sure you have a valid kubeconfig and cluster access"
	$(TEST_ENV_VARS) USE_REAL_CLUSTER=true go test $(GO_TEST_FLAGS) ./...

.PHONY: test-lifecycle
test-lifecycle: ## Run only lifecycle tests
	@echo "Running N8nInstance lifecycle tests..."
	$(TEST_ENV_VARS) go test $(GO_TEST_FLAGS) -run TestE2ESuite/TestN8nInstanceLifecycle ./...

.PHONY: test-custom
test-custom: ## Run only custom configuration tests
	@echo "Running custom configuration tests..."
	$(TEST_ENV_VARS) go test $(GO_TEST_FLAGS) -run TestE2ESuite/TestN8nInstanceWithCustomConfig ./...

.PHONY: test-error
test-error: ## Run only error handling tests
	@echo "Running error handling tests..."
	$(TEST_ENV_VARS) go test $(GO_TEST_FLAGS) -run TestE2ESuite/TestN8nInstanceErrorHandling ./...

.PHONY: test-monitoring
test-monitoring: ## Run only monitoring tests
	@echo "Running monitoring tests..."
	$(TEST_ENV_VARS) go test $(GO_TEST_FLAGS) -run TestE2ESuite/TestN8nInstanceMonitoring ./...

##@ Cluster Management

.PHONY: create-namespace
create-namespace: ## Create test namespace
	@echo "Creating test namespace: $(NAMESPACE)"
	kubectl create namespace $(NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -
	kubectl label namespace $(NAMESPACE) test-suite=n8n-e2e --overwrite

.PHONY: delete-namespace
delete-namespace: ## Delete test namespace
	@echo "Deleting test namespace: $(NAMESPACE)"
	kubectl delete namespace $(NAMESPACE) --ignore-not-found=true

.PHONY: cleanup-resources
cleanup-resources: ## Clean up test resources
	@echo "Cleaning up E2E test resources..."
	kubectl delete n8ninstances -l test-suite=n8n-e2e --all-namespaces --ignore-not-found=true
	kubectl delete deployments -l test-suite=n8n-e2e --all-namespaces --ignore-not-found=true
	kubectl delete services -l test-suite=n8n-e2e --all-namespaces --ignore-not-found=true
	kubectl delete configmaps -l test-suite=n8n-e2e --all-namespaces --ignore-not-found=true
	kubectl delete secrets -l test-suite=n8n-e2e --all-namespaces --ignore-not-found=true
	kubectl delete hpa -l test-suite=n8n-e2e --all-namespaces --ignore-not-found=true

##@ Debugging

.PHONY: logs
logs: ## Show logs from test resources
	@echo "Showing logs from test resources in namespace: $(NAMESPACE)"
	kubectl logs -l test-suite=n8n-e2e -n $(NAMESPACE) --tail=100 || true

.PHONY: describe
describe: ## Describe test resources
	@echo "Describing test resources in namespace: $(NAMESPACE)"
	kubectl describe n8ninstances -l test-suite=n8n-e2e -n $(NAMESPACE) || true
	kubectl describe deployments -l test-suite=n8n-e2e -n $(NAMESPACE) || true
	kubectl describe services -l test-suite=n8n-e2e -n $(NAMESPACE) || true

.PHONY: get-resources
get-resources: ## Get all test resources
	@echo "Getting all test resources in namespace: $(NAMESPACE)"
	kubectl get all -l test-suite=n8n-e2e -n $(NAMESPACE) || true
	kubectl get n8ninstances -l test-suite=n8n-e2e -n $(NAMESPACE) || true
	kubectl get configmaps -l test-suite=n8n-e2e -n $(NAMESPACE) || true
	kubectl get secrets -l test-suite=n8n-e2e -n $(NAMESPACE) || true

##@ Coverage

.PHONY: test-coverage
test-coverage: ## Run E2E tests with coverage
	@echo "Running E2E tests with coverage..."
	$(TEST_ENV_VARS) go test $(GO_TEST_FLAGS) -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

##@ CI/CD

.PHONY: test-ci
test-ci: ## Run E2E tests in CI environment
	@echo "Running E2E tests in CI environment..."
	$(TEST_ENV_VARS) USE_REAL_CLUSTER=false go test $(GO_TEST_FLAGS) -json ./... > e2e-results.json

.PHONY: test-parallel
test-parallel: ## Run E2E tests in parallel
	@echo "Running E2E tests in parallel..."
	$(TEST_ENV_VARS) go test $(GO_TEST_FLAGS) -parallel=4 ./...

##@ Prerequisites

.PHONY: check-deps
check-deps: ## Check test dependencies
	@echo "Checking E2E test dependencies..."
	@command -v kubectl >/dev/null 2>&1 || { echo "kubectl is required but not installed. Aborting." >&2; exit 1; }
	@command -v go >/dev/null 2>&1 || { echo "go is required but not installed. Aborting." >&2; exit 1; }
	@if [ "$(USE_REAL_CLUSTER)" = "true" ]; then \
		kubectl cluster-info >/dev/null 2>&1 || { echo "Cannot connect to Kubernetes cluster. Check your kubeconfig." >&2; exit 1; }; \
		echo "✓ Kubernetes cluster connection verified"; \
	fi
	@echo "✓ All dependencies are available"

.PHONY: install-deps
install-deps: ## Install test dependencies
	@echo "Installing E2E test dependencies..."
	go mod download
	go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

##@ Quick Commands

.PHONY: quick-test
quick-test: check-deps test ## Quick test run with dependency check

.PHONY: full-test
full-test: check-deps create-namespace test cleanup-resources ## Full test cycle with setup and cleanup

.PHONY: debug-test
debug-test: create-namespace test get-resources logs ## Run tests and show debug information

# Default target
.DEFAULT_GOAL := help