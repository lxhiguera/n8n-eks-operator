# Security Test Makefile for n8n EKS Operator

# Variables
TIMEOUT ?= 30m
SECURITY_PROFILE ?= standard
COMPLIANCE_STANDARDS ?= SOC2,GDPR,CIS

# Test binary
TEST_BINARY = security.test

# Go test flags
GO_TEST_FLAGS = -v -timeout=$(TIMEOUT) -tags=security

# Environment variables for tests
SEC_ENV_VARS = \
	SEC_TEST_TIMEOUT=$(TIMEOUT) \
	SEC_SECURITY_PROFILE=$(SECURITY_PROFILE) \
	SEC_COMPLIANCE_STANDARDS=$(COMPLIANCE_STANDARDS)

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: build
build: ## Build security test binary
	@echo "Building security test binary..."
	go test -c $(GO_TEST_FLAGS) -o $(TEST_BINARY) .

.PHONY: clean
clean: ## Clean test artifacts
	@echo "Cleaning security test artifacts..."
	rm -f $(TEST_BINARY)
	rm -f *.log *.json *.html *.xml
	rm -f security-report.* compliance-report.*
	rm -f vulnerability-scan-results.*

##@ Security Testing

.PHONY: test
test: ## Run all security tests
	@echo "Running security tests..."
	$(SEC_ENV_VARS) go test $(GO_TEST_FLAGS) ./...

.PHONY: test-secrets
test-secrets: ## Run secret management tests
	@echo "Running secret management tests..."
	$(SEC_ENV_VARS) go test $(GO_TEST_FLAGS) -run TestSecretEncryption ./...

.PHONY: test-network
test-network: ## Run network security tests
	@echo "Running network security tests..."
	$(SEC_ENV_VARS) go test $(GO_TEST_FLAGS) -run TestNetworkPolicies ./...

.PHONY: test-rbac
test-rbac: ## Run RBAC security tests
	@echo "Running RBAC security tests..."
	$(SEC_ENV_VARS) go test $(GO_TEST_FLAGS) -run TestRBACConfiguration ./...

.PHONY: test-pod-security
test-pod-security: ## Run Pod Security Standards tests
	@echo "Running Pod Security Standards tests..."
	$(SEC_ENV_VARS) go test $(GO_TEST_FLAGS) -run TestPodSecurityStandards ./...

.PHONY: test-vulnerabilities
test-vulnerabilities: ## Run vulnerability scanning tests
	@echo "Running vulnerability scanning tests..."
	$(SEC_ENV_VARS) go test $(GO_TEST_FLAGS) -run TestVulnerabilityScanning ./...

.PHONY: test-compliance
test-compliance: ## Run compliance tests
	@echo "Running compliance tests..."
	$(SEC_ENV_VARS) go test $(GO_TEST_FLAGS) -run TestComplianceChecks ./...

.PHONY: test-auditing
test-auditing: ## Run security auditing tests
	@echo "Running security auditing tests..."
	$(SEC_ENV_VARS) go test $(GO_TEST_FLAGS) -run TestSecurityAuditing ./...

##@ Security Profiles

.PHONY: test-basic
test-basic: ## Run basic security profile tests
	@echo "Running basic security profile tests..."
	SEC_SECURITY_PROFILE=basic \
	SEC_MAX_CRITICAL_VULNS=0 \
	SEC_MAX_HIGH_VULNS=10 \
	SEC_REQUIRE_NETWORK_POLICIES=false \
	SEC_REQUIRE_AUDIT_LOGGING=false \
	go test $(GO_TEST_FLAGS) ./...

.PHONY: test-standard
test-standard: ## Run standard security profile tests
	@echo "Running standard security profile tests..."
	SEC_SECURITY_PROFILE=standard \
	SEC_MAX_CRITICAL_VULNS=0 \
	SEC_MAX_HIGH_VULNS=5 \
	SEC_REQUIRE_NETWORK_POLICIES=true \
	SEC_REQUIRE_AUDIT_LOGGING=true \
	SEC_SOC2_REQUIRED=true \
	SEC_GDPR_REQUIRED=true \
	SEC_CIS_REQUIRED=true \
	go test $(GO_TEST_FLAGS) ./...

.PHONY: test-strict
test-strict: ## Run strict security profile tests
	@echo "Running strict security profile tests..."
	SEC_SECURITY_PROFILE=strict \
	SEC_MAX_CRITICAL_VULNS=0 \
	SEC_MAX_HIGH_VULNS=0 \
	SEC_REQUIRE_NETWORK_POLICIES=true \
	SEC_REQUIRE_DEFAULT_DENY_ALL=true \
	SEC_REQUIRE_AUDIT_LOGGING=true \
	SEC_REQUIRE_LOG_INTEGRITY=true \
	SEC_REQUIRE_SECRET_ENCRYPTION=true \
	SEC_REQUIRE_SECRET_ROTATION=true \
	SEC_REQUIRE_SIGNED_IMAGES=true \
	go test $(GO_TEST_FLAGS) ./...

.PHONY: test-compliance-full
test-compliance-full: ## Run full compliance profile tests
	@echo "Running full compliance profile tests..."
	SEC_SECURITY_PROFILE=compliance \
	SEC_MAX_CRITICAL_VULNS=0 \
	SEC_MAX_HIGH_VULNS=0 \
	SEC_SOC2_REQUIRED=true \
	SEC_GDPR_REQUIRED=true \
	SEC_HIPAA_REQUIRED=true \
	SEC_PCIDSS_REQUIRED=true \
	SEC_CIS_REQUIRED=true \
	SEC_REQUIRE_ENCRYPTION_AT_REST=true \
	SEC_REQUIRE_ENCRYPTION_IN_TRANSIT=true \
	go test $(GO_TEST_FLAGS) ./...

##@ Compliance Testing

.PHONY: test-soc2
test-soc2: ## Run SOC 2 compliance tests
	@echo "Running SOC 2 compliance tests..."
	SEC_SOC2_REQUIRED=true \
	go test $(GO_TEST_FLAGS) -run TestSOC2Compliance ./...

.PHONY: test-gdpr
test-gdpr: ## Run GDPR compliance tests
	@echo "Running GDPR compliance tests..."
	SEC_GDPR_REQUIRED=true \
	go test $(GO_TEST_FLAGS) -run TestGDPRCompliance ./...

.PHONY: test-hipaa
test-hipaa: ## Run HIPAA compliance tests
	@echo "Running HIPAA compliance tests..."
	SEC_HIPAA_REQUIRED=true \
	go test $(GO_TEST_FLAGS) -run TestHIPAACompliance ./...

.PHONY: test-pcidss
test-pcidss: ## Run PCI DSS compliance tests
	@echo "Running PCI DSS compliance tests..."
	SEC_PCIDSS_REQUIRED=true \
	go test $(GO_TEST_FLAGS) -run TestPCIDSSCompliance ./...

.PHONY: test-cis
test-cis: ## Run CIS Kubernetes Benchmark tests
	@echo "Running CIS Kubernetes Benchmark tests..."
	SEC_CIS_REQUIRED=true \
	go test $(GO_TEST_FLAGS) -run TestCISKubernetesBenchmark ./...

##@ Vulnerability Scanning

.PHONY: scan-images
scan-images: ## Scan container images for vulnerabilities
	@echo "Scanning container images..."
	@if command -v trivy >/dev/null 2>&1; then \
		echo "Using Trivy for image scanning..."; \
		trivy image --severity HIGH,CRITICAL n8nio/n8n:latest || true; \
	elif command -v docker >/dev/null 2>&1; then \
		echo "Docker available, running basic image checks..."; \
		docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
			aquasec/trivy:latest image --severity HIGH,CRITICAL n8nio/n8n:latest || true; \
	else \
		echo "No vulnerability scanner available. Install Trivy for image scanning."; \
	fi

.PHONY: scan-dependencies
scan-dependencies: ## Scan Go dependencies for vulnerabilities
	@echo "Scanning Go dependencies..."
	@if command -v govulncheck >/dev/null 2>&1; then \
		echo "Using govulncheck for dependency scanning..."; \
		govulncheck ./... || true; \
	else \
		echo "govulncheck not available. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

.PHONY: scan-all
scan-all: scan-images scan-dependencies ## Run all vulnerability scans

##@ Security Analysis

.PHONY: analyze-rbac
analyze-rbac: ## Analyze RBAC configurations
	@echo "Analyzing RBAC configurations..."
	@if command -v kubectl >/dev/null 2>&1; then \
		echo "Checking for overprivileged roles..."; \
		kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name' || true; \
		kubectl get rolebindings --all-namespaces -o json | jq -r '.items[] | select(.roleRef.name=="admin") | "\(.metadata.namespace)/\(.metadata.name)"' || true; \
	else \
		echo "kubectl not available. Cannot analyze RBAC configurations."; \
	fi

.PHONY: analyze-network-policies
analyze-network-policies: ## Analyze network policies
	@echo "Analyzing network policies..."
	@if command -v kubectl >/dev/null 2>&1; then \
		echo "Checking network policies..."; \
		kubectl get networkpolicies --all-namespaces || true; \
		echo "Checking for namespaces without network policies..."; \
		kubectl get namespaces -o json | jq -r '.items[] | select(.metadata.name != "kube-system" and .metadata.name != "kube-public") | .metadata.name' | while read ns; do \
			if ! kubectl get networkpolicies -n "$$ns" --no-headers 2>/dev/null | grep -q .; then \
				echo "Namespace $$ns has no network policies"; \
			fi; \
		done || true; \
	else \
		echo "kubectl not available. Cannot analyze network policies."; \
	fi

.PHONY: analyze-pod-security
analyze-pod-security: ## Analyze pod security configurations
	@echo "Analyzing pod security configurations..."
	@if command -v kubectl >/dev/null 2>&1; then \
		echo "Checking for privileged pods..."; \
		kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[]?.securityContext?.privileged == true) | "\(.metadata.namespace)/\(.metadata.name)"' || true; \
		echo "Checking for pods running as root..."; \
		kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.securityContext?.runAsUser == 0 or .spec.containers[]?.securityContext?.runAsUser == 0) | "\(.metadata.namespace)/\(.metadata.name)"' || true; \
	else \
		echo "kubectl not available. Cannot analyze pod security."; \
	fi

.PHONY: analyze-secrets
analyze-secrets: ## Analyze secret configurations
	@echo "Analyzing secret configurations..."
	@if command -v kubectl >/dev/null 2>&1; then \
		echo "Checking for secrets in default namespace..."; \
		kubectl get secrets -n default --no-headers | wc -l || true; \
		echo "Checking for secrets with generic names..."; \
		kubectl get secrets --all-namespaces -o json | jq -r '.items[] | select(.metadata.name | test("secret|password|key")) | "\(.metadata.namespace)/\(.metadata.name)"' || true; \
	else \
		echo "kubectl not available. Cannot analyze secrets."; \
	fi

##@ Reporting

.PHONY: report
report: ## Generate security report
	@echo "Generating security report..."
	@echo "# Security Test Report" > security-report.txt
	@echo "Generated on: $$(date)" >> security-report.txt
	@echo "" >> security-report.txt
	@echo "## Configuration" >> security-report.txt
	@echo "- Security Profile: $(SECURITY_PROFILE)" >> security-report.txt
	@echo "- Compliance Standards: $(COMPLIANCE_STANDARDS)" >> security-report.txt
	@echo "- Timeout: $(TIMEOUT)" >> security-report.txt
	@echo "" >> security-report.txt
	@echo "Security report generated: security-report.txt"

.PHONY: report-html
report-html: ## Generate HTML security report
	@echo "Generating HTML security report..."
	@echo "<!DOCTYPE html><html><head><title>Security Report</title></head><body>" > security-report.html
	@echo "<h1>n8n EKS Operator Security Report</h1>" >> security-report.html
	@echo "<p>Generated on: $$(date)</p>" >> security-report.html
	@echo "<h2>Configuration</h2><ul>" >> security-report.html
	@echo "<li>Security Profile: $(SECURITY_PROFILE)</li>" >> security-report.html
	@echo "<li>Compliance Standards: $(COMPLIANCE_STANDARDS)</li>" >> security-report.html
	@echo "<li>Timeout: $(TIMEOUT)</li>" >> security-report.html
	@echo "</ul>" >> security-report.html
	@echo "</body></html>" >> security-report.html
	@echo "HTML security report generated: security-report.html"

.PHONY: report-compliance
report-compliance: ## Generate compliance report
	@echo "Generating compliance report..."
	@echo "# Compliance Report" > compliance-report.txt
	@echo "Generated on: $$(date)" >> compliance-report.txt
	@echo "" >> compliance-report.txt
	@echo "## Standards Tested" >> compliance-report.txt
	@echo "$(COMPLIANCE_STANDARDS)" | tr ',' '\n' | while read standard; do \
		echo "- $$standard" >> compliance-report.txt; \
	done
	@echo "" >> compliance-report.txt
	@echo "Compliance report generated: compliance-report.txt"

.PHONY: report-vulnerabilities
report-vulnerabilities: ## Generate vulnerability report
	@echo "Generating vulnerability report..."
	@echo "# Vulnerability Scan Report" > vulnerability-report.txt
	@echo "Generated on: $$(date)" >> vulnerability-report.txt
	@echo "" >> vulnerability-report.txt
	@echo "## Image Scans" >> vulnerability-report.txt
	@echo "See scan-images target output" >> vulnerability-report.txt
	@echo "" >> vulnerability-report.txt
	@echo "## Dependency Scans" >> vulnerability-report.txt
	@echo "See scan-dependencies target output" >> vulnerability-report.txt
	@echo "" >> vulnerability-report.txt
	@echo "Vulnerability report generated: vulnerability-report.txt"

##@ CI/CD

.PHONY: test-ci
test-ci: ## Run security tests for CI/CD
	@echo "Running security tests for CI/CD..."
	SEC_TEST_TIMEOUT=15m \
	SEC_SECURITY_PROFILE=standard \
	SEC_MAX_CRITICAL_VULNS=0 \
	SEC_MAX_HIGH_VULNS=5 \
	go test $(GO_TEST_FLAGS) -json ./... > security-results.json

.PHONY: scan-ci
scan-ci: ## Run vulnerability scans for CI/CD
	@echo "Running vulnerability scans for CI/CD..."
	@$(MAKE) scan-all > vulnerability-scan-results.txt 2>&1 || true

.PHONY: compliance-ci
compliance-ci: ## Run compliance tests for CI/CD
	@echo "Running compliance tests for CI/CD..."
	SEC_SOC2_REQUIRED=true \
	SEC_GDPR_REQUIRED=true \
	SEC_CIS_REQUIRED=true \
	go test $(GO_TEST_FLAGS) -run "TestSOC2Compliance|TestGDPRCompliance|TestCISKubernetesBenchmark" ./... > compliance-results.txt 2>&1

##@ Prerequisites

.PHONY: check-deps
check-deps: ## Check security test dependencies
	@echo "Checking security test dependencies..."
	@command -v go >/dev/null 2>&1 || { echo "go is required but not installed. Aborting." >&2; exit 1; }
	@echo "✓ Go is available"
	@if command -v kubectl >/dev/null 2>&1; then \
		echo "✓ kubectl is available"; \
	else \
		echo "⚠ kubectl not available (optional for some tests)"; \
	fi
	@if command -v trivy >/dev/null 2>&1; then \
		echo "✓ Trivy is available"; \
	else \
		echo "⚠ Trivy not available (install for vulnerability scanning)"; \
	fi
	@if command -v govulncheck >/dev/null 2>&1; then \
		echo "✓ govulncheck is available"; \
	else \
		echo "⚠ govulncheck not available (install for dependency scanning)"; \
	fi
	@echo "✓ Dependency check completed"

.PHONY: install-deps
install-deps: ## Install security test dependencies
	@echo "Installing security test dependencies..."
	go mod download
	@echo "Installing govulncheck..."
	go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "Installing security analysis tools..."
	@if command -v curl >/dev/null 2>&1; then \
		echo "Trivy installation instructions: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"; \
	fi

##@ Security Benchmarks

.PHONY: benchmark-encryption
benchmark-encryption: ## Benchmark encryption operations
	@echo "Benchmarking encryption operations..."
	go test -bench=BenchmarkEncryption -benchmem -tags=security ./... || echo "No encryption benchmarks found"

.PHONY: benchmark-rbac
benchmark-rbac: ## Benchmark RBAC operations
	@echo "Benchmarking RBAC operations..."
	go test -bench=BenchmarkRBAC -benchmem -tags=security ./... || echo "No RBAC benchmarks found"

.PHONY: benchmark-network
benchmark-network: ## Benchmark network policy operations
	@echo "Benchmarking network policy operations..."
	go test -bench=BenchmarkNetwork -benchmem -tags=security ./... || echo "No network benchmarks found"

##@ Quick Commands

.PHONY: quick-test
quick-test: check-deps test-basic ## Quick security test for development

.PHONY: full-test
full-test: check-deps test-standard scan-all report ## Full security test cycle

.PHONY: compliance-test
compliance-test: check-deps test-compliance-full report-compliance ## Full compliance test cycle

.PHONY: security-audit
security-audit: analyze-rbac analyze-network-policies analyze-pod-security analyze-secrets ## Complete security audit

# Default target
.DEFAULT_GOAL := help