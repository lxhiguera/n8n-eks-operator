# Performance Test Makefile for n8n EKS Operator

# Variables
TIMEOUT ?= 60m
CONCURRENT_INSTANCES ?= 10
RECONCILE_ITERATIONS ?= 50
LOAD_TEST_DURATION ?= 5m
LOAD_TEST_CONCURRENCY ?= 5
BENCHMARK_ITERATIONS ?= 100

# Test binary
TEST_BINARY = performance.test
BENCH_BINARY = benchmark.test

# Go test flags
GO_TEST_FLAGS = -v -timeout=$(TIMEOUT) -tags=performance
GO_BENCH_FLAGS = -bench=. -benchmem -benchtime=10s -tags=performance

# Environment variables for tests
PERF_ENV_VARS = \
	PERF_TEST_TIMEOUT=$(TIMEOUT) \
	PERF_CONCURRENT_INSTANCES=$(CONCURRENT_INSTANCES) \
	PERF_RECONCILE_ITERATIONS=$(RECONCILE_ITERATIONS) \
	PERF_LOAD_TEST_DURATION=$(LOAD_TEST_DURATION) \
	PERF_LOAD_TEST_CONCURRENCY=$(LOAD_TEST_CONCURRENCY) \
	PERF_BENCHMARK_ITERATIONS=$(BENCHMARK_ITERATIONS)

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: build
build: ## Build performance test binary
	@echo "Building performance test binary..."
	go test -c $(GO_TEST_FLAGS) -o $(TEST_BINARY) .

.PHONY: build-bench
build-bench: ## Build benchmark test binary
	@echo "Building benchmark test binary..."
	go test -c $(GO_BENCH_FLAGS) -o $(BENCH_BINARY) .

.PHONY: clean
clean: ## Clean test artifacts
	@echo "Cleaning performance test artifacts..."
	rm -f $(TEST_BINARY) $(BENCH_BINARY)
	rm -f *.log *.json *.html
	rm -f cpu.prof mem.prof trace.out
	rm -f performance-report.txt benchmark-report.txt

##@ Performance Testing

.PHONY: test
test: ## Run all performance tests
	@echo "Running performance tests..."
	$(PERF_ENV_VARS) go test $(GO_TEST_FLAGS) ./...

.PHONY: test-reconcile
test-reconcile: ## Run reconciliation performance tests
	@echo "Running reconciliation performance tests..."
	$(PERF_ENV_VARS) go test $(GO_TEST_FLAGS) -run TestReconcilePerformance ./...

.PHONY: test-concurrent
test-concurrent: ## Run concurrent reconciliation tests
	@echo "Running concurrent reconciliation tests..."
	$(PERF_ENV_VARS) go test $(GO_TEST_FLAGS) -run TestConcurrentReconciliation ./...

.PHONY: test-iterations
test-iterations: ## Run reconciliation iteration tests
	@echo "Running reconciliation iteration tests..."
	$(PERF_ENV_VARS) go test $(GO_TEST_FLAGS) -run TestReconcileIterations ./...

.PHONY: test-load
test-load: ## Run load tests
	@echo "Running load tests..."
	$(PERF_ENV_VARS) go test $(GO_TEST_FLAGS) -run TestLoadTest ./...

##@ Benchmarking

.PHONY: bench
bench: ## Run all benchmarks
	@echo "Running benchmarks..."
	$(PERF_ENV_VARS) go test $(GO_BENCH_FLAGS) ./... | tee benchmark-report.txt

.PHONY: bench-create
bench-create: ## Benchmark N8nInstance creation
	@echo "Benchmarking N8nInstance creation..."
	$(PERF_ENV_VARS) go test $(GO_BENCH_FLAGS) -run=^$$ -bench=BenchmarkN8nInstanceCreate ./...

.PHONY: bench-update
bench-update: ## Benchmark N8nInstance updates
	@echo "Benchmarking N8nInstance updates..."
	$(PERF_ENV_VARS) go test $(GO_BENCH_FLAGS) -run=^$$ -bench=BenchmarkN8nInstanceUpdate ./...

.PHONY: bench-get
bench-get: ## Benchmark N8nInstance retrieval
	@echo "Benchmarking N8nInstance retrieval..."
	$(PERF_ENV_VARS) go test $(GO_BENCH_FLAGS) -run=^$$ -bench=BenchmarkN8nInstanceGet ./...

.PHONY: bench-list
bench-list: ## Benchmark N8nInstance listing
	@echo "Benchmarking N8nInstance listing..."
	$(PERF_ENV_VARS) go test $(GO_BENCH_FLAGS) -run=^$$ -bench=BenchmarkN8nInstanceList ./...

.PHONY: bench-delete
bench-delete: ## Benchmark N8nInstance deletion
	@echo "Benchmarking N8nInstance deletion..."
	$(PERF_ENV_VARS) go test $(GO_BENCH_FLAGS) -run=^$$ -bench=BenchmarkN8nInstanceDelete ./...

.PHONY: bench-concurrent
bench-concurrent: ## Benchmark concurrent operations
	@echo "Benchmarking concurrent operations..."
	$(PERF_ENV_VARS) go test $(GO_BENCH_FLAGS) -run=^$$ -bench=BenchmarkConcurrentOperations ./...

.PHONY: bench-validation
bench-validation: ## Benchmark validation webhook
	@echo "Benchmarking validation webhook..."
	$(PERF_ENV_VARS) go test $(GO_BENCH_FLAGS) -run=^$$ -bench=BenchmarkValidationWebhook ./...

.PHONY: bench-status
bench-status: ## Benchmark status updates
	@echo "Benchmarking status updates..."
	$(PERF_ENV_VARS) go test $(GO_BENCH_FLAGS) -run=^$$ -bench=BenchmarkStatusUpdate ./...

##@ Profiling

.PHONY: profile-cpu
profile-cpu: ## Run benchmarks with CPU profiling
	@echo "Running benchmarks with CPU profiling..."
	$(PERF_ENV_VARS) go test $(GO_BENCH_FLAGS) -cpuprofile=cpu.prof ./...
	@echo "CPU profile saved to cpu.prof"
	@echo "View with: go tool pprof cpu.prof"

.PHONY: profile-mem
profile-mem: ## Run benchmarks with memory profiling
	@echo "Running benchmarks with memory profiling..."
	$(PERF_ENV_VARS) go test $(GO_BENCH_FLAGS) -memprofile=mem.prof ./...
	@echo "Memory profile saved to mem.prof"
	@echo "View with: go tool pprof mem.prof"

.PHONY: profile-trace
profile-trace: ## Run benchmarks with execution tracing
	@echo "Running benchmarks with execution tracing..."
	$(PERF_ENV_VARS) go test $(GO_BENCH_FLAGS) -trace=trace.out ./...
	@echo "Trace saved to trace.out"
	@echo "View with: go tool trace trace.out"

.PHONY: profile-all
profile-all: ## Run benchmarks with all profiling enabled
	@echo "Running benchmarks with all profiling enabled..."
	$(PERF_ENV_VARS) go test $(GO_BENCH_FLAGS) -cpuprofile=cpu.prof -memprofile=mem.prof -trace=trace.out ./...
	@echo "Profiles saved: cpu.prof, mem.prof, trace.out"

##@ Load Testing Scenarios

.PHONY: load-light
load-light: ## Run light load test scenario
	@echo "Running light load test scenario..."
	PERF_CONCURRENT_INSTANCES=5 \
	PERF_RECONCILE_ITERATIONS=20 \
	PERF_LOAD_TEST_DURATION=2m \
	PERF_LOAD_TEST_CONCURRENCY=2 \
	go test $(GO_TEST_FLAGS) -run TestLoadTest ./...

.PHONY: load-medium
load-medium: ## Run medium load test scenario
	@echo "Running medium load test scenario..."
	PERF_CONCURRENT_INSTANCES=15 \
	PERF_RECONCILE_ITERATIONS=50 \
	PERF_LOAD_TEST_DURATION=5m \
	PERF_LOAD_TEST_CONCURRENCY=5 \
	go test $(GO_TEST_FLAGS) -run TestLoadTest ./...

.PHONY: load-heavy
load-heavy: ## Run heavy load test scenario
	@echo "Running heavy load test scenario..."
	PERF_CONCURRENT_INSTANCES=50 \
	PERF_RECONCILE_ITERATIONS=100 \
	PERF_LOAD_TEST_DURATION=10m \
	PERF_LOAD_TEST_CONCURRENCY=10 \
	go test $(GO_TEST_FLAGS) -run TestLoadTest ./...

.PHONY: load-burst
load-burst: ## Run burst load test scenario
	@echo "Running burst load test scenario..."
	PERF_CONCURRENT_INSTANCES=100 \
	PERF_RECONCILE_ITERATIONS=200 \
	PERF_LOAD_TEST_DURATION=3m \
	PERF_LOAD_TEST_CONCURRENCY=20 \
	go test $(GO_TEST_FLAGS) -run TestLoadTest ./...

##@ Reporting

.PHONY: report
report: ## Generate performance report
	@echo "Generating performance report..."
	@echo "# Performance Test Report" > performance-report.txt
	@echo "Generated on: $$(date)" >> performance-report.txt
	@echo "" >> performance-report.txt
	@echo "## Configuration" >> performance-report.txt
	@echo "- Timeout: $(TIMEOUT)" >> performance-report.txt
	@echo "- Concurrent Instances: $(CONCURRENT_INSTANCES)" >> performance-report.txt
	@echo "- Reconcile Iterations: $(RECONCILE_ITERATIONS)" >> performance-report.txt
	@echo "- Load Test Duration: $(LOAD_TEST_DURATION)" >> performance-report.txt
	@echo "- Load Test Concurrency: $(LOAD_TEST_CONCURRENCY)" >> performance-report.txt
	@echo "" >> performance-report.txt
	@if [ -f benchmark-report.txt ]; then \
		echo "## Benchmark Results" >> performance-report.txt; \
		cat benchmark-report.txt >> performance-report.txt; \
	fi
	@echo "Performance report generated: performance-report.txt"

.PHONY: report-html
report-html: ## Generate HTML performance report
	@echo "Generating HTML performance report..."
	@echo "<!DOCTYPE html><html><head><title>Performance Report</title></head><body>" > performance-report.html
	@echo "<h1>n8n EKS Operator Performance Report</h1>" >> performance-report.html
	@echo "<p>Generated on: $$(date)</p>" >> performance-report.html
	@echo "<h2>Configuration</h2><ul>" >> performance-report.html
	@echo "<li>Timeout: $(TIMEOUT)</li>" >> performance-report.html
	@echo "<li>Concurrent Instances: $(CONCURRENT_INSTANCES)</li>" >> performance-report.html
	@echo "<li>Reconcile Iterations: $(RECONCILE_ITERATIONS)</li>" >> performance-report.html
	@echo "<li>Load Test Duration: $(LOAD_TEST_DURATION)</li>" >> performance-report.html
	@echo "<li>Load Test Concurrency: $(LOAD_TEST_CONCURRENCY)</li>" >> performance-report.html
	@echo "</ul>" >> performance-report.html
	@if [ -f benchmark-report.txt ]; then \
		echo "<h2>Benchmark Results</h2><pre>" >> performance-report.html; \
		cat benchmark-report.txt >> performance-report.html; \
		echo "</pre>" >> performance-report.html; \
	fi
	@echo "</body></html>" >> performance-report.html
	@echo "HTML performance report generated: performance-report.html"

##@ Analysis

.PHONY: analyze-cpu
analyze-cpu: ## Analyze CPU profile
	@if [ -f cpu.prof ]; then \
		echo "Analyzing CPU profile..."; \
		go tool pprof -top cpu.prof; \
	else \
		echo "CPU profile not found. Run 'make profile-cpu' first."; \
	fi

.PHONY: analyze-mem
analyze-mem: ## Analyze memory profile
	@if [ -f mem.prof ]; then \
		echo "Analyzing memory profile..."; \
		go tool pprof -top mem.prof; \
	else \
		echo "Memory profile not found. Run 'make profile-mem' first."; \
	fi

.PHONY: analyze-trace
analyze-trace: ## Analyze execution trace
	@if [ -f trace.out ]; then \
		echo "Opening trace analyzer..."; \
		go tool trace trace.out; \
	else \
		echo "Trace file not found. Run 'make profile-trace' first."; \
	fi

##@ Comparison

.PHONY: compare-bench
compare-bench: ## Compare benchmark results with baseline
	@if [ -f baseline-benchmark.txt ] && [ -f benchmark-report.txt ]; then \
		echo "Comparing benchmark results..."; \
		echo "# Benchmark Comparison" > benchmark-comparison.txt; \
		echo "## Baseline vs Current" >> benchmark-comparison.txt; \
		echo "### Baseline Results" >> benchmark-comparison.txt; \
		cat baseline-benchmark.txt >> benchmark-comparison.txt; \
		echo "### Current Results" >> benchmark-comparison.txt; \
		cat benchmark-report.txt >> benchmark-comparison.txt; \
		echo "Comparison saved to benchmark-comparison.txt"; \
	else \
		echo "Baseline or current benchmark results not found."; \
		echo "Run 'make bench' to generate current results."; \
		echo "Copy benchmark-report.txt to baseline-benchmark.txt to set baseline."; \
	fi

.PHONY: save-baseline
save-baseline: ## Save current benchmark results as baseline
	@if [ -f benchmark-report.txt ]; then \
		cp benchmark-report.txt baseline-benchmark.txt; \
		echo "Baseline saved from current benchmark results."; \
	else \
		echo "No benchmark results found. Run 'make bench' first."; \
	fi

##@ CI/CD

.PHONY: test-ci
test-ci: ## Run performance tests for CI/CD
	@echo "Running performance tests for CI/CD..."
	PERF_TEST_TIMEOUT=15m \
	PERF_CONCURRENT_INSTANCES=5 \
	PERF_RECONCILE_ITERATIONS=20 \
	PERF_LOAD_TEST_DURATION=2m \
	PERF_LOAD_TEST_CONCURRENCY=2 \
	PERF_BENCHMARK_ITERATIONS=50 \
	go test $(GO_TEST_FLAGS) -json ./... > performance-results.json

.PHONY: bench-ci
bench-ci: ## Run benchmarks for CI/CD
	@echo "Running benchmarks for CI/CD..."
	PERF_BENCHMARK_ITERATIONS=50 \
	go test $(GO_BENCH_FLAGS) -benchtime=5s ./... | tee benchmark-ci.txt

##@ Prerequisites

.PHONY: check-deps
check-deps: ## Check performance test dependencies
	@echo "Checking performance test dependencies..."
	@command -v go >/dev/null 2>&1 || { echo "go is required but not installed. Aborting." >&2; exit 1; }
	@echo "✓ Go is available"
	@go version
	@echo "✓ All dependencies are available"

.PHONY: install-deps
install-deps: ## Install performance test dependencies
	@echo "Installing performance test dependencies..."
	go mod download
	go install golang.org/x/perf/cmd/benchstat@latest
	go install github.com/google/pprof@latest

##@ Quick Commands

.PHONY: quick-test
quick-test: check-deps test-ci ## Quick performance test for CI/CD

.PHONY: full-test
full-test: check-deps test bench report ## Full performance test cycle

.PHONY: profile-suite
profile-suite: profile-all analyze-cpu analyze-mem ## Complete profiling suite

# Default target
.DEFAULT_GOAL := help