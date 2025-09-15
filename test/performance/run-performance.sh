#!/bin/bash

# Performance Test Runner Script for n8n EKS Operator
# This script provides a convenient way to run performance tests with various configurations

set -euo pipefail

# Default configuration
DEFAULT_TIMEOUT="60m"
DEFAULT_CONCURRENT_INSTANCES="10"
DEFAULT_RECONCILE_ITERATIONS="50"
DEFAULT_LOAD_DURATION="5m"
DEFAULT_LOAD_CONCURRENCY="5"
DEFAULT_SCENARIO="medium"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] [TEST_TYPE]

Run performance tests for n8n EKS Operator

OPTIONS:
    -h, --help                  Show this help message
    -t, --timeout DURATION     Test timeout (default: $DEFAULT_TIMEOUT)
    -c, --concurrent NUM        Concurrent instances (default: $DEFAULT_CONCURRENT_INSTANCES)
    -i, --iterations NUM        Reconcile iterations (default: $DEFAULT_RECONCILE_ITERATIONS)
    -d, --duration DURATION    Load test duration (default: $DEFAULT_LOAD_DURATION)
    -p, --parallel NUM          Load test concurrency (default: $DEFAULT_LOAD_CONCURRENCY)
    -s, --scenario NAME         Test scenario (light|medium|heavy|burst) (default: $DEFAULT_SCENARIO)
    --profile                   Enable profiling (cpu, memory, trace)
    --benchmark                 Run benchmarks instead of tests
    --report                    Generate performance report
    --compare                   Compare with baseline
    --save-baseline             Save current results as baseline
    --ci                        Run in CI mode
    --dry-run                   Show what would be executed

TEST_TYPE:
    all                         Run all performance tests (default)
    reconcile                   Run reconciliation performance tests
    concurrent                  Run concurrent reconciliation tests
    iterations                  Run reconciliation iteration tests
    load                        Run load tests
    create                      Run creation benchmarks
    update                      Run update benchmarks
    get                         Run retrieval benchmarks
    list                        Run list benchmarks
    delete                      Run deletion benchmarks

EXAMPLES:
    $0                                          # Run medium scenario performance tests
    $0 --scenario heavy load                    # Run heavy load tests
    $0 --benchmark --profile create             # Benchmark creation with profiling
    $0 --concurrent 20 --iterations 100        # Custom concurrent test
    $0 --ci --report                           # CI mode with report generation

ENVIRONMENT VARIABLES:
    PERF_TEST_TIMEOUT           Test timeout override
    PERF_CONCURRENT_INSTANCES   Concurrent instances override
    PERF_RECONCILE_ITERATIONS   Reconcile iterations override
    PERF_LOAD_TEST_DURATION     Load test duration override
    PERF_LOAD_TEST_CONCURRENCY  Load test concurrency override

EOF
}

# Function to check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check required commands
    local required_commands=("go")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            print_error "$cmd is required but not installed"
            exit 1
        fi
    done
    
    # Check Go version
    local go_version
    go_version=$(go version | grep -o 'go[0-9]\+\.[0-9]\+' | sed 's/go//')
    local major_version
    major_version=$(echo "$go_version" | cut -d. -f1)
    local minor_version
    minor_version=$(echo "$go_version" | cut -d. -f2)
    
    if [[ $major_version -lt 1 ]] || [[ $major_version -eq 1 && $minor_version -lt 19 ]]; then
        print_error "Go 1.19+ is required, found $go_version"
        exit 1
    fi
    
    print_success "All prerequisites satisfied"
}

# Function to setup test environment
setup_environment() {
    print_info "Setting up performance test environment..."
    
    # Set environment variables based on scenario
    case "$SCENARIO" in
        "light")
            export PERF_CONCURRENT_INSTANCES=5
            export PERF_RECONCILE_ITERATIONS=20
            export PERF_LOAD_TEST_DURATION="2m"
            export PERF_LOAD_TEST_CONCURRENCY=2
            ;;
        "medium")
            export PERF_CONCURRENT_INSTANCES=15
            export PERF_RECONCILE_ITERATIONS=50
            export PERF_LOAD_TEST_DURATION="5m"
            export PERF_LOAD_TEST_CONCURRENCY=5
            ;;
        "heavy")
            export PERF_CONCURRENT_INSTANCES=50
            export PERF_RECONCILE_ITERATIONS=100
            export PERF_LOAD_TEST_DURATION="10m"
            export PERF_LOAD_TEST_CONCURRENCY=10
            ;;
        "burst")
            export PERF_CONCURRENT_INSTANCES=100
            export PERF_RECONCILE_ITERATIONS=200
            export PERF_LOAD_TEST_DURATION="3m"
            export PERF_LOAD_TEST_CONCURRENCY=20
            ;;
    esac
    
    # Override with command line arguments
    export PERF_TEST_TIMEOUT="$TIMEOUT"
    export PERF_CONCURRENT_INSTANCES="${CONCURRENT_INSTANCES:-$PERF_CONCURRENT_INSTANCES}"
    export PERF_RECONCILE_ITERATIONS="${RECONCILE_ITERATIONS:-$PERF_RECONCILE_ITERATIONS}"
    export PERF_LOAD_TEST_DURATION="${LOAD_DURATION:-$PERF_LOAD_TEST_DURATION}"
    export PERF_LOAD_TEST_CONCURRENCY="${LOAD_CONCURRENCY:-$PERF_LOAD_TEST_CONCURRENCY}"
    
    print_success "Environment configured for $SCENARIO scenario"
}

# Function to run performance tests
run_performance_tests() {
    local test_type="$1"
    local go_test_args=("-v" "-timeout=$TIMEOUT" "-tags=performance")
    
    if [[ "$CI_MODE" == "true" ]]; then
        go_test_args+=("-json")
    fi
    
    # Determine test run pattern
    local run_pattern=""
    case "$test_type" in
        "all")
            run_pattern="./..."
            ;;
        "reconcile")
            run_pattern="-run TestReconcilePerformance ./..."
            ;;
        "concurrent")
            run_pattern="-run TestConcurrentReconciliation ./..."
            ;;
        "iterations")
            run_pattern="-run TestReconcileIterations ./..."
            ;;
        "load")
            run_pattern="-run TestLoadTest ./..."
            ;;
        *)
            print_error "Unknown test type: $test_type"
            exit 1
            ;;
    esac
    
    print_info "Running performance tests: $test_type"
    print_info "Test arguments: ${go_test_args[*]} $run_pattern"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "DRY RUN: Would execute: go test ${go_test_args[*]} $run_pattern"
        return 0
    fi
    
    # Run the tests
    local output_file=""
    if [[ "$CI_MODE" == "true" ]]; then
        output_file="performance-results.json"
    fi
    
    if [[ "$run_pattern" == "./..." ]]; then
        if [[ -n "$output_file" ]]; then
            go test "${go_test_args[@]}" ./... > "$output_file"
        else
            go test "${go_test_args[@]}" ./...
        fi
    else
        if [[ -n "$output_file" ]]; then
            go test "${go_test_args[@]}" $run_pattern > "$output_file"
        else
            go test "${go_test_args[@]}" $run_pattern
        fi
    fi
}

# Function to run benchmarks
run_benchmarks() {
    local bench_type="$1"
    local go_bench_args=("-bench=." "-benchmem" "-benchtime=10s" "-tags=performance")
    
    if [[ "$PROFILE" == "true" ]]; then
        go_bench_args+=("-cpuprofile=cpu.prof" "-memprofile=mem.prof" "-trace=trace.out")
    fi
    
    # Determine benchmark pattern
    local bench_pattern=""
    case "$bench_type" in
        "all")
            bench_pattern="./..."
            ;;
        "create")
            bench_pattern="-run=^$$ -bench=BenchmarkN8nInstanceCreate ./..."
            ;;
        "update")
            bench_pattern="-run=^$$ -bench=BenchmarkN8nInstanceUpdate ./..."
            ;;
        "get")
            bench_pattern="-run=^$$ -bench=BenchmarkN8nInstanceGet ./..."
            ;;
        "list")
            bench_pattern="-run=^$$ -bench=BenchmarkN8nInstanceList ./..."
            ;;
        "delete")
            bench_pattern="-run=^$$ -bench=BenchmarkN8nInstanceDelete ./..."
            ;;
        *)
            print_error "Unknown benchmark type: $bench_type"
            exit 1
            ;;
    esac
    
    print_info "Running benchmarks: $bench_type"
    print_info "Benchmark arguments: ${go_bench_args[*]} $bench_pattern"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "DRY RUN: Would execute: go test ${go_bench_args[*]} $bench_pattern"
        return 0
    fi
    
    # Run the benchmarks
    local output_file="benchmark-report.txt"
    
    if [[ "$bench_pattern" == "./..." ]]; then
        go test "${go_bench_args[@]}" ./... | tee "$output_file"
    else
        go test "${go_bench_args[@]}" $bench_pattern | tee "$output_file"
    fi
    
    if [[ "$PROFILE" == "true" ]]; then
        print_success "Profiling data saved: cpu.prof, mem.prof, trace.out"
        print_info "Analyze with:"
        print_info "  go tool pprof cpu.prof"
        print_info "  go tool pprof mem.prof"
        print_info "  go tool trace trace.out"
    fi
}

# Function to generate report
generate_report() {
    print_info "Generating performance report..."
    
    local report_file="performance-report.txt"
    
    {
        echo "# Performance Test Report"
        echo "Generated on: $(date)"
        echo ""
        echo "## Configuration"
        echo "- Scenario: $SCENARIO"
        echo "- Timeout: $TIMEOUT"
        echo "- Concurrent Instances: $PERF_CONCURRENT_INSTANCES"
        echo "- Reconcile Iterations: $PERF_RECONCILE_ITERATIONS"
        echo "- Load Test Duration: $PERF_LOAD_TEST_DURATION"
        echo "- Load Test Concurrency: $PERF_LOAD_TEST_CONCURRENCY"
        echo ""
        
        if [[ -f "benchmark-report.txt" ]]; then
            echo "## Benchmark Results"
            cat "benchmark-report.txt"
            echo ""
        fi
        
        if [[ -f "performance-results.json" ]]; then
            echo "## Test Results"
            echo "Results saved in JSON format: performance-results.json"
            echo ""
        fi
        
        echo "## System Information"
        echo "- OS: $(uname -s)"
        echo "- Architecture: $(uname -m)"
        echo "- Go Version: $(go version)"
        echo "- CPU Cores: $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 'unknown')"
        echo "- Memory: $(free -h 2>/dev/null | grep '^Mem:' | awk '{print $2}' || echo 'unknown')"
    } > "$report_file"
    
    print_success "Performance report generated: $report_file"
}

# Function to compare with baseline
compare_with_baseline() {
    print_info "Comparing with baseline..."
    
    if [[ ! -f "baseline-benchmark.txt" ]]; then
        print_warning "No baseline found. Run with --save-baseline first."
        return 1
    fi
    
    if [[ ! -f "benchmark-report.txt" ]]; then
        print_warning "No current benchmark results found. Run benchmarks first."
        return 1
    fi
    
    local comparison_file="benchmark-comparison.txt"
    
    {
        echo "# Benchmark Comparison Report"
        echo "Generated on: $(date)"
        echo ""
        echo "## Baseline Results"
        cat "baseline-benchmark.txt"
        echo ""
        echo "## Current Results"
        cat "benchmark-report.txt"
        echo ""
        echo "## Analysis"
        echo "Manual analysis required - compare the results above"
    } > "$comparison_file"
    
    print_success "Comparison report generated: $comparison_file"
}

# Function to save baseline
save_baseline() {
    print_info "Saving current results as baseline..."
    
    if [[ -f "benchmark-report.txt" ]]; then
        cp "benchmark-report.txt" "baseline-benchmark.txt"
        print_success "Baseline saved from current benchmark results"
    else
        print_warning "No benchmark results found. Run benchmarks first."
        return 1
    fi
}

# Parse command line arguments
TIMEOUT="$DEFAULT_TIMEOUT"
CONCURRENT_INSTANCES=""
RECONCILE_ITERATIONS=""
LOAD_DURATION=""
LOAD_CONCURRENCY=""
SCENARIO="$DEFAULT_SCENARIO"
PROFILE="false"
BENCHMARK="false"
REPORT="false"
COMPARE="false"
SAVE_BASELINE_FLAG="false"
CI_MODE="false"
DRY_RUN="false"
TEST_TYPE="all"

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -c|--concurrent)
            CONCURRENT_INSTANCES="$2"
            shift 2
            ;;
        -i|--iterations)
            RECONCILE_ITERATIONS="$2"
            shift 2
            ;;
        -d|--duration)
            LOAD_DURATION="$2"
            shift 2
            ;;
        -p|--parallel)
            LOAD_CONCURRENCY="$2"
            shift 2
            ;;
        -s|--scenario)
            SCENARIO="$2"
            shift 2
            ;;
        --profile)
            PROFILE="true"
            shift
            ;;
        --benchmark)
            BENCHMARK="true"
            shift
            ;;
        --report)
            REPORT="true"
            shift
            ;;
        --compare)
            COMPARE="true"
            shift
            ;;
        --save-baseline)
            SAVE_BASELINE_FLAG="true"
            shift
            ;;
        --ci)
            CI_MODE="true"
            shift
            ;;
        --dry-run)
            DRY_RUN="true"
            shift
            ;;
        all|reconcile|concurrent|iterations|load|create|update|get|list|delete)
            TEST_TYPE="$1"
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    print_info "Starting performance test execution..."
    print_info "Configuration:"
    print_info "  Scenario: $SCENARIO"
    print_info "  Timeout: $TIMEOUT"
    print_info "  Test Type: $TEST_TYPE"
    print_info "  Benchmark Mode: $BENCHMARK"
    print_info "  Profiling: $PROFILE"
    print_info "  CI Mode: $CI_MODE"
    
    # Execute test pipeline
    check_prerequisites
    setup_environment
    
    # Run tests or benchmarks
    local exit_code=0
    if [[ "$BENCHMARK" == "true" ]]; then
        run_benchmarks "$TEST_TYPE" || exit_code=$?
    else
        run_performance_tests "$TEST_TYPE" || exit_code=$?
    fi
    
    # Post-processing
    if [[ "$REPORT" == "true" ]]; then
        generate_report
    fi
    
    if [[ "$COMPARE" == "true" ]]; then
        compare_with_baseline
    fi
    
    if [[ "$SAVE_BASELINE_FLAG" == "true" ]]; then
        save_baseline
    fi
    
    # Report results
    if [[ $exit_code -eq 0 ]]; then
        print_success "Performance tests completed successfully!"
    else
        print_error "Performance tests failed with exit code: $exit_code"
    fi
    
    return $exit_code
}

# Execute main function
main "$@"