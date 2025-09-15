#!/bin/bash

# E2E Test Runner Script for n8n EKS Operator
# This script provides a convenient way to run E2E tests with various configurations

set -euo pipefail

# Default configuration
DEFAULT_NAMESPACE="n8n-e2e-test"
DEFAULT_TIMEOUT="30m"
DEFAULT_USE_REAL_CLUSTER="false"
DEFAULT_CLEANUP="true"
DEFAULT_VERBOSE="false"

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
Usage: $0 [OPTIONS] [TEST_PATTERN]

Run E2E tests for n8n EKS Operator

OPTIONS:
    -h, --help              Show this help message
    -n, --namespace NAME    Test namespace (default: $DEFAULT_NAMESPACE)
    -t, --timeout DURATION Test timeout (default: $DEFAULT_TIMEOUT)
    -r, --real-cluster      Use real Kubernetes cluster instead of envtest
    -c, --no-cleanup        Skip cleanup after tests
    -v, --verbose           Enable verbose logging
    -p, --parallel NUM      Run tests in parallel (default: 1)
    --coverage              Generate coverage report
    --ci                    Run in CI mode (JSON output)
    --dry-run               Show what would be executed without running

TEST_PATTERN:
    all                     Run all E2E tests (default)
    lifecycle               Run lifecycle tests only
    custom                  Run custom configuration tests only
    error                   Run error handling tests only
    monitoring              Run monitoring tests only

EXAMPLES:
    $0                                          # Run all tests with envtest
    $0 --real-cluster lifecycle                # Run lifecycle tests on real cluster
    $0 --namespace my-test --timeout 60m       # Custom namespace and timeout
    $0 --verbose --coverage all                # Verbose mode with coverage
    $0 --ci --no-cleanup                       # CI mode without cleanup

ENVIRONMENT VARIABLES:
    KUBECONFIG              Path to kubeconfig file
    AWS_REGION              AWS region for tests (default: us-west-2)
    AWS_PROFILE             AWS profile to use
    OPERATOR_IMAGE          Custom operator image for tests
    TEST_PREFIX             Prefix for test resources
    KEEP_RESOURCES          Keep resources after tests (true/false)

EOF
}

# Function to check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check required commands
    local required_commands=("go" "kubectl")
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
    
    # Check cluster connectivity if using real cluster
    if [[ "$USE_REAL_CLUSTER" == "true" ]]; then
        if ! kubectl cluster-info &> /dev/null; then
            print_error "Cannot connect to Kubernetes cluster. Check your kubeconfig."
            exit 1
        fi
        print_success "Kubernetes cluster connection verified"
    fi
    
    print_success "All prerequisites satisfied"
}

# Function to setup test environment
setup_environment() {
    print_info "Setting up test environment..."
    
    # Set environment variables
    export RUN_E2E_TESTS="true"
    export USE_REAL_CLUSTER="$USE_REAL_CLUSTER"
    export TEST_NAMESPACE="$NAMESPACE"
    export TEST_TIMEOUT="$TIMEOUT"
    
    if [[ "$VERBOSE" == "true" ]]; then
        export VERBOSE_LOGGING="true"
    fi
    
    if [[ "$CLEANUP" == "false" ]]; then
        export KEEP_RESOURCES="true"
    fi
    
    # Create namespace if using real cluster
    if [[ "$USE_REAL_CLUSTER" == "true" ]]; then
        print_info "Creating test namespace: $NAMESPACE"
        kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
        kubectl label namespace "$NAMESPACE" test-suite=n8n-e2e --overwrite
    fi
    
    print_success "Test environment ready"
}

# Function to run tests
run_tests() {
    local test_pattern="$1"
    local go_test_args=("-v" "-timeout=$TIMEOUT" "-tags=e2e")
    
    # Add parallel flag if specified
    if [[ "$PARALLEL" -gt 1 ]]; then
        go_test_args+=("-parallel=$PARALLEL")
    fi
    
    # Add coverage flag if specified
    if [[ "$COVERAGE" == "true" ]]; then
        go_test_args+=("-coverprofile=coverage.out")
    fi
    
    # Add CI flag if specified
    if [[ "$CI_MODE" == "true" ]]; then
        go_test_args+=("-json")
    fi
    
    # Determine test run pattern
    local run_pattern=""
    case "$test_pattern" in
        "all")
            run_pattern="./..."
            ;;
        "lifecycle")
            run_pattern="-run TestE2ESuite/TestN8nInstanceLifecycle ./..."
            ;;
        "custom")
            run_pattern="-run TestE2ESuite/TestN8nInstanceWithCustomConfig ./..."
            ;;
        "error")
            run_pattern="-run TestE2ESuite/TestN8nInstanceErrorHandling ./..."
            ;;
        "monitoring")
            run_pattern="-run TestE2ESuite/TestN8nInstanceMonitoring ./..."
            ;;
        *)
            print_error "Unknown test pattern: $test_pattern"
            exit 1
            ;;
    esac
    
    print_info "Running E2E tests: $test_pattern"
    print_info "Test arguments: ${go_test_args[*]} $run_pattern"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "DRY RUN: Would execute: go test ${go_test_args[*]} $run_pattern"
        return 0
    fi
    
    # Run the tests
    if [[ "$run_pattern" == "./..." ]]; then
        go test "${go_test_args[@]}" ./...
    else
        go test "${go_test_args[@]}" $run_pattern
    fi
}

# Function to cleanup resources
cleanup_resources() {
    if [[ "$CLEANUP" == "false" ]]; then
        print_warning "Skipping cleanup (--no-cleanup specified)"
        return 0
    fi
    
    print_info "Cleaning up test resources..."
    
    if [[ "$USE_REAL_CLUSTER" == "true" ]]; then
        # Clean up test resources
        kubectl delete n8ninstances -l test-suite=n8n-e2e --all-namespaces --ignore-not-found=true --timeout=60s || true
        kubectl delete deployments -l test-suite=n8n-e2e --all-namespaces --ignore-not-found=true --timeout=60s || true
        kubectl delete services -l test-suite=n8n-e2e --all-namespaces --ignore-not-found=true --timeout=60s || true
        kubectl delete configmaps -l test-suite=n8n-e2e --all-namespaces --ignore-not-found=true --timeout=60s || true
        kubectl delete secrets -l test-suite=n8n-e2e --all-namespaces --ignore-not-found=true --timeout=60s || true
        kubectl delete hpa -l test-suite=n8n-e2e --all-namespaces --ignore-not-found=true --timeout=60s || true
        
        # Delete test namespace
        kubectl delete namespace "$NAMESPACE" --ignore-not-found=true --timeout=120s || true
    fi
    
    # Clean up local files
    rm -f coverage.out coverage.html e2e-results.json e2e.test
    
    print_success "Cleanup completed"
}

# Function to generate coverage report
generate_coverage_report() {
    if [[ "$COVERAGE" == "true" && -f "coverage.out" ]]; then
        print_info "Generating coverage report..."
        go tool cover -html=coverage.out -o coverage.html
        print_success "Coverage report generated: coverage.html"
        
        # Show coverage summary
        go tool cover -func=coverage.out | tail -1
    fi
}

# Parse command line arguments
NAMESPACE="$DEFAULT_NAMESPACE"
TIMEOUT="$DEFAULT_TIMEOUT"
USE_REAL_CLUSTER="$DEFAULT_USE_REAL_CLUSTER"
CLEANUP="$DEFAULT_CLEANUP"
VERBOSE="$DEFAULT_VERBOSE"
PARALLEL=1
COVERAGE="false"
CI_MODE="false"
DRY_RUN="false"
TEST_PATTERN="all"

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -r|--real-cluster)
            USE_REAL_CLUSTER="true"
            shift
            ;;
        -c|--no-cleanup)
            CLEANUP="false"
            shift
            ;;
        -v|--verbose)
            VERBOSE="true"
            shift
            ;;
        -p|--parallel)
            PARALLEL="$2"
            shift 2
            ;;
        --coverage)
            COVERAGE="true"
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
        all|lifecycle|custom|error|monitoring)
            TEST_PATTERN="$1"
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
    print_info "Starting E2E test execution..."
    print_info "Configuration:"
    print_info "  Namespace: $NAMESPACE"
    print_info "  Timeout: $TIMEOUT"
    print_info "  Use Real Cluster: $USE_REAL_CLUSTER"
    print_info "  Cleanup: $CLEANUP"
    print_info "  Verbose: $VERBOSE"
    print_info "  Parallel: $PARALLEL"
    print_info "  Coverage: $COVERAGE"
    print_info "  Test Pattern: $TEST_PATTERN"
    
    # Setup trap for cleanup on exit
    trap cleanup_resources EXIT
    
    # Execute test pipeline
    check_prerequisites
    setup_environment
    
    # Run tests and capture exit code
    local exit_code=0
    run_tests "$TEST_PATTERN" || exit_code=$?
    
    # Generate coverage report if requested
    generate_coverage_report
    
    # Report results
    if [[ $exit_code -eq 0 ]]; then
        print_success "All E2E tests passed!"
    else
        print_error "E2E tests failed with exit code: $exit_code"
    fi
    
    return $exit_code
}

# Execute main function
main "$@"