#!/bin/bash

# Security Test Runner Script for n8n EKS Operator
# This script provides a convenient way to run security tests with various configurations

set -euo pipefail

# Default configuration
DEFAULT_TIMEOUT="30m"
DEFAULT_PROFILE="standard"
DEFAULT_COMPLIANCE="SOC2,GDPR,CIS"

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

Run security tests for n8n EKS Operator

OPTIONS:
    -h, --help                  Show this help message
    -t, --timeout DURATION     Test timeout (default: $DEFAULT_TIMEOUT)
    -p, --profile PROFILE       Security profile (basic|standard|strict|compliance) (default: $DEFAULT_PROFILE)
    -c, --compliance STANDARDS  Compliance standards (SOC2,GDPR,HIPAA,PCIDSS,CIS) (default: $DEFAULT_COMPLIANCE)
    --max-critical NUM          Maximum critical vulnerabilities allowed (default: 0)
    --max-high NUM              Maximum high vulnerabilities allowed (default: 5)
    --scan                      Run vulnerability scans
    --analyze                   Run security analysis
    --report                    Generate security report
    --ci                        Run in CI mode
    --dry-run                   Show what would be executed

TEST_TYPE:
    all                         Run all security tests (default)
    secrets                     Run secret management tests
    network                     Run network security tests
    rbac                        Run RBAC tests
    pod-security               Run Pod Security Standards tests
    vulnerabilities            Run vulnerability tests
    compliance                 Run compliance tests
    auditing                   Run security auditing tests
    soc2                       Run SOC 2 compliance tests
    gdpr                       Run GDPR compliance tests
    hipaa                      Run HIPAA compliance tests
    pcidss                     Run PCI DSS compliance tests
    cis                        Run CIS Kubernetes Benchmark tests

EXAMPLES:
    $0                                          # Run standard security tests
    $0 --profile strict compliance              # Run strict compliance tests
    $0 --scan --analyze --report               # Full security assessment
    $0 --compliance SOC2,GDPR soc2            # Run SOC 2 tests only
    $0 --ci --timeout 15m                     # CI mode with custom timeout

ENVIRONMENT VARIABLES:
    SEC_TEST_TIMEOUT            Test timeout override
    SEC_SECURITY_PROFILE        Security profile override
    SEC_COMPLIANCE_STANDARDS    Compliance standards override
    SEC_MAX_CRITICAL_VULNS      Max critical vulnerabilities override
    SEC_MAX_HIGH_VULNS          Max high vulnerabilities override

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
    
    # Check optional tools
    if command -v kubectl &> /dev/null; then
        print_info "✓ kubectl available for cluster analysis"
    else
        print_warning "kubectl not available (optional for some tests)"
    fi
    
    if command -v trivy &> /dev/null; then
        print_info "✓ Trivy available for vulnerability scanning"
    else
        print_warning "Trivy not available (install for vulnerability scanning)"
    fi
    
    if command -v govulncheck &> /dev/null; then
        print_info "✓ govulncheck available for dependency scanning"
    else
        print_warning "govulncheck not available (install for dependency scanning)"
    fi
    
    print_success "Prerequisites check completed"
}

# Function to setup test environment
setup_environment() {
    print_info "Setting up security test environment..."
    
    # Set environment variables based on profile
    case "$PROFILE" in
        "basic")
            export SEC_MAX_CRITICAL_VULNS=0
            export SEC_MAX_HIGH_VULNS=10
            export SEC_REQUIRE_NETWORK_POLICIES=false
            export SEC_REQUIRE_AUDIT_LOGGING=false
            export SEC_SOC2_REQUIRED=false
            export SEC_GDPR_REQUIRED=false
            export SEC_CIS_REQUIRED=false
            ;;
        "standard")
            export SEC_MAX_CRITICAL_VULNS=0
            export SEC_MAX_HIGH_VULNS=5
            export SEC_REQUIRE_NETWORK_POLICIES=true
            export SEC_REQUIRE_AUDIT_LOGGING=true
            export SEC_SOC2_REQUIRED=true
            export SEC_GDPR_REQUIRED=true
            export SEC_CIS_REQUIRED=true
            ;;
        "strict")
            export SEC_MAX_CRITICAL_VULNS=0
            export SEC_MAX_HIGH_VULNS=0
            export SEC_REQUIRE_NETWORK_POLICIES=true
            export SEC_REQUIRE_DEFAULT_DENY_ALL=true
            export SEC_REQUIRE_AUDIT_LOGGING=true
            export SEC_REQUIRE_LOG_INTEGRITY=true
            export SEC_REQUIRE_SECRET_ENCRYPTION=true
            export SEC_REQUIRE_SECRET_ROTATION=true
            export SEC_REQUIRE_SIGNED_IMAGES=true
            ;;
        "compliance")
            export SEC_MAX_CRITICAL_VULNS=0
            export SEC_MAX_HIGH_VULNS=0
            export SEC_SOC2_REQUIRED=true
            export SEC_GDPR_REQUIRED=true
            export SEC_HIPAA_REQUIRED=true
            export SEC_PCIDSS_REQUIRED=true
            export SEC_CIS_REQUIRED=true
            export SEC_REQUIRE_ENCRYPTION_AT_REST=true
            export SEC_REQUIRE_ENCRYPTION_IN_TRANSIT=true
            ;;
    esac
    
    # Override with command line arguments
    export SEC_TEST_TIMEOUT="$TIMEOUT"
    export SEC_SECURITY_PROFILE="$PROFILE"
    export SEC_COMPLIANCE_STANDARDS="$COMPLIANCE"
    
    if [[ -n "$MAX_CRITICAL" ]]; then
        export SEC_MAX_CRITICAL_VULNS="$MAX_CRITICAL"
    fi
    
    if [[ -n "$MAX_HIGH" ]]; then
        export SEC_MAX_HIGH_VULNS="$MAX_HIGH"
    fi
    
    # Set compliance flags based on standards
    IFS=',' read -ra STANDARDS <<< "$COMPLIANCE"
    for standard in "${STANDARDS[@]}"; do
        case "$standard" in
            "SOC2")
                export SEC_SOC2_REQUIRED=true
                ;;
            "GDPR")
                export SEC_GDPR_REQUIRED=true
                ;;
            "HIPAA")
                export SEC_HIPAA_REQUIRED=true
                ;;
            "PCIDSS")
                export SEC_PCIDSS_REQUIRED=true
                ;;
            "CIS")
                export SEC_CIS_REQUIRED=true
                ;;
        esac
    done
    
    print_success "Environment configured for $PROFILE profile"
}

# Function to run security tests
run_security_tests() {
    local test_type="$1"
    local go_test_args=("-v" "-timeout=$TIMEOUT" "-tags=security")
    
    if [[ "$CI_MODE" == "true" ]]; then
        go_test_args+=("-json")
    fi
    
    # Determine test run pattern
    local run_pattern=""
    case "$test_type" in
        "all")
            run_pattern="./..."
            ;;
        "secrets")
            run_pattern="-run TestSecretEncryption ./..."
            ;;
        "network")
            run_pattern="-run TestNetworkPolicies ./..."
            ;;
        "rbac")
            run_pattern="-run TestRBACConfiguration ./..."
            ;;
        "pod-security")
            run_pattern="-run TestPodSecurityStandards ./..."
            ;;
        "vulnerabilities")
            run_pattern="-run TestVulnerabilityScanning ./..."
            ;;
        "compliance")
            run_pattern="-run TestComplianceChecks ./..."
            ;;
        "auditing")
            run_pattern="-run TestSecurityAuditing ./..."
            ;;
        "soc2")
            run_pattern="-run TestSOC2Compliance ./..."
            ;;
        "gdpr")
            run_pattern="-run TestGDPRCompliance ./..."
            ;;
        "hipaa")
            run_pattern="-run TestHIPAACompliance ./..."
            ;;
        "pcidss")
            run_pattern="-run TestPCIDSSCompliance ./..."
            ;;
        "cis")
            run_pattern="-run TestCISKubernetesBenchmark ./..."
            ;;
        *)
            print_error "Unknown test type: $test_type"
            exit 1
            ;;
    esac
    
    print_info "Running security tests: $test_type"
    print_info "Test arguments: ${go_test_args[*]} $run_pattern"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "DRY RUN: Would execute: go test ${go_test_args[*]} $run_pattern"
        return 0
    fi
    
    # Run the tests
    local output_file=""
    if [[ "$CI_MODE" == "true" ]]; then
        output_file="security-results.json"
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

# Function to run vulnerability scans
run_vulnerability_scans() {
    print_info "Running vulnerability scans..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "DRY RUN: Would run vulnerability scans"
        return 0
    fi
    
    # Scan container images
    if command -v trivy &> /dev/null; then
        print_info "Scanning container images with Trivy..."
        trivy image --severity HIGH,CRITICAL n8nio/n8n:latest || true
        trivy image --severity HIGH,CRITICAL n8n-eks-operator:latest || true
    else
        print_warning "Trivy not available, skipping image scans"
    fi
    
    # Scan Go dependencies
    if command -v govulncheck &> /dev/null; then
        print_info "Scanning Go dependencies with govulncheck..."
        govulncheck ./... || true
    else
        print_warning "govulncheck not available, skipping dependency scans"
    fi
    
    print_success "Vulnerability scans completed"
}

# Function to run security analysis
run_security_analysis() {
    print_info "Running security analysis..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "DRY RUN: Would run security analysis"
        return 0
    fi
    
    if ! command -v kubectl &> /dev/null; then
        print_warning "kubectl not available, skipping cluster analysis"
        return 0
    fi
    
    # Analyze RBAC
    print_info "Analyzing RBAC configurations..."
    kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name' || true
    
    # Analyze Network Policies
    print_info "Analyzing network policies..."
    kubectl get networkpolicies --all-namespaces || true
    
    # Analyze Pod Security
    print_info "Analyzing pod security..."
    kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[]?.securityContext?.privileged == true) | "\(.metadata.namespace)/\(.metadata.name)"' || true
    
    # Analyze Secrets
    print_info "Analyzing secrets..."
    kubectl get secrets --all-namespaces --no-headers | wc -l || true
    
    print_success "Security analysis completed"
}

# Function to generate reports
generate_reports() {
    print_info "Generating security reports..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "DRY RUN: Would generate reports"
        return 0
    fi
    
    # Generate main security report
    {
        echo "# Security Test Report"
        echo "Generated on: $(date)"
        echo ""
        echo "## Configuration"
        echo "- Security Profile: $PROFILE"
        echo "- Compliance Standards: $COMPLIANCE"
        echo "- Timeout: $TIMEOUT"
        echo "- Max Critical Vulnerabilities: ${SEC_MAX_CRITICAL_VULNS:-0}"
        echo "- Max High Vulnerabilities: ${SEC_MAX_HIGH_VULNS:-5}"
        echo ""
        echo "## Test Results"
        if [[ -f "security-results.json" ]]; then
            echo "Test results available in security-results.json"
        else
            echo "No test results available"
        fi
        echo ""
        echo "## System Information"
        echo "- OS: $(uname -s)"
        echo "- Architecture: $(uname -m)"
        echo "- Go Version: $(go version)"
        echo ""
    } > security-report.txt
    
    # Generate compliance report
    {
        echo "# Compliance Report"
        echo "Generated on: $(date)"
        echo ""
        echo "## Standards Tested"
        echo "$COMPLIANCE" | tr ',' '\n' | while read -r standard; do
            echo "- $standard"
        done
        echo ""
    } > compliance-report.txt
    
    print_success "Reports generated: security-report.txt, compliance-report.txt"
}

# Parse command line arguments
TIMEOUT="$DEFAULT_TIMEOUT"
PROFILE="$DEFAULT_PROFILE"
COMPLIANCE="$DEFAULT_COMPLIANCE"
MAX_CRITICAL=""
MAX_HIGH=""
SCAN="false"
ANALYZE="false"
REPORT="false"
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
        -p|--profile)
            PROFILE="$2"
            shift 2
            ;;
        -c|--compliance)
            COMPLIANCE="$2"
            shift 2
            ;;
        --max-critical)
            MAX_CRITICAL="$2"
            shift 2
            ;;
        --max-high)
            MAX_HIGH="$2"
            shift 2
            ;;
        --scan)
            SCAN="true"
            shift
            ;;
        --analyze)
            ANALYZE="true"
            shift
            ;;
        --report)
            REPORT="true"
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
        all|secrets|network|rbac|pod-security|vulnerabilities|compliance|auditing|soc2|gdpr|hipaa|pcidss|cis)
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

# Validate profile
case "$PROFILE" in
    basic|standard|strict|compliance)
        ;;
    *)
        print_error "Invalid profile: $PROFILE. Must be one of: basic, standard, strict, compliance"
        exit 1
        ;;
esac

# Main execution
main() {
    print_info "Starting security test execution..."
    print_info "Configuration:"
    print_info "  Profile: $PROFILE"
    print_info "  Compliance: $COMPLIANCE"
    print_info "  Timeout: $TIMEOUT"
    print_info "  Test Type: $TEST_TYPE"
    print_info "  Scan: $SCAN"
    print_info "  Analyze: $ANALYZE"
    print_info "  Report: $REPORT"
    print_info "  CI Mode: $CI_MODE"
    
    # Execute test pipeline
    check_prerequisites
    setup_environment
    
    # Run tests
    local exit_code=0
    run_security_tests "$TEST_TYPE" || exit_code=$?
    
    # Run additional operations
    if [[ "$SCAN" == "true" ]]; then
        run_vulnerability_scans
    fi
    
    if [[ "$ANALYZE" == "true" ]]; then
        run_security_analysis
    fi
    
    if [[ "$REPORT" == "true" ]]; then
        generate_reports
    fi
    
    # Report results
    if [[ $exit_code -eq 0 ]]; then
        print_success "Security tests completed successfully!"
    else
        print_error "Security tests failed with exit code: $exit_code"
    fi
    
    return $exit_code
}

# Execute main function
main "$@"