# Security Tests for n8n EKS Operator

This directory contains comprehensive security and compliance tests for the n8n EKS Operator. These tests validate security configurations, compliance requirements, and vulnerability management practices.

## Overview

The security test suite includes:

- **Secret Management Tests**: Encryption, rotation, and access control
- **Network Security Tests**: Network policies and isolation
- **RBAC Tests**: Role-based access control validation
- **Pod Security Tests**: Pod Security Standards compliance
- **Vulnerability Scanning**: Image and dependency vulnerability detection
- **Compliance Tests**: SOC 2, GDPR, HIPAA, PCI DSS, CIS Kubernetes Benchmark
- **Security Auditing**: Logging, monitoring, and alerting validation

## Test Structure

### Test Files

- `security_test.go` - Main security test suite
- `security_helpers.go` - Security validation helper functions
- `compliance.go` - Compliance testing implementations
- `config.go` - Security configuration management
- `Makefile` - Build and execution targets
- `README.md` - This documentation

### Test Categories

#### 1. Secret Management Tests

- **Encryption Testing**: Validates secret encryption at rest and in transit
- **Access Control**: Verifies proper secret access restrictions
- **Rotation Testing**: Tests automated secret rotation capabilities
- **Key Management**: Validates cryptographic key handling

#### 2. Network Security Tests

- **Network Policies**: Tests Kubernetes NetworkPolicy configurations
- **Default Deny**: Validates default-deny-all network policies
- **Isolation Testing**: Verifies network segmentation between components
- **Ingress/Egress Control**: Tests traffic flow restrictions

#### 3. RBAC Security Tests

- **Minimal Permissions**: Validates principle of least privilege
- **Role Configuration**: Tests role and role binding configurations
- **Privilege Escalation**: Prevents unauthorized privilege escalation
- **Service Account Security**: Validates service account configurations

#### 4. Pod Security Standards Tests

- **Non-Root Execution**: Ensures pods run as non-root users
- **Security Contexts**: Validates security context configurations
- **Resource Limits**: Ensures proper resource constraints
- **Privileged Containers**: Prevents privileged container execution
- **Read-Only Filesystems**: Validates read-only root filesystems

#### 5. Vulnerability Management Tests

- **Image Scanning**: Scans container images for vulnerabilities
- **Dependency Scanning**: Checks Go modules and dependencies
- **Critical Vulnerability Detection**: Ensures no critical vulnerabilities
- **Vulnerability Reporting**: Generates vulnerability reports

#### 6. Compliance Tests

- **SOC 2 Type II**: Service Organization Control compliance
- **GDPR**: General Data Protection Regulation compliance
- **HIPAA**: Health Insurance Portability and Accountability Act
- **PCI DSS**: Payment Card Industry Data Security Standard
- **CIS Kubernetes Benchmark**: Center for Internet Security benchmarks

## Security Profiles

The test suite supports multiple security profiles:

### Basic Profile
```yaml
profile: basic
max_critical_vulnerabilities: 0
max_high_vulnerabilities: 10
require_non_root: true
require_resource_limits: true
require_network_policies: false
require_audit_logging: false
compliance_standards: []
```

### Standard Profile
```yaml
profile: standard
max_critical_vulnerabilities: 0
max_high_vulnerabilities: 5
require_non_root: true
require_readonly_root: true
require_resource_limits: true
require_network_policies: true
require_audit_logging: true
require_secret_encryption: true
compliance_standards: [SOC2, GDPR, CIS]
```

### Strict Profile
```yaml
profile: strict
max_critical_vulnerabilities: 0
max_high_vulnerabilities: 0
require_all_security_controls: true
require_signed_images: true
require_log_integrity: true
require_secret_rotation: true
compliance_standards: [SOC2, GDPR, CIS]
```

### Compliance Profile
```yaml
profile: compliance
max_critical_vulnerabilities: 0
max_high_vulnerabilities: 0
require_all_security_controls: true
require_encryption_at_rest: true
require_encryption_in_transit: true
compliance_standards: [SOC2, GDPR, HIPAA, PCIDSS, CIS]
```

## Configuration

### Environment Variables

Security tests can be configured using environment variables:

```bash
# Test execution
SEC_TEST_TIMEOUT=30m                     # Test timeout
SEC_SECURITY_PROFILE=standard            # Security profile to use

# Vulnerability scanning
SEC_MAX_CRITICAL_VULNS=0                 # Max critical vulnerabilities allowed
SEC_MAX_HIGH_VULNS=5                     # Max high vulnerabilities allowed
SEC_MAX_MEDIUM_VULNS=20                  # Max medium vulnerabilities allowed
SEC_VULN_SCAN_TIMEOUT=10m                # Vulnerability scan timeout

# Compliance requirements
SEC_SOC2_REQUIRED=true                   # Require SOC 2 compliance
SEC_GDPR_REQUIRED=true                   # Require GDPR compliance
SEC_HIPAA_REQUIRED=false                 # Require HIPAA compliance
SEC_PCIDSS_REQUIRED=false                # Require PCI DSS compliance
SEC_CIS_REQUIRED=true                    # Require CIS compliance

# Security controls
SEC_REQUIRE_NON_ROOT=true                # Require non-root execution
SEC_REQUIRE_READONLY_ROOT=true           # Require read-only root filesystem
SEC_REQUIRE_RESOURCE_LIMITS=true         # Require resource limits
SEC_REQUIRE_NETWORK_POLICIES=true        # Require network policies
SEC_REQUIRE_AUDIT_LOGGING=true           # Require audit logging
SEC_REQUIRE_SECRET_ENCRYPTION=true       # Require secret encryption
SEC_REQUIRE_SECRET_ROTATION=true         # Require secret rotation

# Image and dependency scanning
SEC_OPERATOR_IMAGE=n8n-eks-operator:latest  # Operator image to scan
SEC_SCAN_CONTAINER_IMAGES=true           # Enable container image scanning
SEC_SCAN_DEPENDENCIES=true               # Enable dependency scanning
SEC_REQUIRE_SIGNED_IMAGES=false          # Require signed container images
```

## Running Tests

### Prerequisites

1. **Go 1.19+** - Required for running tests
2. **kubectl** - For Kubernetes cluster analysis (optional)
3. **Trivy** - For vulnerability scanning (optional)
4. **govulncheck** - For Go dependency scanning (optional)

### Quick Start

```bash
# Check dependencies
make check-deps

# Run all security tests
make test

# Run specific test categories
make test-secrets          # Secret management tests
make test-network          # Network security tests
make test-rbac            # RBAC tests
make test-pod-security    # Pod security tests
make test-vulnerabilities # Vulnerability tests
make test-compliance      # Compliance tests
```

### Security Profiles

```bash
# Run tests with different security profiles
make test-basic           # Basic security requirements
make test-standard        # Standard security requirements
make test-strict          # Strict security requirements
make test-compliance-full # Full compliance requirements
```

### Compliance Testing

```bash
# Run specific compliance tests
make test-soc2           # SOC 2 compliance
make test-gdpr           # GDPR compliance
make test-hipaa          # HIPAA compliance
make test-pcidss         # PCI DSS compliance
make test-cis            # CIS Kubernetes Benchmark
```

### Vulnerability Scanning

```bash
# Scan container images
make scan-images

# Scan Go dependencies
make scan-dependencies

# Run all vulnerability scans
make scan-all
```

### Security Analysis

```bash
# Analyze RBAC configurations
make analyze-rbac

# Analyze network policies
make analyze-network-policies

# Analyze pod security
make analyze-pod-security

# Analyze secret configurations
make analyze-secrets

# Complete security audit
make security-audit
```

## Security Controls

### Required Security Controls

The test suite validates the following security controls:

#### Pod Security
- ✅ Non-root execution
- ✅ Read-only root filesystem
- ✅ Resource limits and requests
- ✅ Security contexts
- ✅ No privileged containers
- ✅ No privilege escalation
- ✅ Capability dropping

#### Network Security
- ✅ Network policies
- ✅ Default deny-all policy
- ✅ Ingress/egress restrictions
- ✅ Service mesh security (if applicable)

#### RBAC Security
- ✅ Minimal permissions
- ✅ No cluster-admin bindings
- ✅ Service account restrictions
- ✅ Role-based access control

#### Secret Management
- ✅ Secret encryption at rest
- ✅ Secret encryption in transit
- ✅ Secret rotation
- ✅ Access control

#### Compliance Controls
- ✅ Audit logging
- ✅ Log integrity
- ✅ Data protection
- ✅ Incident response
- ✅ Access monitoring

### Security Benchmarks

Performance benchmarks for security operations:

```bash
# Benchmark encryption operations
make benchmark-encryption

# Benchmark RBAC operations
make benchmark-rbac

# Benchmark network operations
make benchmark-network
```

## Compliance Requirements

### SOC 2 Type II

**Common Criteria (CC) Requirements:**
- CC6.1: Logical and Physical Access Controls
- CC6.2: Authentication and Authorization
- CC6.3: System Access Monitoring
- CC7.1: System Boundaries and Data Classification
- CC7.2: Data Transmission and Disposal

**Trust Services Criteria:**
- Security: Information and systems are protected
- Availability: Information and systems are available for operation
- Processing Integrity: System processing is complete, valid, accurate, timely, and authorized
- Confidentiality: Information designated as confidential is protected
- Privacy: Personal information is collected, used, retained, disclosed, and disposed of in conformity with commitments

### GDPR (General Data Protection Regulation)

**Key Requirements:**
- Article 25: Data Protection by Design and by Default
- Article 32: Security of Processing
- Article 33: Notification of Personal Data Breach
- Article 35: Data Protection Impact Assessment

**Technical Measures:**
- Pseudonymisation and encryption of personal data
- Ongoing confidentiality, integrity, availability and resilience
- Regular testing, assessing and evaluating effectiveness
- Process for regularly testing, assessing and evaluating

### CIS Kubernetes Benchmark

**Control Areas:**
- 5.1: RBAC and Service Accounts
- 5.2: Pod Security Policies / Pod Security Standards
- 5.3: Network Policies and CNI
- 5.7: General Policies

**Key Controls:**
- Minimize access to secrets
- Minimize wildcard use in Roles and ClusterRoles
- Minimize the admission of privileged containers
- Minimize the admission of containers with allowPrivilegeEscalation
- Minimize the admission of root containers
- Minimize the admission of containers with dangerous capabilities

## Reporting

### Generate Reports

```bash
# Generate security report
make report

# Generate HTML security report
make report-html

# Generate compliance report
make report-compliance

# Generate vulnerability report
make report-vulnerabilities
```

### Sample Security Report

```
# Security Test Report
Generated on: 2024-01-15 10:30:00

## Configuration
- Security Profile: standard
- Compliance Standards: SOC2,GDPR,CIS
- Timeout: 30m

## Test Results
✅ Secret Management: PASSED
✅ Network Security: PASSED
✅ RBAC Configuration: PASSED
✅ Pod Security Standards: PASSED
⚠️  Vulnerability Scanning: 3 medium vulnerabilities found
✅ Compliance Checks: PASSED

## Vulnerability Summary
- Critical: 0
- High: 0
- Medium: 3
- Low: 12

## Compliance Status
- SOC 2: COMPLIANT
- GDPR: COMPLIANT
- CIS Kubernetes: COMPLIANT

## Recommendations
1. Update dependencies to fix medium vulnerabilities
2. Enable additional network policies for worker components
3. Implement secret rotation for database credentials
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Tests
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v3
        with:
          go-version: '1.19'
      
      - name: Install Security Tools
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
      
      - name: Run Security Tests
        run: |
          cd test/security
          make test-ci
      
      - name: Run Vulnerability Scans
        run: |
          cd test/security
          make scan-ci
      
      - name: Run Compliance Tests
        run: |
          cd test/security
          make compliance-ci
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-results
          path: |
            test/security/security-results.json
            test/security/vulnerability-scan-results.txt
            test/security/compliance-results.txt
```

## Troubleshooting

### Common Issues

1. **Test Timeouts**
   ```bash
   # Increase timeout
   SEC_TEST_TIMEOUT=60m make test
   ```

2. **Vulnerability Scanner Not Found**
   ```bash
   # Install Trivy
   curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
   
   # Install govulncheck
   go install golang.org/x/vuln/cmd/govulncheck@latest
   ```

3. **Kubernetes Access Issues**
   ```bash
   # Check kubectl access
   kubectl cluster-info
   
   # Check permissions
   kubectl auth can-i get pods --all-namespaces
   ```

4. **Compliance Test Failures**
   ```bash
   # Check specific compliance requirements
   make test-soc2
   make test-gdpr
   make test-cis
   ```

### Security Best Practices

1. **Regular Testing**: Run security tests in CI/CD pipelines
2. **Vulnerability Management**: Regularly scan for vulnerabilities
3. **Compliance Monitoring**: Continuously monitor compliance status
4. **Security Metrics**: Track security metrics and trends
5. **Incident Response**: Have procedures for security incidents

## Contributing

### Adding New Security Tests

1. Add test methods to `SecurityTestSuite` in `security_test.go`
2. Create helper functions in `security_helpers.go`
3. Add compliance checks in `compliance.go`
4. Update configuration in `config.go`
5. Add Makefile targets for convenience
6. Document new tests in this README

### Security Test Guidelines

- Follow security testing best practices
- Use realistic security scenarios
- Include both positive and negative test cases
- Validate security controls thoroughly
- Document security requirements clearly
- Include compliance mapping where applicable

## Security Resources

### Documentation
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

### Tools
- [Trivy](https://github.com/aquasecurity/trivy) - Vulnerability scanner
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) - Go vulnerability checker
- [kube-bench](https://github.com/aquasecurity/kube-bench) - CIS Kubernetes Benchmark
- [kube-hunter](https://github.com/aquasecurity/kube-hunter) - Kubernetes penetration testing

### Compliance Frameworks
- [SOC 2](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html)
- [GDPR](https://gdpr.eu/)
- [HIPAA](https://www.hhs.gov/hipaa/index.html)
- [PCI DSS](https://www.pcisecuritystandards.org/)
- [CIS Controls](https://www.cisecurity.org/controls/)