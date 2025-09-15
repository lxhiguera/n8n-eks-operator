# End-to-End Tests for n8n EKS Operator

This directory contains comprehensive end-to-end (E2E) tests for the n8n EKS Operator. These tests validate the complete functionality of the operator from N8nInstance creation to deletion, including all intermediate states and operations.

## Overview

The E2E tests are designed to:

- Test the complete lifecycle of N8nInstance resources
- Validate custom configurations and scaling operations
- Test error handling and recovery scenarios
- Verify monitoring and observability features
- Ensure proper resource cleanup and finalizer behavior

## Test Structure

### Test Files

- `e2e_test.go` - Main test suite with core test cases
- `e2e_helpers.go` - Helper functions and utilities
- `Makefile` - Build and execution targets
- `README.md` - This documentation

### Test Cases

#### 1. N8nInstance Lifecycle Test (`TestN8nInstanceLifecycle`)

Tests the complete lifecycle of an N8nInstance:

- **Phase 1**: Creation and Initial Reconciliation
- **Phase 2**: Component Deployment (main, webhook, worker)
- **Phase 3**: Service Creation
- **Phase 4**: ConfigMaps and Secrets
- **Phase 5**: Ready State
- **Phase 6**: Health Checks
- **Phase 7**: Update Operations
- **Phase 8**: Scaling Operations
- **Phase 9**: Deletion and Cleanup

#### 2. Custom Configuration Test (`TestN8nInstanceWithCustomConfig`)

Tests N8nInstance with custom configuration:

- Custom replica counts
- Custom resource requirements
- Autoscaling configuration
- Storage specifications
- Monitoring settings

#### 3. Error Handling Test (`TestN8nInstanceErrorHandling`)

Tests error scenarios:

- Invalid configuration validation
- Webhook validation (if implemented)
- Error condition reporting
- Failed phase handling

#### 4. Monitoring Test (`TestN8nInstanceMonitoring`)

Tests monitoring and observability:

- Prometheus metrics services
- ServiceMonitor creation
- Grafana dashboard ConfigMaps
- CloudWatch integration (if configured)

## Running Tests

### Prerequisites

1. **Go 1.19+** - Required for running tests
2. **kubectl** - For cluster operations
3. **Kubernetes cluster** - Either real cluster or envtest

### Environment Variables

- `RUN_E2E_TESTS=true` - Enable E2E test execution
- `USE_REAL_CLUSTER=true/false` - Use real cluster vs envtest
- `KUBECONFIG` - Path to kubeconfig file
- `TEST_NAMESPACE` - Namespace for test resources

### Quick Start

```bash
# Run all E2E tests with envtest
make test

# Run tests against real cluster
make test-real

# Run specific test suite
make test-lifecycle
make test-custom
make test-error
make test-monitoring
```

### Detailed Commands

```bash
# Check dependencies
make check-deps

# Install dependencies
make install-deps

# Create test namespace
make create-namespace

# Run full test cycle
make full-test

# Debug tests
make debug-test

# Clean up resources
make cleanup-resources
```

## Test Modes

### 1. EnvTest Mode (Default)

Uses controller-runtime's envtest for isolated testing:

```bash
RUN_E2E_TESTS=true USE_REAL_CLUSTER=false make test
```

**Advantages:**
- Fast execution
- Isolated environment
- No external dependencies
- Suitable for CI/CD

**Limitations:**
- No real AWS services
- Limited networking features
- No actual container execution

### 2. Real Cluster Mode

Tests against a real Kubernetes cluster:

```bash
RUN_E2E_TESTS=true USE_REAL_CLUSTER=true make test-real
```

**Advantages:**
- Full functionality testing
- Real AWS service integration
- Complete networking validation
- Actual container execution

**Requirements:**
- Valid kubeconfig
- Cluster admin permissions
- n8n operator deployed
- AWS credentials (for AWS features)

## Test Configuration

### Test Instance Specifications

#### Basic Test Instance
```yaml
spec:
  version: "1.0.0"
  domain: "test.local"
  components:
    main:
      replicas: 1
      port: 5678
      resources:
        requests:
          cpu: "100m"
          memory: "128Mi"
```

#### Custom Test Instance
```yaml
spec:
  version: "1.0.0"
  domain: "custom.test.local"
  components:
    main:
      replicas: 2
      autoscaling:
        enabled: true
        minReplicas: 2
        maxReplicas: 5
        targetCPU: 70
    webhook:
      replicas: 3
      subdomain: "webhooks"
    worker:
      replicas: 2
  storage:
    persistent:
      type: "ebs-csi"
      storageClass: "gp3"
      size: "10Gi"
  monitoring:
    metrics:
      enabled: true
      prometheus:
        enabled: true
```

## Test Validation

### Resource Validation

Tests verify the creation and configuration of:

- **Deployments**: Correct replica counts, resource limits, labels
- **Services**: Proper port configuration, selectors, endpoints
- **ConfigMaps**: Configuration data, monitoring dashboards
- **Secrets**: Sensitive data handling (if applicable)
- **HPA**: Autoscaling configuration and targets
- **PVC**: Storage claims and specifications

### Status Validation

Tests verify N8nInstance status progression:

1. `Creating` - Initial reconciliation
2. `Progressing` - Components being deployed
3. `Ready` - All components healthy
4. `Failed` - Error conditions (for error tests)

### Condition Validation

Tests verify status conditions:

- `Ready` - Instance is fully operational
- `Progressing` - Deployment in progress
- `Available` - Services are accessible
- `Degraded` - Partial functionality (if applicable)

## Debugging Tests

### Viewing Test Resources

```bash
# Get all test resources
make get-resources

# Describe resources for debugging
make describe

# View logs from test pods
make logs
```

### Manual Debugging

```bash
# Connect to test namespace
kubectl config set-context --current --namespace=n8n-e2e-test

# Check N8nInstance status
kubectl get n8ninstances -o yaml

# Check operator logs
kubectl logs -l app.kubernetes.io/name=n8n-eks-operator -n n8n-system
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: E2E Tests
on: [push, pull_request]

jobs:
  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v3
        with:
          go-version: '1.19'
      
      - name: Run E2E Tests
        run: |
          cd test/e2e
          make test-ci
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: e2e-results
          path: test/e2e/e2e-results.json
```

### Coverage Reports

```bash
# Generate coverage report
make test-coverage

# View coverage in browser
open coverage.html
```

## Troubleshooting

### Common Issues

1. **Test Timeout**
   ```bash
   # Increase timeout
   TIMEOUT=60m make test
   ```

2. **Resource Conflicts**
   ```bash
   # Clean up before running
   make cleanup-resources
   make test
   ```

3. **Permission Issues**
   ```bash
   # Check cluster permissions
   kubectl auth can-i create n8ninstances
   kubectl auth can-i create deployments
   ```

4. **Operator Not Running**
   ```bash
   # Check operator status
   kubectl get pods -n n8n-system
   kubectl logs -l app.kubernetes.io/name=n8n-eks-operator -n n8n-system
   ```

### Test Failures

When tests fail:

1. Check the test output for specific error messages
2. Use `make describe` to see resource status
3. Use `make logs` to view pod logs
4. Check operator logs for reconciliation errors
5. Verify cluster has sufficient resources

### Performance Issues

For slow tests:

1. Reduce timeout values for faster feedback
2. Use parallel execution: `make test-parallel`
3. Run specific test suites instead of all tests
4. Use envtest mode for faster execution

## Contributing

### Adding New Tests

1. Add test methods to `E2ETestSuite` in `e2e_test.go`
2. Create helper functions in `e2e_helpers.go`
3. Update Makefile with new test targets
4. Document new tests in this README

### Test Guidelines

- Use descriptive test names
- Include proper setup and cleanup
- Add timeout contexts for all operations
- Use assertions for validation
- Log important test steps
- Handle both success and failure cases

### Code Style

- Follow Go testing conventions
- Use testify/suite for structured tests
- Include proper error handling
- Add comments for complex logic
- Use consistent naming patterns