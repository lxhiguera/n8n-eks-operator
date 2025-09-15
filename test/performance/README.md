# Performance Tests for n8n EKS Operator

This directory contains comprehensive performance and load tests for the n8n EKS Operator. These tests are designed to measure and validate the operator's performance characteristics under various load conditions.

## Overview

The performance test suite includes:

- **Reconciliation Performance Tests**: Measure single and concurrent reconciliation performance
- **Load Tests**: Sustained load testing with configurable concurrency
- **Benchmark Tests**: Go benchmark tests for specific operations
- **Resource Usage Monitoring**: CPU and memory usage tracking
- **Throughput Analysis**: Operations per second measurements
- **Latency Analysis**: P50, P95, P99 latency measurements

## Test Structure

### Test Files

- `performance_test.go` - Main performance test suite
- `benchmark_test.go` - Go benchmark tests
- `config.go` - Configuration management
- `metrics.go` - Performance metrics collection and analysis
- `Makefile` - Build and execution targets
- `README.md` - This documentation

### Test Categories

#### 1. Reconciliation Performance Tests

- **Single Reconciliation**: Measures time for a single N8nInstance reconciliation
- **Concurrent Reconciliation**: Tests multiple simultaneous reconciliations
- **Iteration Testing**: Repeated reconciliations to measure consistency
- **Load Testing**: Sustained load over extended periods

#### 2. Benchmark Tests

- **Creation Benchmark**: N8nInstance creation performance
- **Update Benchmark**: N8nInstance update performance
- **Retrieval Benchmark**: N8nInstance GET operations
- **List Benchmark**: N8nInstance LIST operations
- **Deletion Benchmark**: N8nInstance deletion performance
- **Concurrent Operations**: Parallel operation performance
- **Validation Webhook**: Webhook validation performance
- **Status Updates**: Status update performance

## Configuration

### Environment Variables

Performance tests can be configured using environment variables:

```bash
# Test execution settings
PERF_TEST_TIMEOUT=60m                    # Overall test timeout
PERF_CONCURRENT_INSTANCES=10             # Number of concurrent instances
PERF_RECONCILE_ITERATIONS=50             # Number of reconciliation iterations

# Performance thresholds
PERF_MAX_RECONCILE_TIME=30s              # Maximum acceptable reconcile time
PERF_MAX_MEMORY_MB=512                   # Maximum memory usage (MB)
PERF_MAX_CPU_PERCENT=80.0                # Maximum CPU usage (%)

# Load test settings
PERF_LOAD_TEST_DURATION=5m               # Load test duration
PERF_LOAD_TEST_CONCURRENCY=5             # Load test concurrency
PERF_LOAD_TEST_RAMPUP=30s                # Ramp-up time

# Benchmark settings
PERF_BENCHMARK_ITERATIONS=100            # Number of benchmark iterations
PERF_BENCHMARK_WARMUP=10s                # Benchmark warmup time
```

### Test Scenarios

The test suite includes predefined scenarios:

#### Light Load Scenario
```bash
PERF_CONCURRENT_INSTANCES=5
PERF_RECONCILE_ITERATIONS=20
PERF_LOAD_TEST_DURATION=2m
PERF_LOAD_TEST_CONCURRENCY=2
```

#### Medium Load Scenario
```bash
PERF_CONCURRENT_INSTANCES=15
PERF_RECONCILE_ITERATIONS=50
PERF_LOAD_TEST_DURATION=5m
PERF_LOAD_TEST_CONCURRENCY=5
```

#### Heavy Load Scenario
```bash
PERF_CONCURRENT_INSTANCES=50
PERF_RECONCILE_ITERATIONS=100
PERF_LOAD_TEST_DURATION=10m
PERF_LOAD_TEST_CONCURRENCY=10
```

#### Burst Load Scenario
```bash
PERF_CONCURRENT_INSTANCES=100
PERF_RECONCILE_ITERATIONS=200
PERF_LOAD_TEST_DURATION=3m
PERF_LOAD_TEST_CONCURRENCY=20
```

## Running Tests

### Prerequisites

1. **Go 1.19+** - Required for running tests
2. **Sufficient system resources** - Tests can be resource-intensive
3. **Test environment** - Either envtest or real Kubernetes cluster

### Quick Start

```bash
# Run all performance tests
make test

# Run specific test categories
make test-reconcile      # Reconciliation performance
make test-concurrent     # Concurrent operations
make test-load          # Load testing

# Run benchmarks
make bench              # All benchmarks
make bench-create       # Creation benchmarks
make bench-update       # Update benchmarks
```

### Load Testing Scenarios

```bash
# Predefined load scenarios
make load-light         # Light load (5 instances, 2m duration)
make load-medium        # Medium load (15 instances, 5m duration)
make load-heavy         # Heavy load (50 instances, 10m duration)
make load-burst         # Burst load (100 instances, 3m duration)
```

### Profiling

```bash
# CPU profiling
make profile-cpu

# Memory profiling
make profile-mem

# Execution tracing
make profile-trace

# All profiling
make profile-all

# Analyze profiles
make analyze-cpu
make analyze-mem
make analyze-trace
```

## Performance Metrics

### Reconciliation Metrics

- **Reconcile Time**: Time taken for complete reconciliation
- **Throughput**: Reconciliations per second
- **Error Rate**: Percentage of failed reconciliations
- **Latency Percentiles**: P50, P95, P99 reconciliation times

### Resource Metrics

- **CPU Usage**: Percentage CPU utilization
- **Memory Usage**: Memory consumption in MB
- **Goroutine Count**: Number of active goroutines
- **GC Metrics**: Garbage collection statistics

### Benchmark Metrics

- **Operations/sec**: Benchmark operations per second
- **ns/op**: Nanoseconds per operation
- **B/op**: Bytes allocated per operation
- **allocs/op**: Allocations per operation

## Performance Thresholds

### Light Load Thresholds
```yaml
max_reconcile_time_p50: 5s
max_reconcile_time_p95: 15s
max_reconcile_time_p99: 30s
min_throughput_rps: 2.0
max_error_rate: 1%
max_memory_usage_mb: 512
max_cpu_usage_percent: 50%
```

### Medium Load Thresholds
```yaml
max_reconcile_time_p50: 10s
max_reconcile_time_p95: 30s
max_reconcile_time_p99: 60s
min_throughput_rps: 1.5
max_error_rate: 2%
max_memory_usage_mb: 1024
max_cpu_usage_percent: 70%
```

### Heavy Load Thresholds
```yaml
max_reconcile_time_p50: 20s
max_reconcile_time_p95: 60s
max_reconcile_time_p99: 120s
min_throughput_rps: 1.0
max_error_rate: 5%
max_memory_usage_mb: 2048
max_cpu_usage_percent: 85%
```

## Reporting

### Generate Reports

```bash
# Text report
make report

# HTML report
make report-html

# Benchmark comparison
make compare-bench

# Save baseline for future comparisons
make save-baseline
```

### Sample Report Output

```
=== Performance Test Results ===
Reconciliation Times:
  Count: 100
  Min: 1.2s
  Max: 8.5s
  Mean: 3.2s
  Median: 2.8s
  P95: 6.1s
  P99: 7.8s
  StdDev: 1.4s

Throughput: 2.34 reconciliations/sec
Error Rate: 0.50%

Memory Usage (MB):
  Min: 45.2
  Max: 128.7
  Mean: 78.3
  P95: 115.4

CPU Usage (%):
  Min: 12.5
  Max: 67.8
  Mean: 34.2
  P95: 58.9
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Performance Tests
on: [push, pull_request]

jobs:
  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v3
        with:
          go-version: '1.19'
      
      - name: Run Performance Tests
        run: |
          cd test/performance
          make test-ci
      
      - name: Run Benchmarks
        run: |
          cd test/performance
          make bench-ci
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: performance-results
          path: |
            test/performance/performance-results.json
            test/performance/benchmark-ci.txt
```

### Performance Regression Detection

```bash
# Save baseline after successful release
make bench
make save-baseline

# Compare current performance with baseline
make bench
make compare-bench

# Check for regressions (example thresholds)
# - Reconcile time increase > 20%
# - Throughput decrease > 15%
# - Memory usage increase > 30%
```

## Troubleshooting

### Common Issues

1. **High Memory Usage**
   ```bash
   # Profile memory usage
   make profile-mem
   make analyze-mem
   
   # Check for memory leaks
   go tool pprof -alloc_space mem.prof
   ```

2. **Slow Reconciliation**
   ```bash
   # Profile CPU usage
   make profile-cpu
   make analyze-cpu
   
   # Check for bottlenecks
   go tool pprof -top cpu.prof
   ```

3. **Test Timeouts**
   ```bash
   # Increase timeout
   PERF_TEST_TIMEOUT=120m make test
   
   # Reduce load
   PERF_CONCURRENT_INSTANCES=5 make test
   ```

4. **Resource Exhaustion**
   ```bash
   # Monitor system resources
   top -p $(pgrep -f "performance.test")
   
   # Reduce test intensity
   make load-light
   ```

### Performance Optimization Tips

1. **Reconciliation Optimization**
   - Implement efficient resource diffing
   - Use client-side caching
   - Batch API operations
   - Optimize status updates

2. **Memory Optimization**
   - Avoid memory leaks in controllers
   - Use object pools for frequent allocations
   - Implement proper cleanup in finalizers
   - Monitor goroutine lifecycle

3. **CPU Optimization**
   - Optimize hot paths in reconciliation
   - Use efficient data structures
   - Minimize reflection usage
   - Implement proper rate limiting

## Best Practices

### Test Design

1. **Realistic Workloads**: Design tests that reflect real-world usage patterns
2. **Gradual Load Increase**: Use ramp-up periods to avoid overwhelming the system
3. **Baseline Comparisons**: Maintain performance baselines for regression detection
4. **Resource Monitoring**: Monitor system resources during tests

### Performance Analysis

1. **Multiple Metrics**: Don't rely on a single performance metric
2. **Statistical Significance**: Run tests multiple times for statistical validity
3. **Environment Consistency**: Use consistent test environments
4. **Bottleneck Identification**: Use profiling to identify performance bottlenecks

### Continuous Monitoring

1. **Regular Testing**: Run performance tests regularly in CI/CD
2. **Trend Analysis**: Track performance trends over time
3. **Alert Thresholds**: Set up alerts for performance regressions
4. **Capacity Planning**: Use performance data for capacity planning

## Contributing

### Adding New Tests

1. Add test methods to `PerformanceTestSuite` in `performance_test.go`
2. Create benchmark functions in `benchmark_test.go`
3. Update configuration in `config.go` if needed
4. Add new Makefile targets for convenience
5. Document new tests in this README

### Performance Test Guidelines

- Use realistic test data and scenarios
- Include proper setup and cleanup
- Add timeout contexts for all operations
- Use statistical analysis for results
- Document expected performance characteristics
- Include both positive and negative test cases