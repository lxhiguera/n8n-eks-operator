# Integration Tests

This directory contains integration tests for the n8n EKS Operator that test against real AWS services.

## Overview

Integration tests validate that the operator works correctly with actual AWS services including:
- RDS PostgreSQL clusters
- ElastiCache Redis clusters  
- S3 buckets and CloudFront distributions
- AWS Secrets Manager
- Route53 DNS
- AWS Certificate Manager (ACM)

## Prerequisites

### AWS Configuration
1. Configure AWS credentials (via AWS CLI, environment variables, or IAM roles)
2. Ensure you have appropriate permissions for the AWS services being tested
3. Set up test resources in your AWS account (see Test Resources section)

### Environment Variables

#### Required for all tests:
```bash
export RUN_INTEGRATION_TESTS=true
export AWS_REGION=us-west-2  # or your preferred region
```

#### Optional test resource identifiers:
```bash
# RDS Integration Tests
export TEST_RDS_CLUSTER_ID=your-test-rds-cluster
export TEST_DB_SECRET_ARN=arn:aws:secretsmanager:region:account:secret:db-credentials

# ElastiCache Integration Tests  
export TEST_ELASTICACHE_CLUSTER_ID=your-test-redis-cluster
export TEST_CACHE_SECRET_ARN=arn:aws:secretsmanager:region:account:secret:redis-auth

# Route53 Integration Tests
export TEST_ROUTE53_HOSTED_ZONE_ID=Z1234567890ABC

# Test behavior configuration
export CLEANUP_TEST_RESOURCES=true  # Clean up created resources (default: true)
export SKIP_SLOW_TESTS=false        # Skip tests that take longer to run
```

## Test Resources

### RDS PostgreSQL Cluster
Create a test RDS Aurora PostgreSQL cluster:
```bash
aws rds create-db-cluster \
  --db-cluster-identifier n8n-test-cluster \
  --engine aurora-postgresql \
  --master-username postgres \
  --master-user-password YourSecurePassword123 \
  --database-name n8n \
  --storage-encrypted \
  --backup-retention-period 7
```

Store credentials in Secrets Manager:
```bash
aws secretsmanager create-secret \
  --name n8n-test-db-credentials \
  --description "Test database credentials for n8n operator" \
  --secret-string '{
    "username": "postgres",
    "password": "YourSecurePassword123", 
    "engine": "postgres",
    "host": "n8n-test-cluster.cluster-xyz.us-west-2.rds.amazonaws.com",
    "port": 5432,
    "dbname": "n8n"
  }'
```

### ElastiCache Redis Cluster
Create a test ElastiCache Redis cluster:
```bash
aws elasticache create-cache-cluster \
  --cache-cluster-id n8n-test-redis \
  --engine redis \
  --cache-node-type cache.t3.micro \
  --num-cache-nodes 1 \
  --auth-token YourRedisAuthToken123 \
  --transit-encryption-enabled \
  --at-rest-encryption-enabled
```

Store auth token in Secrets Manager:
```bash
aws secretsmanager create-secret \
  --name n8n-test-redis-auth \
  --description "Test Redis auth token for n8n operator" \
  --secret-string '{
    "auth_token": "YourRedisAuthToken123",
    "host": "n8n-test-redis.cache.amazonaws.com",
    "port": 6379
  }'
```

### Route53 Hosted Zone
Create a test hosted zone (or use existing):
```bash
aws route53 create-hosted-zone \
  --name test.example.com \
  --caller-reference $(date +%s)
```

## Running Tests

### Run all integration tests:
```bash
go test -tags=integration ./test/integration/...
```

### Run specific test suites:
```bash
# RDS tests only
go test -tags=integration ./test/integration/ -run TestRDS

# ElastiCache tests only  
go test -tags=integration ./test/integration/ -run TestElastiCache

# S3 tests only
go test -tags=integration ./test/integration/ -run TestS3
```

### Run with verbose output:
```bash
go test -tags=integration -v ./test/integration/...
```

### Skip slow tests:
```bash
SKIP_SLOW_TESTS=true go test -tags=integration ./test/integration/...
```

## Test Structure

### Test Categories

1. **Service Discovery Tests**: Validate that existing AWS resources can be discovered
2. **Connectivity Tests**: Test actual connections to AWS services  
3. **Configuration Tests**: Validate service configurations meet n8n requirements
4. **Credential Tests**: Test credential retrieval from Secrets Manager
5. **Manager Integration Tests**: Test operator managers with real AWS services

### Test Files

- `aws_integration_test.go` - Main integration test suite
- `config.go` - Test configuration and utilities
- `rds_test.go` - RDS PostgreSQL specific tests
- `elasticache_test.go` - ElastiCache Redis specific tests
- `s3_test.go` - S3 and CloudFront specific tests (future)
- `route53_test.go` - Route53 DNS specific tests (future)

## Test Safety

### Resource Management
- Tests use unique prefixes to avoid conflicts
- Cleanup functions remove created resources
- Tests are designed to be safe to run in shared AWS accounts
- No destructive operations on existing resources

### Cost Considerations
- Tests create minimal, short-lived resources
- Most tests use existing resources when possible
- Cleanup is automatic unless disabled
- Use smallest instance types for test resources

### Security
- Tests never expose credentials in logs
- All connections use encryption in transit
- Test resources follow security best practices
- Secrets are properly managed in AWS Secrets Manager

## Troubleshooting

### Common Issues

1. **AWS Credentials**: Ensure AWS credentials are properly configured
2. **Permissions**: Verify IAM permissions for all tested services
3. **Resource Availability**: Check that test resources exist and are available
4. **Network Connectivity**: Ensure network access to AWS services
5. **Region Mismatch**: Verify all resources are in the same AWS region

### Debug Mode
Enable debug logging:
```bash
export AWS_SDK_LOAD_CONFIG=1
export AWS_LOG_LEVEL=debug
go test -tags=integration -v ./test/integration/...
```

### Test Resource Validation
Validate test resources before running tests:
```bash
# Check RDS cluster
aws rds describe-db-clusters --db-cluster-identifier $TEST_RDS_CLUSTER_ID

# Check ElastiCache cluster  
aws elasticache describe-cache-clusters --cache-cluster-id $TEST_ELASTICACHE_CLUSTER_ID

# Check secrets
aws secretsmanager get-secret-value --secret-id $TEST_DB_SECRET_ARN
```

## Contributing

When adding new integration tests:

1. Follow the existing test structure and patterns
2. Add appropriate skip conditions for missing resources
3. Include cleanup functions for created resources
4. Add documentation for any new test resources required
5. Ensure tests are safe to run in shared environments
6. Add appropriate timeout handling for long-running operations