# n8n EKS Operator

[![Go Report Card](https://goreportcard.com/badge/github.com/lxhiguera/n8n-eks-operator)](https://goreportcard.com/report/github.com/lxhiguera/n8n-eks-operator)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Release](https://img.shields.io/github/release/lxhiguera/n8n-eks-operator.svg)](https://github.com/lxhiguera/n8n-eks-operator/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/n8nio/n8n-eks-operator.svg)](https://hub.docker.com/r/n8nio/n8n-eks-operator)

A Kubernetes operator for managing n8n workflow automation instances on Amazon EKS with full AWS integration.

## 🚀 Features

- **Complete n8n Lifecycle Management**: Deploy, scale, update, and monitor n8n instances
- **AWS Native Integration**: RDS PostgreSQL, ElastiCache Redis, S3 storage, CloudFront CDN
- **High Availability**: Multi-AZ deployments with automatic failover
- **Auto-scaling**: Horizontal Pod Autoscaler with custom metrics
- **Security First**: Pod Security Standards, Network Policies, RBAC, secrets encryption
- **Observability**: Prometheus metrics, Grafana dashboards, CloudWatch integration
- **Service Mesh Ready**: Istio integration with mTLS and traffic management
- **GitOps Compatible**: Declarative configuration with Kubernetes CRDs

## 📋 Prerequisites

- **Kubernetes**: 1.24+ (Amazon EKS recommended)
- **Helm**: 3.8+
- **AWS CLI**: 2.0+ (configured with appropriate permissions)
- **kubectl**: 1.24+

### Required AWS Services

- **Amazon EKS**: Kubernetes cluster
- **AWS Load Balancer Controller**: For ingress management
- **Amazon RDS**: PostgreSQL database (optional, can use external)
- **Amazon ElastiCache**: Redis cache (optional, can use external)
- **Amazon S3**: Object storage for workflows and assets
- **Amazon Route53**: DNS management (optional)
- **AWS Certificate Manager**: SSL/TLS certificates (optional)

### Optional Dependencies

- **cert-manager**: For automatic TLS certificate management
- **Prometheus Operator**: For monitoring and alerting
- **Istio**: For service mesh capabilities
- **Grafana**: For visualization dashboards

## 🛠️ Installation

### Quick Start

```bash
# Add the Helm repository
helm repo add n8n-operator https://charts.lxhiguera.io
helm repo update

# Install the operator
helm install n8n-operator n8n-operator/n8n-eks-operator \
  --namespace n8n-system \
  --create-namespace \
  --set aws.region=us-west-2 \
  --set aws.cluster.name=my-eks-cluster
```

### Production Installation

```bash
# Create values file for production
cat > values-production.yaml << EOF
operator:
  replicaCount: 2
  resources:
    limits:
      cpu: 1000m
      memory: 1Gi
    requests:
      cpu: 200m
      memory: 256Mi

aws:
  region: us-west-2
  cluster:
    name: production-eks
  serviceAccount:
    roleArn: arn:aws:iam::123456789012:role/n8n-operator-role

monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
  prometheusRule:
    enabled: true

webhook:
  enabled: true
  certificate:
    certManager:
      enabled: true
      issuer: letsencrypt-prod

networkPolicy:
  enabled: true

podSecurityStandards:
  enforce: restricted
EOF

# Install with production configuration
helm install n8n-operator n8n-operator/n8n-eks-operator \
  --namespace n8n-system \
  --create-namespace \
  -f values-production.yaml
```

## 📖 Usage

### Creating Your First n8n Instance

After installing the operator, create an n8n instance using the `N8nInstance` custom resource:

```yaml
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: my-n8n
  namespace: default
spec:
  version: "1.0.0"
  domain: "workflows.example.com"
  
  # Component configuration
  components:
    main:
      replicas: 2
      resources:
        requests:
          cpu: "200m"
          memory: "256Mi"
        limits:
          cpu: "1000m"
          memory: "1Gi"
    webhook:
      replicas: 1
      resources:
        requests:
          cpu: "100m"
          memory: "128Mi"
    worker:
      replicas: 3
      resources:
        requests:
          cpu: "150m"
          memory: "192Mi"
  
  # Database configuration
  database:
    type: "rds"
    host: "n8n-db.cluster-xxx.us-west-2.rds.amazonaws.com"
    port: 5432
    name: "n8n"
    credentialsSecret: "n8n-db-credentials"
    ssl: true
  
  # Cache configuration
  cache:
    type: "elasticache"
    host: "n8n-redis.xxx.cache.amazonaws.com"
    port: 6379
    credentialsSecret: "n8n-redis-credentials"
  
  # Storage configuration
  storage:
    s3:
      bucket: "my-n8n-workflows"
      region: "us-west-2"
    persistent:
      storageClass: "gp3"
      size: "10Gi"
  
  # Monitoring
  monitoring:
    metrics:
      enabled: true
      prometheus:
        enabled: true
    logging:
      level: "info"
  
  # Security
  security:
    podSecurityStandard: "restricted"
    networkPolicies:
      enabled: true
```

Apply the configuration:

```bash
kubectl apply -f my-n8n-instance.yaml
```

### Monitoring Your Instance

```bash
# Check instance status
kubectl get n8ninstance my-n8n -o yaml

# View operator logs
kubectl logs -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator

# Check created resources
kubectl get all -l app.kubernetes.io/managed-by=n8n-eks-operator

# View events
kubectl get events --field-selector involvedObject.kind=N8nInstance
```

## 🏗️ Architecture

The n8n EKS Operator follows the Kubernetes Operator pattern and manages the complete lifecycle of n8n instances:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Amazon EKS Cluster                       │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   n8n Main      │  │  n8n Webhook    │  │   n8n Worker    │ │
│  │   (UI/API)      │  │   (Webhooks)    │  │  (Execution)    │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│           │                     │                     │         │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              AWS Load Balancer Controller                   │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
           │                     │                     │
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   Amazon RDS    │  │ Amazon ElastiCache│  │   Amazon S3     │
│  (PostgreSQL)   │  │     (Redis)     │  │   (Storage)     │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

### Components

- **n8n Main**: Web UI and API server
- **n8n Webhook**: Handles incoming webhooks
- **n8n Worker**: Executes workflows
- **Database Manager**: Manages RDS PostgreSQL connections
- **Cache Manager**: Manages ElastiCache Redis connections
- **Storage Manager**: Manages S3 buckets and CloudFront distributions
- **Network Manager**: Manages DNS, SSL certificates, and Istio configuration
- **Security Manager**: Manages RBAC, secrets, and network policies
- **Monitoring Manager**: Manages metrics, logging, and alerting

## 🔧 Configuration

### Environment Variables

The operator supports the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_REGION` | AWS region | `""` |
| `AWS_ROLE_ARN` | IAM role ARN for IRSA | `""` |
| `LOG_LEVEL` | Log level (debug, info, warn, error) | `info` |
| `METRICS_BIND_ADDRESS` | Metrics server bind address | `:8080` |
| `HEALTH_PROBE_BIND_ADDRESS` | Health probe bind address | `:8081` |
| `WEBHOOK_PORT` | Webhook server port | `9443` |
| `LEADER_ELECT` | Enable leader election | `true` |

### AWS IAM Permissions

The operator requires the following AWS permissions:

<details>
<summary>Click to expand IAM policy</summary>

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBClusters",
        "rds:DescribeDBInstances",
        "rds:DescribeDBSubnetGroups",
        "rds:DescribeDBParameterGroups",
        "rds:CreateDBCluster",
        "rds:CreateDBInstance",
        "rds:ModifyDBCluster",
        "rds:ModifyDBInstance",
        "rds:DeleteDBCluster",
        "rds:DeleteDBInstance"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "elasticache:DescribeCacheClusters",
        "elasticache:DescribeReplicationGroups",
        "elasticache:DescribeCacheSubnetGroups",
        "elasticache:DescribeCacheParameterGroups",
        "elasticache:CreateCacheCluster",
        "elasticache:CreateReplicationGroup",
        "elasticache:ModifyCacheCluster",
        "elasticache:ModifyReplicationGroup",
        "elasticache:DeleteCacheCluster",
        "elasticache:DeleteReplicationGroup"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning",
        "s3:ListBucket",
        "s3:PutBucketPolicy",
        "s3:PutBucketVersioning",
        "s3:PutBucketEncryption",
        "s3:PutBucketLifecycleConfiguration",
        "s3:PutBucketCORS"
      ],
      "Resource": "arn:aws:s3:::n8n-*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "cloudfront:CreateDistribution",
        "cloudfront:GetDistribution",
        "cloudfront:UpdateDistribution",
        "cloudfront:DeleteDistribution",
        "cloudfront:CreateOriginAccessIdentity",
        "cloudfront:GetOriginAccessIdentity",
        "cloudfront:DeleteOriginAccessIdentity"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "route53:ChangeResourceRecordSets",
        "route53:GetHostedZone",
        "route53:ListHostedZones",
        "route53:ListResourceRecordSets"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "acm:RequestCertificate",
        "acm:DescribeCertificate",
        "acm:ListCertificates",
        "acm:DeleteCertificate"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:UpdateSecret",
        "secretsmanager:DeleteSecret",
        "secretsmanager:RotateSecret"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:n8n/*"
    }
  ]
}
```

</details>

## 📊 Monitoring and Observability

### Metrics

The operator exposes Prometheus metrics on port 8080:

- `n8n_instances_total`: Total number of N8nInstance resources
- `n8n_instances_ready`: Number of ready N8nInstance resources
- `n8n_reconcile_duration_seconds`: Time spent reconciling resources
- `n8n_reconcile_errors_total`: Total reconciliation errors
- `n8n_aws_api_calls_total`: Total AWS API calls
- `n8n_aws_api_errors_total`: Total AWS API errors

### Logging

Structured logging with configurable levels:

```bash
# Enable debug logging
kubectl patch deployment n8n-eks-operator-controller-manager \
  -n n8n-system \
  --type='json' \
  -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/env/0/value", "value": "debug"}]'
```

### Alerting

Pre-configured Prometheus alerts:

- **N8nOperatorDown**: Operator is not running
- **N8nInstanceNotReady**: N8nInstance is not ready
- **N8nHighErrorRate**: High error rate in reconciliation
- **N8nAWSAPIErrors**: AWS API errors detected

## 🔒 Security

### Pod Security Standards

The operator enforces Pod Security Standards:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: n8n-production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### Network Policies

Network policies restrict traffic between components:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: n8n-network-policy
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: n8n
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: aws-load-balancer-controller
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 5432  # PostgreSQL
    - protocol: TCP
      port: 6379  # Redis
    - protocol: TCP
      port: 443   # HTTPS
```

### Secrets Management

Secrets are encrypted at rest and rotated automatically:

```bash
# Create database credentials secret
kubectl create secret generic n8n-db-credentials \
  --from-literal=username=n8n \
  --from-literal=password=secure-password \
  --from-literal=host=n8n-db.cluster-xxx.us-west-2.rds.amazonaws.com \
  --from-literal=port=5432 \
  --from-literal=database=n8n
```

## 🚀 Advanced Usage

### Multi-Environment Setup

<details>
<summary>Development Environment</summary>

```yaml
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: n8n-dev
  namespace: development
spec:
  version: "1.0.0"
  domain: "n8n-dev.example.com"
  components:
    main:
      replicas: 1
      resources:
        requests:
          cpu: "100m"
          memory: "128Mi"
        limits:
          cpu: "500m"
          memory: "512Mi"
  database:
    type: "rds"
    host: "n8n-dev-db.cluster-xxx.us-west-2.rds.amazonaws.com"
    port: 5432
    name: "n8n_dev"
    credentialsSecret: "n8n-dev-db-credentials"
  storage:
    s3:
      bucket: "n8n-dev-workflows"
      region: "us-west-2"
  monitoring:
    logging:
      level: "debug"
```

</details>

<details>
<summary>Staging Environment</summary>

```yaml
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: n8n-staging
  namespace: staging
spec:
  version: "1.0.0"
  domain: "n8n-staging.example.com"
  components:
    main:
      replicas: 2
      resources:
        requests:
          cpu: "200m"
          memory: "256Mi"
        limits:
          cpu: "1000m"
          memory: "1Gi"
    webhook:
      replicas: 1
    worker:
      replicas: 2
  database:
    type: "rds"
    host: "n8n-staging-db.cluster-xxx.us-west-2.rds.amazonaws.com"
    port: 5432
    name: "n8n_staging"
    credentialsSecret: "n8n-staging-db-credentials"
    ssl: true
  cache:
    type: "elasticache"
    host: "n8n-staging-redis.xxx.cache.amazonaws.com"
    port: 6379
  storage:
    s3:
      bucket: "n8n-staging-workflows"
      region: "us-west-2"
    persistent:
      storageClass: "gp3"
      size: "20Gi"
  monitoring:
    metrics:
      enabled: true
    logging:
      level: "info"
  security:
    podSecurityStandard: "restricted"
    networkPolicies:
      enabled: true
```

</details>

<details>
<summary>Production Environment</summary>

```yaml
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: n8n-production
  namespace: production
spec:
  version: "1.0.0"
  domain: "workflows.company.com"
  components:
    main:
      replicas: 3
      resources:
        requests:
          cpu: "500m"
          memory: "1Gi"
        limits:
          cpu: "2000m"
          memory: "4Gi"
      autoscaling:
        enabled: true
        minReplicas: 3
        maxReplicas: 10
        targetCPU: 70
    webhook:
      replicas: 2
      resources:
        requests:
          cpu: "200m"
          memory: "256Mi"
        limits:
          cpu: "1000m"
          memory: "1Gi"
      autoscaling:
        enabled: true
        minReplicas: 2
        maxReplicas: 8
    worker:
      replicas: 5
      resources:
        requests:
          cpu: "300m"
          memory: "512Mi"
        limits:
          cpu: "1500m"
          memory: "2Gi"
      autoscaling:
        enabled: true
        minReplicas: 5
        maxReplicas: 20
        targetCPU: 80
  database:
    type: "rds"
    host: "n8n-prod.cluster-abc123.us-west-2.rds.amazonaws.com"
    port: 5432
    name: "n8n_production"
    credentialsSecret: "n8n-prod-db-credentials"
    ssl: true
    connectionPooling:
      enabled: true
      maxConnections: 100
  cache:
    type: "elasticache"
    host: "n8n-prod-redis.abc123.cache.amazonaws.com"
    port: 6379
    credentialsSecret: "n8n-prod-redis-credentials"
    ssl: true
  storage:
    s3:
      bucket: "n8n-production-workflows"
      region: "us-west-2"
      encryption: "AES256"
      versioning: true
    cloudfront:
      enabled: true
      domain: "cdn.workflows.company.com"
    persistent:
      storageClass: "gp3"
      size: "100Gi"
      autoExpansion: true
  networking:
    dns:
      provider: "route53"
      zoneId: "Z123456789"
    ssl:
      provider: "acm"
      certificateArn: "arn:aws:acm:us-west-2:123456789012:certificate/abc123"
    istio:
      enabled: true
      gateway: "n8n-gateway"
  monitoring:
    metrics:
      enabled: true
      prometheus:
        enabled: true
        serviceMonitor: true
      cloudwatch:
        enabled: true
        namespace: "N8N/Production"
    logging:
      level: "info"
      cloudwatch:
        enabled: true
        retention: 30
    alerts:
      enabled: true
      sns:
        topicArn: "arn:aws:sns:us-west-2:123456789012:n8n-alerts"
  security:
    podSecurityStandard: "restricted"
    networkPolicies:
      enabled: true
    rbac:
      enabled: true
    secrets:
      encryption: true
      rotation: true
```

</details>

## 🔧 Troubleshooting

### Common Issues

<details>
<summary>Operator Not Starting</summary>

**Symptoms**: Operator pods are in CrashLoopBackOff or Pending state

**Diagnosis**:
```bash
kubectl describe pod -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator
kubectl logs -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator
```

**Common Causes**:
- Missing RBAC permissions
- Invalid AWS credentials
- Image pull errors
- Resource constraints

**Solutions**:
```bash
# Check RBAC
kubectl auth can-i create n8ninstances --as=system:serviceaccount:n8n-system:n8n-eks-operator

# Verify AWS credentials
kubectl describe serviceaccount -n n8n-system n8n-eks-operator

# Check resource limits
kubectl describe node
```

</details>

<details>
<summary>N8nInstance Not Ready</summary>

**Symptoms**: N8nInstance status shows "Not Ready" or error conditions

**Diagnosis**:
```bash
kubectl describe n8ninstance my-n8n
kubectl get events --field-selector involvedObject.kind=N8nInstance
```

**Common Causes**:
- AWS service connectivity issues
- Invalid database credentials
- Network policy blocking traffic
- Resource constraints

**Solutions**:
```bash
# Check AWS connectivity
kubectl run aws-cli --rm -it --image=amazon/aws-cli -- aws sts get-caller-identity

# Verify database credentials
kubectl get secret n8n-db-credentials -o yaml

# Test network connectivity
kubectl run netshoot --rm -it --image=nicolaka/netshoot -- nslookup your-db-host
```

</details>

<details>
<summary>Webhook Certificate Issues</summary>

**Symptoms**: Webhook validation/mutation failures

**Diagnosis**:
```bash
kubectl get validatingwebhookconfiguration
kubectl get mutatingwebhookconfiguration
kubectl describe certificate -n n8n-system
```

**Solutions**:
```bash
# Recreate certificates
kubectl delete certificate -n n8n-system n8n-eks-operator-serving-cert

# Check cert-manager logs
kubectl logs -n cert-manager -l app=cert-manager
```

</details>

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
helm upgrade n8n-operator n8n-operator/n8n-eks-operator \
  --set logging.level=debug \
  --set logging.development=true \
  --reuse-values
```

### Health Checks

The operator provides health and readiness endpoints:

```bash
# Port forward to health endpoints
kubectl port-forward -n n8n-system svc/n8n-eks-operator-controller-manager 8081:8081

# Check health
curl http://localhost:8081/healthz
curl http://localhost:8081/readyz

# Check metrics
curl http://localhost:8081/metrics
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/lxhiguera/n8n-eks-operator.git
cd n8n-eks-operator

# Install dependencies
make deps

# Run tests
make test

# Build the operator
make build

# Run locally
make run
```

### Testing

```bash
# Unit tests
make test-unit

# Integration tests (requires AWS credentials)
make test-integration

# End-to-end tests (requires EKS cluster)
make test-e2e

# Security tests
make test-security

# Performance tests
make test-performance
```

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [https://github.com/lxhiguera/n8n-eks-operator/docs](https://github.com/lxhiguera/n8n-eks-operator/docs)
- **Issues**: [https://github.com/lxhiguera/n8n-eks-operator/issues](https://github.com/lxhiguera/n8n-eks-operator/issues)
- **Discussions**: [https://github.com/lxhiguera/n8n-eks-operator/discussions](https://github.com/lxhiguera/n8n-eks-operator/discussions)
- **Slack**: [n8n Community](https://n8n.io/slack)

## 🙏 Acknowledgments

- [n8n](https://n8n.io) - The workflow automation platform
- [Kubebuilder](https://kubebuilder.io) - SDK for building Kubernetes APIs
- [AWS Controllers for Kubernetes](https://aws-controllers-k8s.github.io/community/) - Inspiration for AWS integration patterns
- [Operator Framework](https://operatorframework.io) - Best practices for Kubernetes operators

---

Made with ❤️ by the n8n team and contributors.