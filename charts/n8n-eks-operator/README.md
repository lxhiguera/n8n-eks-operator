# n8n EKS Operator Helm Chart

This Helm chart deploys the n8n EKS Operator on a Kubernetes cluster. The operator manages n8n workflow automation instances with full AWS integration.

## Prerequisites

- Kubernetes 1.24+
- Helm 3.8+
- AWS EKS cluster
- AWS Load Balancer Controller (for ingress)
- cert-manager (optional, for webhook certificates)
- Prometheus Operator (optional, for monitoring)

## Installation

### Quick Start

```bash
# Add the Helm repository
helm repo add n8n-operator https://lxhiguera.github.io/n8n-eks-operator
helm repo update

# Install the operator
helm install n8n-operator n8n-operator/n8n-eks-operator
```

### From Source

```bash
# Clone the repository
git clone https://github.com/n8n-io/n8n-eks-operator.git
cd n8n-eks-operator

# Install the chart
helm install n8n-operator ./charts/n8n-eks-operator
```

### Custom Installation

```bash
# Install with custom values
helm install n8n-operator ./charts/n8n-eks-operator \
  --set operator.image.tag=v1.0.0 \
  --set monitoring.enabled=true \
  --set webhook.enabled=true
```

## Configuration

### Basic Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.replicaCount` | Number of operator replicas | `1` |
| `operator.image.repository` | Operator image repository | `ghcr.io/n8n-io/n8n-eks-operator` |
| `operator.image.tag` | Operator image tag | `""` (uses appVersion) |
| `operator.image.pullPolicy` | Image pull policy | `IfNotPresent` |

### Resource Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.resources.limits.cpu` | CPU limit | `500m` |
| `operator.resources.limits.memory` | Memory limit | `512Mi` |
| `operator.resources.requests.cpu` | CPU request | `100m` |
| `operator.resources.requests.memory` | Memory request | `128Mi` |

### Autoscaling Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.autoscaling.enabled` | Enable HPA | `false` |
| `operator.autoscaling.minReplicas` | Minimum replicas | `1` |
| `operator.autoscaling.maxReplicas` | Maximum replicas | `3` |
| `operator.autoscaling.targetCPUUtilizationPercentage` | Target CPU % | `80` |
| `operator.autoscaling.targetMemoryUtilizationPercentage` | Target Memory % | `80` |

### Webhook Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `webhook.enabled` | Enable admission webhooks | `true` |
| `webhook.certificate.certManager.enabled` | Use cert-manager | `false` |
| `webhook.certificate.certManager.issuer` | cert-manager issuer | `""` |
| `webhook.certificate.selfSigned.enabled` | Use self-signed cert | `true` |
| `webhook.certificate.custom.enabled` | Use custom cert | `false` |
| `webhook.certificate.custom.secretName` | Custom cert secret | `""` |

### Monitoring Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `monitoring.enabled` | Enable monitoring | `false` |
| `monitoring.serviceMonitor.enabled` | Create ServiceMonitor | `false` |
| `monitoring.serviceMonitor.interval` | Scrape interval | `30s` |
| `monitoring.grafanaDashboard.enabled` | Create Grafana dashboard | `false` |

### Security Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `networkPolicies.enabled` | Enable network policies | `false` |
| `podSecurityStandards.enforce` | Pod Security Standard | `restricted` |
| `rbac.create` | Create RBAC resources | `true` |

### AWS Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `aws.region` | AWS region | `""` |
| `aws.cluster.name` | EKS cluster name | `""` |
| `aws.serviceAccount.roleArn` | IRSA role ARN | `""` |
| `aws.defaultTags` | Default AWS tags | `{}` |

## Environment-Specific Configurations

### Staging Environment

```bash
helm install n8n-operator ./charts/n8n-eks-operator \
  -f ./charts/n8n-eks-operator/values-staging.yaml
```

Key staging features:
- Debug logging enabled
- Autoscaling enabled for testing
- Self-signed certificates
- Comprehensive monitoring
- Network policies enabled

### Production Environment

```bash
helm install n8n-operator ./charts/n8n-eks-operator \
  -f ./charts/n8n-eks-operator/values-production.yaml
```

Key production features:
- High availability (2+ replicas)
- Resource limits optimized
- cert-manager integration
- Strict security policies
- Production monitoring
- Node affinity rules

## Examples

### Basic N8nInstance

After installing the operator, create an N8nInstance:

```yaml
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: my-n8n
  namespace: default
spec:
  version: "1.0.0"
  domain: "my-n8n.example.com"
  components:
    main:
      replicas: 2
      resources:
        requests:
          cpu: "200m"
          memory: "256Mi"
        limits:
          cpu: "500m"
          memory: "512Mi"
    webhook:
      replicas: 1
    worker:
      replicas: 3
  database:
    type: "rds"
    host: "my-postgres.cluster-xxx.us-west-2.rds.amazonaws.com"
    port: 5432
    name: "n8n"
    credentialsSecret: "n8n-db-credentials"
  cache:
    type: "elasticache"
    host: "my-redis.xxx.cache.amazonaws.com"
    port: 6379
  storage:
    s3:
      bucket: "my-n8n-storage"
      region: "us-west-2"
    persistent:
      storageClass: "gp3"
      size: "10Gi"
  monitoring:
    metrics:
      enabled: true
      prometheus:
        enabled: true
        serviceMonitor: true
    logging:
      level: "info"
  security:
    podSecurityStandard: "restricted"
    networkPolicies:
      enabled: true
```

### Advanced N8nInstance with Full Configuration

```yaml
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: advanced-n8n
  namespace: n8n-production
spec:
  version: "1.0.0"
  domain: "workflows.company.com"
  components:
    main:
      replicas: 3
      port: 5678
      subdomain: "app"
      resources:
        requests:
          cpu: "300m"
          memory: "512Mi"
        limits:
          cpu: "1000m"
          memory: "2Gi"
      autoscaling:
        enabled: true
        minReplicas: 3
        maxReplicas: 10
        targetCPU: 70
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        readOnlyRootFilesystem: true
    webhook:
      replicas: 2
      port: 5679
      subdomain: "webhooks"
      resources:
        requests:
          cpu: "200m"
          memory: "256Mi"
        limits:
          cpu: "500m"
          memory: "512Mi"
      autoscaling:
        enabled: true
        minReplicas: 2
        maxReplicas: 8
        targetCPU: 75
    worker:
      replicas: 5
      resources:
        requests:
          cpu: "250m"
          memory: "384Mi"
        limits:
          cpu: "750m"
          memory: "1Gi"
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
    credentialsSecret: "n8n-db-prod-credentials"
    ssl: true
    connectionPooling:
      enabled: true
      maxConnections: 100
      minConnections: 10
  cache:
    type: "elasticache"
    host: "n8n-prod-redis.abc123.cache.amazonaws.com"
    port: 6379
    credentialsSecret: "n8n-redis-prod-credentials"
    ssl: true
    ttl:
      default: "1h"
      sessions: "24h"
  storage:
    s3:
      bucket: "n8n-production-storage"
      region: "us-west-2"
      encryption: "AES256"
      versioning: true
      lifecyclePolicy: "30d"
    cloudfront:
      enabled: true
      domain: "cdn.workflows.company.com"
      certificateArn: "arn:aws:acm:us-east-1:ACCOUNT-ID:certificate/abc123"
    persistent:
      type: "ebs-csi"
      storageClass: "gp3"
      size: "50Gi"
      autoExpansion: true
      snapshotPolicy: "daily"
  networking:
    dns:
      provider: "route53"
      zoneId: "Z123456789"
    ssl:
      provider: "acm"
      certificateArn: "arn:aws:acm:us-west-2:ACCOUNT-ID:certificate/def456"
    istio:
      enabled: true
      gateway: "n8n-gateway"
      virtualService: true
      destinationRule: true
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
        topicArn: "arn:aws:sns:us-west-2:ACCOUNT-ID:n8n-alerts"
  security:
    podSecurityStandard: "restricted"
    networkPolicies:
      enabled: true
      denyAll: true
      allowRules:
        - name: "allow-database"
          ports:
            - port: 5432
              protocol: "TCP"
        - name: "allow-cache"
          ports:
            - port: 6379
              protocol: "TCP"
    rbac:
      enabled: true
      minimalPermissions: true
    secrets:
      encryption: true
      rotation: true
      rotationInterval: "90d"
```

## Upgrading

### Upgrade the Operator

```bash
# Upgrade to latest version
helm upgrade n8n-operator n8n-operator/n8n-eks-operator

# Upgrade with new values
helm upgrade n8n-operator ./charts/n8n-eks-operator \
  -f ./charts/n8n-eks-operator/values-production.yaml
```

### Migration Guide

When upgrading between major versions:

1. **Backup existing N8nInstances**:
   ```bash
   kubectl get n8ninstances --all-namespaces -o yaml > n8n-backup.yaml
   ```

2. **Check for breaking changes** in the CHANGELOG

3. **Test in staging** environment first

4. **Perform rolling upgrade**:
   ```bash
   helm upgrade n8n-operator ./charts/n8n-eks-operator --wait
   ```

## Uninstallation

```bash
# Uninstall the operator (keeps CRDs by default)
helm uninstall n8n-operator

# Remove CRDs (WARNING: This will delete all N8nInstances)
kubectl delete crd n8ninstances.n8n.io
```

## Troubleshooting

### Common Issues

1. **Operator pods not starting**
   ```bash
   kubectl describe pod -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator
   kubectl logs -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator
   ```

2. **Webhook certificate issues**
   ```bash
   kubectl get secret -n n8n-system | grep webhook
   kubectl describe validatingwebhookconfiguration
   ```

3. **RBAC permission issues**
   ```bash
   kubectl auth can-i create n8ninstances --as=system:serviceaccount:n8n-system:n8n-eks-operator
   ```

4. **AWS permissions issues**
   ```bash
   kubectl describe serviceaccount -n n8n-system n8n-eks-operator
   # Check IRSA annotation
   ```

### Debug Mode

Enable debug logging:

```bash
helm upgrade n8n-operator ./charts/n8n-eks-operator \
  --set logging.level=debug \
  --set logging.development=true
```

### Health Checks

Check operator health:

```bash
# Port forward to health endpoint
kubectl port-forward -n n8n-system svc/n8n-eks-operator-controller-manager-metrics-service 8081:8443

# Check health
curl http://localhost:8081/healthz
curl http://localhost:8081/readyz
```

## Monitoring

### Prometheus Integration

If you have Prometheus Operator installed:

```bash
helm upgrade n8n-operator ./charts/n8n-eks-operator \
  --set monitoring.enabled=true \
  --set monitoring.serviceMonitor.enabled=true
```

### Grafana Dashboard

Import the included Grafana dashboard:

```bash
helm upgrade n8n-operator ./charts/n8n-eks-operator \
  --set monitoring.grafanaDashboard.enabled=true
```

### Metrics Available

- `controller_runtime_reconcile_total` - Total reconciliations
- `controller_runtime_reconcile_duration_seconds` - Reconciliation duration
- `controller_runtime_reconcile_errors_total` - Reconciliation errors
- `workqueue_depth` - Work queue depth
- `workqueue_adds_total` - Work queue additions
- `process_resident_memory_bytes` - Memory usage
- `process_cpu_seconds_total` - CPU usage

## Security

### Pod Security Standards

The chart enforces Pod Security Standards by default:

```yaml
podSecurityStandards:
  enforce: "restricted"
  audit: "restricted"
  warn: "restricted"
```

### Network Policies

Enable network policies for enhanced security:

```yaml
networkPolicies:
  enabled: true
  egress:
    allowDNS: true
    allowHTTPS: true
    toCIDRs:
      - cidr: "10.0.0.0/8"  # VPC CIDR
        ports:
          - protocol: TCP
            port: 5432  # PostgreSQL
          - protocol: TCP
            port: 6379  # Redis
```

### RBAC

The chart creates minimal RBAC permissions:

- Manage N8nInstance resources
- Create/manage Deployments, Services, ConfigMaps, Secrets
- Access to monitoring resources
- Leader election permissions

## AWS Integration

### IAM Roles for Service Accounts (IRSA)

Configure IRSA for AWS permissions:

```yaml
aws:
  serviceAccount:
    roleArn: "arn:aws:iam::ACCOUNT-ID:role/n8n-eks-operator-role"
```

### Required AWS Permissions

The operator requires the following AWS permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBClusters",
        "rds:DescribeDBInstances",
        "elasticache:DescribeCacheClusters",
        "elasticache:DescribeReplicationGroups",
        "s3:CreateBucket",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:PutBucketPolicy",
        "cloudfront:CreateDistribution",
        "cloudfront:GetDistribution",
        "route53:ChangeResourceRecordSets",
        "route53:GetHostedZone",
        "acm:RequestCertificate",
        "acm:DescribeCertificate",
        "secretsmanager:GetSecretValue",
        "secretsmanager:CreateSecret",
        "secretsmanager:UpdateSecret"
      ],
      "Resource": "*"
    }
  ]
}
```

## Development

### Local Development

```bash
# Install for local development
helm install n8n-operator ./charts/n8n-eks-operator \
  --set operator.image.pullPolicy=Never \
  --set logging.level=debug \
  --set logging.development=true
```

### Testing

```bash
# Run chart tests
helm test n8n-operator

# Lint the chart
helm lint ./charts/n8n-eks-operator

# Template the chart
helm template n8n-operator ./charts/n8n-eks-operator
```

## Contributing

1. Make changes to the chart
2. Update the version in `Chart.yaml`
3. Update this README if needed
4. Test the changes:
   ```bash
   helm lint ./charts/n8n-eks-operator
   helm template test ./charts/n8n-eks-operator
   ```
5. Submit a pull request

## Changelog

### v0.1.0
- Initial release
- Basic operator deployment
- Webhook support
- Monitoring integration
- Security configurations
- AWS integration support

## Support

- GitHub Issues: https://github.com/n8n-io/n8n-eks-operator/issues
- Documentation: https://github.com/n8n-io/n8n-eks-operator
- n8n Community: https://community.n8n.io