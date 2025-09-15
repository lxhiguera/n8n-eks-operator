# 📦 Helm Installation Guide

## Quick Start

### 1. Add the Helm Repository

```bash
# Add the n8n EKS Operator Helm repository
helm repo add n8n-operator https://lxhiguera.github.io/n8n-eks-operator
helm repo update
```

### 2. Install the Operator

```bash
# Basic installation
helm install n8n-operator n8n-operator/n8n-eks-operator \
  --namespace n8n-system \
  --create-namespace

# With custom AWS configuration
helm install n8n-operator n8n-operator/n8n-eks-operator \
  --namespace n8n-system \
  --create-namespace \
  --set aws.region=us-west-2 \
  --set aws.cluster.name=my-eks-cluster
```

## Configuration Options

### Basic Configuration

```yaml
# values.yaml
aws:
  region: "us-west-2"
  cluster:
    name: "my-eks-cluster"

operator:
  replicaCount: 1
  image:
    repository: "ghcr.io/lxhiguera/n8n-eks-operator"
    tag: "v1.0.0"
    pullPolicy: IfNotPresent

monitoring:
  enabled: true
  serviceMonitor:
    enabled: true

webhook:
  enabled: true
  port: 9443
```

### Production Configuration

```yaml
# values-production.yaml
aws:
  region: "us-west-2"
  cluster:
    name: "production-eks"
  serviceAccount:
    roleArn: "arn:aws:iam::123456789012:role/n8n-operator-role"

operator:
  replicaCount: 2
  resources:
    limits:
      cpu: 1000m
      memory: 1Gi
    requests:
      cpu: 200m
      memory: 256Mi

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
      issuer: "letsencrypt-prod"

networkPolicy:
  enabled: true

podSecurityStandards:
  enforce: "restricted"

rbac:
  create: true
  serviceAccount:
    create: true
    annotations:
      eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/n8n-operator-role"
```

## Installation Commands

### Development Environment

```bash
helm install n8n-operator n8n-operator/n8n-eks-operator \
  --namespace n8n-system \
  --create-namespace \
  --set operator.image.tag=latest \
  --set monitoring.enabled=false \
  --set webhook.enabled=false
```

### Staging Environment

```bash
helm install n8n-operator n8n-operator/n8n-eks-operator \
  --namespace n8n-system \
  --create-namespace \
  --set aws.region=us-west-2 \
  --set monitoring.enabled=true \
  --set webhook.enabled=true \
  --set networkPolicy.enabled=true
```

### Production Environment

```bash
# Create values file first
cat > values-production.yaml << 'EOF'
aws:
  region: us-west-2
  cluster:
    name: production-eks
  serviceAccount:
    roleArn: arn:aws:iam::123456789012:role/n8n-operator-role

operator:
  replicaCount: 2
  resources:
    limits:
      cpu: 1000m
      memory: 1Gi
    requests:
      cpu: 200m
      memory: 256Mi

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

networkPolicy:
  enabled: true

podSecurityStandards:
  enforce: restricted
EOF

# Install with production values
helm install n8n-operator n8n-operator/n8n-eks-operator \
  --namespace n8n-system \
  --create-namespace \
  -f values-production.yaml
```

## Upgrade

```bash
# Update repository
helm repo update

# Upgrade to latest version
helm upgrade n8n-operator n8n-operator/n8n-eks-operator \
  --namespace n8n-system

# Upgrade with new values
helm upgrade n8n-operator n8n-operator/n8n-eks-operator \
  --namespace n8n-system \
  -f values-production.yaml
```

## Uninstall

```bash
# Uninstall the operator
helm uninstall n8n-operator --namespace n8n-system

# Remove the namespace (optional)
kubectl delete namespace n8n-system
```

## Verification

### Check Installation

```bash
# Check operator pods
kubectl get pods -n n8n-system

# Check operator logs
kubectl logs -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator

# Check CRDs
kubectl get crd | grep n8n

# Check webhooks
kubectl get validatingwebhookconfiguration | grep n8n
kubectl get mutatingwebhookconfiguration | grep n8n
```

### Test Operator

```bash
# Create a test N8nInstance
cat << 'EOF' | kubectl apply -f -
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: test-n8n
  namespace: default
spec:
  version: "1.0.0"
  domain: "test.example.com"
  components:
    main:
      replicas: 1
EOF

# Check instance status
kubectl get n8ninstance test-n8n -o yaml

# Clean up test
kubectl delete n8ninstance test-n8n
```

## Troubleshooting

### Common Issues

#### Operator Not Starting

```bash
# Check events
kubectl get events -n n8n-system --sort-by='.lastTimestamp'

# Check RBAC
kubectl auth can-i create n8ninstances --as=system:serviceaccount:n8n-system:n8n-eks-operator

# Check image pull
kubectl describe pod -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator
```

#### Webhook Issues

```bash
# Check certificate
kubectl get certificate -n n8n-system

# Check webhook configuration
kubectl get validatingwebhookconfiguration n8n-eks-operator-validating-webhook-configuration -o yaml

# Test webhook
kubectl apply --dry-run=server -f - << 'EOF'
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: webhook-test
spec:
  version: "invalid-version"
EOF
```

#### AWS Permissions

```bash
# Check service account
kubectl describe serviceaccount -n n8n-system n8n-eks-operator

# Test AWS access
kubectl run aws-test --rm -it --image=amazon/aws-cli --serviceaccount=n8n-eks-operator -- aws sts get-caller-identity
```

## Repository Information

- **Repository URL**: https://lxhiguera.github.io/n8n-eks-operator
- **Chart Name**: n8n-eks-operator
- **Source Code**: https://github.com/lxhiguera/n8n-eks-operator
- **Issues**: https://github.com/lxhiguera/n8n-eks-operator/issues

## Chart Values Reference

For a complete list of configuration options, see:
- [Chart Values](https://github.com/lxhiguera/n8n-eks-operator/blob/main/charts/n8n-eks-operator/values.yaml)
- [Production Values](https://github.com/lxhiguera/n8n-eks-operator/blob/main/charts/n8n-eks-operator/values-production.yaml)