# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the n8n EKS Operator.

## Quick Diagnostics

### Check Operator Status

```bash
# Check operator deployment
kubectl get deployment -n n8n-system n8n-eks-operator-controller-manager

# Check operator pods
kubectl get pods -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator

# Check operator logs
kubectl logs -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator --tail=100
```

### Check N8nInstance Status

```bash
# List all N8nInstances
kubectl get n8ninstances --all-namespaces

# Get detailed status
kubectl describe n8ninstance <instance-name> -n <namespace>

# Check instance events
kubectl get events --field-selector involvedObject.kind=N8nInstance -n <namespace>
```

### Check CRDs

```bash
# Verify CRDs are installed
kubectl get crd n8ninstances.n8n.io

# Check CRD version
kubectl get crd n8ninstances.n8n.io -o yaml | grep -A5 versions
```

## Common Issues

### 1. Operator Not Starting

#### Symptoms
- Operator pods in `CrashLoopBackOff` or `Pending` state
- Error messages in operator logs
- Deployment shows 0/1 ready replicas

#### Diagnosis

```bash
# Check pod status and events
kubectl describe pod -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator

# Check operator logs for errors
kubectl logs -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator

# Check resource constraints
kubectl top pods -n n8n-system
kubectl describe node
```

#### Common Causes and Solutions

**RBAC Permissions Missing**
```bash
# Check if operator can create resources
kubectl auth can-i create n8ninstances --as=system:serviceaccount:n8n-system:n8n-eks-operator

# Verify ClusterRole exists
kubectl get clusterrole n8n-eks-operator-manager-role

# Check ClusterRoleBinding
kubectl get clusterrolebinding n8n-eks-operator-manager-rolebinding
```

**AWS Credentials Issues**
```bash
# Check ServiceAccount annotations
kubectl describe serviceaccount -n n8n-system n8n-eks-operator

# Verify IRSA role exists
aws iam get-role --role-name n8n-eks-operator-role

# Test AWS connectivity
kubectl run aws-test --rm -it --image=amazon/aws-cli \
  --serviceaccount=n8n-eks-operator \
  --namespace=n8n-system \
  -- aws sts get-caller-identity
```

**Image Pull Issues**
```bash
# Check image pull secrets
kubectl get secrets -n n8n-system

# Verify image exists
docker pull ghcr.io/lxhiguera/n8n-eks-operator:v0.1.0

# Check node capacity
kubectl describe node | grep -A5 "Allocated resources"
```

### 2. N8nInstance Not Ready

#### Symptoms
- N8nInstance status shows "Not Ready"
- Components not being created
- Error conditions in status

#### Diagnosis

```bash
# Check instance status
kubectl get n8ninstance <name> -o yaml

# Look for error conditions
kubectl get n8ninstance <name> -o jsonpath='{.status.conditions[*]}'

# Check created resources
kubectl get all -l app.kubernetes.io/managed-by=n8n-eks-operator
```

#### Common Causes and Solutions

**Database Connection Issues**
```bash
# Verify database credentials secret
kubectl get secret <db-secret-name> -o yaml

# Test database connectivity
kubectl run db-test --rm -it --image=postgres:14 \
  -- psql -h <db-host> -U <username> -d <database> -c "SELECT 1;"

# Check RDS instance status
aws rds describe-db-instances --db-instance-identifier <db-id>
```

**Cache Connection Issues**
```bash
# Test Redis connectivity
kubectl run redis-test --rm -it --image=redis:7 \
  -- redis-cli -h <redis-host> -p 6379 ping

# Check ElastiCache cluster status
aws elasticache describe-cache-clusters --cache-cluster-id <cluster-id>
```

**S3 Access Issues**
```bash
# Test S3 access
kubectl run s3-test --rm -it --image=amazon/aws-cli \
  -- aws s3 ls s3://<bucket-name>

# Check bucket policy
aws s3api get-bucket-policy --bucket <bucket-name>
```

**Network Policy Blocking Traffic**
```bash
# Check network policies
kubectl get networkpolicy -n <namespace>

# Temporarily disable network policies for testing
kubectl patch n8ninstance <name> --type='merge' -p='{"spec":{"security":{"networkPolicies":{"enabled":false}}}}'
```

### 3. Webhook Issues

#### Symptoms
- Webhook validation/mutation failures
- Certificate errors in logs
- Unable to create/update N8nInstances

#### Diagnosis

```bash
# Check webhook configurations
kubectl get validatingwebhookconfiguration
kubectl get mutatingwebhookconfiguration

# Check certificate status
kubectl get certificate -n n8n-system
kubectl describe certificate -n n8n-system

# Check webhook service
kubectl get service -n n8n-system n8n-eks-operator-webhook-service
```

#### Solutions

**Certificate Issues**
```bash
# Check cert-manager logs
kubectl logs -n cert-manager -l app=cert-manager

# Recreate certificate
kubectl delete certificate -n n8n-system n8n-eks-operator-serving-cert

# Check certificate issuer
kubectl get clusterissuer
kubectl describe clusterissuer <issuer-name>
```

**Webhook Service Issues**
```bash
# Check webhook service endpoints
kubectl get endpoints -n n8n-system n8n-eks-operator-webhook-service

# Test webhook connectivity
kubectl run webhook-test --rm -it --image=curlimages/curl \
  -- curl -k https://n8n-eks-operator-webhook-service.n8n-system.svc:443/validate-n8n-io-v1alpha1-n8ninstance
```

### 4. Performance Issues

#### Symptoms
- Slow reconciliation
- High CPU/memory usage
- Timeouts in operations

#### Diagnosis

```bash
# Check resource usage
kubectl top pods -n n8n-system
kubectl top nodes

# Check operator metrics
kubectl port-forward -n n8n-system svc/n8n-eks-operator-controller-manager-metrics-service 8080:8443
curl http://localhost:8080/metrics | grep controller_runtime
```

#### Solutions

**Increase Resources**
```bash
# Update operator resources
helm upgrade n8n-operator n8n-operator/n8n-eks-operator \
  --set operator.resources.limits.cpu=2000m \
  --set operator.resources.limits.memory=2Gi \
  --reuse-values
```

**Tune Reconciliation**
```bash
# Reduce concurrent reconciles
helm upgrade n8n-operator n8n-operator/n8n-eks-operator \
  --set controller.maxConcurrentReconciles=1 \
  --reuse-values

# Increase reconcile timeout
helm upgrade n8n-operator n8n-operator/n8n-eks-operator \
  --set controller.reconcileTimeout=15m \
  --reuse-values
```

### 5. AWS Service Issues

#### Symptoms
- AWS API errors in logs
- Resources not being created in AWS
- Permission denied errors

#### Diagnosis

```bash
# Check AWS credentials
kubectl run aws-debug --rm -it --image=amazon/aws-cli \
  --serviceaccount=n8n-eks-operator \
  --namespace=n8n-system \
  -- aws sts get-caller-identity

# Check IAM role permissions
aws iam list-attached-role-policies --role-name n8n-eks-operator-role
aws iam get-role-policy --role-name n8n-eks-operator-role --policy-name <policy-name>
```

#### Solutions

**Fix IAM Permissions**
```bash
# Attach required policies
aws iam attach-role-policy \
  --role-name n8n-eks-operator-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonRDSFullAccess

# Create custom policy for specific resources
cat > n8n-operator-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances",
        "elasticache:DescribeCacheClusters",
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam create-policy \
  --policy-name n8n-operator-policy \
  --policy-document file://n8n-operator-policy.json

aws iam attach-role-policy \
  --role-name n8n-eks-operator-role \
  --policy-arn arn:aws:iam::<account-id>:policy/n8n-operator-policy
```

## Debug Mode

### Enable Debug Logging

```bash
# Enable debug logging
helm upgrade n8n-operator n8n-operator/n8n-eks-operator \
  --set logging.level=debug \
  --set logging.development=true \
  --reuse-values

# Check debug logs
kubectl logs -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator -f
```

### Verbose AWS Logging

```bash
# Enable AWS SDK debug logging
kubectl patch deployment n8n-eks-operator-controller-manager -n n8n-system \
  --type='json' \
  -p='[{"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": "AWS_SDK_LOAD_CONFIG", "value": "1"}}]'

kubectl patch deployment n8n-eks-operator-controller-manager -n n8n-system \
  --type='json' \
  -p='[{"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": "AWS_LOG_LEVEL", "value": "debug"}}]'
```

## Health Checks

### Operator Health

```bash
# Port forward to health endpoints
kubectl port-forward -n n8n-system svc/n8n-eks-operator-controller-manager 8081:8081

# Check health
curl http://localhost:8081/healthz

# Check readiness
curl http://localhost:8081/readyz

# Check metrics
curl http://localhost:8081/metrics
```

### Component Health

```bash
# Check all components
kubectl get all -l app.kubernetes.io/managed-by=n8n-eks-operator

# Check specific component health
kubectl get pods -l app.kubernetes.io/component=main
kubectl logs -l app.kubernetes.io/component=main --tail=50
```

## Monitoring and Alerting

### Prometheus Queries

```promql
# Operator reconciliation rate
rate(controller_runtime_reconcile_total[5m])

# Reconciliation errors
rate(controller_runtime_reconcile_errors_total[5m])

# Reconciliation duration
histogram_quantile(0.95, rate(controller_runtime_reconcile_duration_seconds_bucket[5m]))

# AWS API call rate
rate(n8n_aws_api_calls_total[5m])

# AWS API errors
rate(n8n_aws_api_errors_total[5m])
```

### Common Alerts

```yaml
# High error rate alert
- alert: N8nOperatorHighErrorRate
  expr: rate(controller_runtime_reconcile_errors_total[5m]) > 0.1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "n8n operator has high error rate"
    description: "Error rate is {{ $value }} errors per second"

# Operator down alert
- alert: N8nOperatorDown
  expr: up{job="n8n-eks-operator"} == 0
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "n8n operator is down"
    description: "n8n operator has been down for more than 1 minute"
```

## Recovery Procedures

### Operator Recovery

```bash
# Restart operator
kubectl rollout restart deployment n8n-eks-operator-controller-manager -n n8n-system

# Force pod recreation
kubectl delete pods -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator

# Reinstall operator
helm uninstall n8n-operator -n n8n-system
helm install n8n-operator n8n-operator/n8n-eks-operator -n n8n-system -f values.yaml
```

### N8nInstance Recovery

```bash
# Force reconciliation
kubectl annotate n8ninstance <name> n8n.io/force-reconcile="$(date +%s)"

# Recreate instance
kubectl delete n8ninstance <name>
kubectl apply -f n8n-instance.yaml

# Check finalizers if stuck deleting
kubectl patch n8ninstance <name> --type='merge' -p='{"metadata":{"finalizers":[]}}'
```

### Database Recovery

```bash
# Check database connectivity
kubectl run db-check --rm -it --image=postgres:14 \
  -- psql -h <host> -U <user> -d <db> -c "SELECT version();"

# Restore from backup
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier n8n-restored \
  --db-snapshot-identifier n8n-backup-snapshot
```

## Getting Help

### Collect Debug Information

```bash
#!/bin/bash
# debug-info.sh - Collect debug information

echo "=== Operator Status ==="
kubectl get deployment -n n8n-system n8n-eks-operator-controller-manager

echo "=== Operator Logs ==="
kubectl logs -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator --tail=100

echo "=== N8nInstances ==="
kubectl get n8ninstances --all-namespaces -o wide

echo "=== Events ==="
kubectl get events --all-namespaces --sort-by='.lastTimestamp' | tail -20

echo "=== CRDs ==="
kubectl get crd n8ninstances.n8n.io

echo "=== Webhooks ==="
kubectl get validatingwebhookconfiguration
kubectl get mutatingwebhookconfiguration

echo "=== Certificates ==="
kubectl get certificate -n n8n-system

echo "=== AWS Connectivity ==="
kubectl run aws-test --rm -it --image=amazon/aws-cli \
  --serviceaccount=n8n-eks-operator \
  --namespace=n8n-system \
  -- aws sts get-caller-identity 2>&1 || echo "AWS connectivity failed"
```

### Support Channels

- **GitHub Issues**: [https://github.com/lxhiguera/n8n-eks-operator/issues](https://github.com/lxhiguera/n8n-eks-operator/issues)
- **Discussions**: [https://github.com/lxhiguera/n8n-eks-operator/discussions](https://github.com/lxhiguera/n8n-eks-operator/discussions)
- **Slack**: [n8n Community](https://n8n.io/slack)

### When Creating Issues

Please include:

1. **Environment Information**:
   - Kubernetes version
   - EKS version
   - Operator version
   - AWS region

2. **Configuration**:
   - Helm values used
   - N8nInstance YAML
   - Relevant secrets (redacted)

3. **Logs and Status**:
   - Operator logs
   - N8nInstance status
   - Recent events
   - Error messages

4. **Steps to Reproduce**:
   - What you were trying to do
   - What happened instead
   - Minimal reproduction case

This information helps maintainers diagnose and resolve issues quickly.