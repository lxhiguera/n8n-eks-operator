# Installation Guide

This guide provides detailed instructions for installing and configuring the n8n EKS Operator.

## Prerequisites

### Required Software

- **kubectl** 1.24+
- **Helm** 3.8+
- **AWS CLI** 2.0+

### AWS Services

- **Amazon EKS** cluster (1.24+)
- **AWS Load Balancer Controller** (for ingress)
- **Amazon RDS** (PostgreSQL 12+)
- **Amazon ElastiCache** (Redis 6+)
- **Amazon S3** (for storage)

### Optional Services

- **cert-manager** (for TLS certificates)
- **Prometheus Operator** (for monitoring)
- **Istio** (for service mesh)

## Step 1: Prepare Your EKS Cluster

### Create EKS Cluster

If you don't have an EKS cluster, create one:

```bash
# Using eksctl
eksctl create cluster \
  --name n8n-cluster \
  --region us-west-2 \
  --version 1.28 \
  --nodegroup-name standard-workers \
  --node-type m5.large \
  --nodes 3 \
  --nodes-min 1 \
  --nodes-max 4 \
  --managed

# Update kubeconfig
aws eks update-kubeconfig --region us-west-2 --name n8n-cluster
```

### Install AWS Load Balancer Controller

```bash
# Create IAM role for AWS Load Balancer Controller
eksctl create iamserviceaccount \
  --cluster=n8n-cluster \
  --namespace=kube-system \
  --name=aws-load-balancer-controller \
  --role-name AmazonEKSLoadBalancerControllerRole \
  --attach-policy-arn=arn:aws:iam::aws:policy/ElasticLoadBalancingFullAccess \
  --approve

# Install AWS Load Balancer Controller
helm repo add eks https://aws.github.io/eks-charts
helm repo update

helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=n8n-cluster \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller
```

## Step 2: Install cert-manager (Optional)

For automatic TLS certificate management:

```bash
# Install cert-manager
helm repo add jetstack https://charts.jetstack.io
helm repo update

helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.13.0 \
  --set installCRDs=true

# Create ClusterIssuer for Let's Encrypt
cat << EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: alb
EOF
```

## Step 3: Install Prometheus Operator (Optional)

For monitoring and alerting:

```bash
# Install Prometheus Operator
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
  --set prometheus.prometheusSpec.ruleSelectorNilUsesHelmValues=false
```

## Step 4: Create AWS Resources

### Create IAM Role for the Operator

```bash
# Create trust policy
cat > trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):oidc-provider/$(aws eks describe-cluster --name n8n-cluster --query "cluster.identity.oidc.issuer" --output text | sed 's|https://||')"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "$(aws eks describe-cluster --name n8n-cluster --query "cluster.identity.oidc.issuer" --output text | sed 's|https://||'):sub": "system:serviceaccount:n8n-system:n8n-eks-operator",
          "$(aws eks describe-cluster --name n8n-cluster --query "cluster.identity.oidc.issuer" --output text | sed 's|https://||'):aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
EOF

# Create IAM role
aws iam create-role \
  --role-name n8n-eks-operator-role \
  --assume-role-policy-document file://trust-policy.json

# Attach policies
aws iam attach-role-policy \
  --role-name n8n-eks-operator-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonRDSFullAccess

aws iam attach-role-policy \
  --role-name n8n-eks-operator-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonElastiCacheFullAccess

aws iam attach-role-policy \
  --role-name n8n-eks-operator-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess

aws iam attach-role-policy \
  --role-name n8n-eks-operator-role \
  --policy-arn arn:aws:iam::aws:policy/CloudFrontFullAccess

aws iam attach-role-policy \
  --role-name n8n-eks-operator-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonRoute53FullAccess

aws iam attach-role-policy \
  --role-name n8n-eks-operator-role \
  --policy-arn arn:aws:iam::aws:policy/AWSCertificateManagerFullAccess

aws iam attach-role-policy \
  --role-name n8n-eks-operator-role \
  --policy-arn arn:aws:iam::aws:policy/SecretsManagerReadWrite
```

### Create RDS Database (Optional)

```bash
# Create DB subnet group
aws rds create-db-subnet-group \
  --db-subnet-group-name n8n-db-subnet-group \
  --db-subnet-group-description "Subnet group for n8n database" \
  --subnet-ids subnet-12345678 subnet-87654321

# Create security group
aws ec2 create-security-group \
  --group-name n8n-db-sg \
  --description "Security group for n8n database"

# Allow PostgreSQL access from EKS nodes
aws ec2 authorize-security-group-ingress \
  --group-name n8n-db-sg \
  --protocol tcp \
  --port 5432 \
  --source-group sg-eks-nodes

# Create RDS instance
aws rds create-db-instance \
  --db-instance-identifier n8n-database \
  --db-instance-class db.t3.micro \
  --engine postgres \
  --engine-version 14.9 \
  --master-username n8n \
  --master-user-password SecurePassword123! \
  --allocated-storage 20 \
  --vpc-security-group-ids sg-n8n-db \
  --db-subnet-group-name n8n-db-subnet-group \
  --backup-retention-period 7 \
  --storage-encrypted
```

### Create ElastiCache Cluster (Optional)

```bash
# Create cache subnet group
aws elasticache create-cache-subnet-group \
  --cache-subnet-group-name n8n-cache-subnet-group \
  --cache-subnet-group-description "Subnet group for n8n cache" \
  --subnet-ids subnet-12345678 subnet-87654321

# Create security group
aws ec2 create-security-group \
  --group-name n8n-cache-sg \
  --description "Security group for n8n cache"

# Allow Redis access from EKS nodes
aws ec2 authorize-security-group-ingress \
  --group-name n8n-cache-sg \
  --protocol tcp \
  --port 6379 \
  --source-group sg-eks-nodes

# Create ElastiCache cluster
aws elasticache create-cache-cluster \
  --cache-cluster-id n8n-cache \
  --cache-node-type cache.t3.micro \
  --engine redis \
  --num-cache-nodes 1 \
  --security-group-ids sg-n8n-cache \
  --cache-subnet-group-name n8n-cache-subnet-group
```

## Step 5: Install the n8n EKS Operator

### Add Helm Repository

```bash
helm repo add n8n-operator https://lxhiguera.github.io/n8n-eks-operator
helm repo update
```

### Create Values File

Create a `values.yaml` file with your configuration:

```yaml
# Basic configuration
operator:
  replicaCount: 2
  image:
    tag: "v0.1.0"
  resources:
    limits:
      cpu: 1000m
      memory: 1Gi
    requests:
      cpu: 200m
      memory: 256Mi

# AWS configuration
aws:
  region: us-west-2
  cluster:
    name: n8n-cluster
  serviceAccount:
    roleArn: arn:aws:iam::123456789012:role/n8n-eks-operator-role

# Monitoring
monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
  prometheusRule:
    enabled: true
  grafanaDashboard:
    enabled: true

# Webhooks
webhook:
  enabled: true
  certificate:
    certManager:
      enabled: true
      issuer: letsencrypt-prod

# Security
networkPolicy:
  enabled: true

podSecurityStandards:
  enforce: restricted
  audit: restricted
  warn: restricted

# Logging
logging:
  level: info
  format: json
```

### Install the Operator

```bash
helm install n8n-operator n8n-operator/n8n-eks-operator \
  --namespace n8n-system \
  --create-namespace \
  -f values.yaml
```

### Verify Installation

```bash
# Check operator status
kubectl get pods -n n8n-system

# Check CRDs
kubectl get crd n8ninstances.n8n.io

# Check webhooks
kubectl get validatingwebhookconfiguration
kubectl get mutatingwebhookconfiguration

# Check operator logs
kubectl logs -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator
```

## Step 6: Create Your First n8n Instance

### Create Database Credentials Secret

```bash
kubectl create secret generic n8n-db-credentials \
  --from-literal=username=n8n \
  --from-literal=password=SecurePassword123! \
  --from-literal=host=n8n-database.cluster-xxx.us-west-2.rds.amazonaws.com \
  --from-literal=port=5432 \
  --from-literal=database=n8n
```

### Create n8n Instance

```yaml
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: my-n8n
  namespace: default
spec:
  version: "1.0.0"
  domain: "n8n.example.com"
  
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
    host: "n8n-database.cluster-xxx.us-west-2.rds.amazonaws.com"
    port: 5432
    name: "n8n"
    credentialsSecret: "n8n-db-credentials"
    ssl: true
  
  cache:
    type: "elasticache"
    host: "n8n-cache.xxx.cache.amazonaws.com"
    port: 6379
  
  storage:
    s3:
      bucket: "my-n8n-workflows"
      region: "us-west-2"
    persistent:
      storageClass: "gp3"
      size: "10Gi"
  
  monitoring:
    metrics:
      enabled: true
      prometheus:
        enabled: true
    logging:
      level: "info"
  
  security:
    podSecurityStandard: "restricted"
    networkPolicies:
      enabled: true
```

Apply the configuration:

```bash
kubectl apply -f my-n8n-instance.yaml
```

### Monitor Deployment

```bash
# Check instance status
kubectl get n8ninstance my-n8n -o yaml

# Check created resources
kubectl get all -l app.kubernetes.io/managed-by=n8n-eks-operator

# Check events
kubectl get events --field-selector involvedObject.kind=N8nInstance

# Check ingress
kubectl get ingress
```

## Step 7: Access Your n8n Instance

### Get the Load Balancer URL

```bash
kubectl get ingress my-n8n-ingress -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

### Configure DNS (Optional)

If using Route53, create a CNAME record pointing to the load balancer:

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id Z123456789 \
  --change-batch '{
    "Changes": [{
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "n8n.example.com",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [{"Value": "k8s-default-myn8ning-xxx.us-west-2.elb.amazonaws.com"}]
      }
    }]
  }'
```

## Troubleshooting

### Common Issues

1. **Operator pods not starting**
   - Check RBAC permissions
   - Verify AWS credentials
   - Check resource limits

2. **N8nInstance not ready**
   - Check AWS service connectivity
   - Verify database credentials
   - Check network policies

3. **Certificate issues**
   - Verify cert-manager installation
   - Check DNS configuration
   - Review certificate logs

### Debug Commands

```bash
# Check operator logs
kubectl logs -n n8n-system -l app.kubernetes.io/name=n8n-eks-operator

# Describe N8nInstance
kubectl describe n8ninstance my-n8n

# Check events
kubectl get events --sort-by='.lastTimestamp'

# Test AWS connectivity
kubectl run aws-cli --rm -it --image=amazon/aws-cli -- aws sts get-caller-identity
```

## Next Steps

1. Configure monitoring and alerting
2. Set up backup and disaster recovery
3. Implement CI/CD pipelines
4. Scale your n8n instances
5. Explore advanced features

For more information, see the [Configuration Guide](configuration.md) and [Operations Guide](operations.md).