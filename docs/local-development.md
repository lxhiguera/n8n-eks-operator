# Local Development Guide

This guide explains how to set up and test the n8n EKS Operator locally using Kind (Kubernetes in Docker).

## Prerequisites

Before starting, make sure you have the following tools installed:

- **Docker**: For running containers
- **kubectl**: Kubernetes command-line tool
- **Kind**: Kubernetes in Docker
- **Go 1.21+**: For building the operator
- **Make**: For running build commands

### Installing Prerequisites

#### macOS (using Homebrew)
```bash
# Install Docker Desktop from https://docker.com/products/docker-desktop
# Or install Docker via Homebrew
brew install docker

# Install kubectl and kind
brew install kubectl kind

# Install Go
brew install go

# Make is usually pre-installed on macOS
```

#### Linux (Ubuntu/Debian)
```bash
# Install Docker
sudo apt-get update
sudo apt-get install docker.io

# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Install Go
sudo apt-get install golang-go

# Install Make
sudo apt-get install make
```

## Quick Start

### 1. Setup Local Environment

Run the setup script to create a Kind cluster and install dependencies:

```bash
make local-setup
```

This will:
- Create a Kind cluster named `n8n-operator-dev`
- Install cert-manager (required for webhooks)
- Create the `n8n-system` namespace
- Build and load the operator image

### 2. Deploy the Operator

Deploy the operator to your local cluster:

```bash
make local-deploy
```

This will:
- Deploy PostgreSQL and Redis for testing
- Deploy the n8n EKS Operator
- Wait for all services to be ready

### 3. Test with a Sample N8nInstance

Create a test N8nInstance:

```bash
make local-test
```

### 4. Monitor the Operator

Watch the operator logs:

```bash
make local-logs
```

Or run a quick test to verify everything is working:

```bash
chmod +x scripts/quick-test.sh
./scripts/quick-test.sh
```

## Manual Testing Steps

### 1. Check Operator Status

```bash
# Check if operator is running
kubectl get pods -n n8n-system

# Check operator logs
kubectl logs -f deployment/n8n-eks-operator -n n8n-system
```

### 2. Create N8nInstance Resources

```bash
# Apply the basic example
kubectl apply -f examples/local/basic-n8n-instance.yaml

# Watch the resource status
kubectl get n8ninstances -w

# Describe the resource for detailed information
kubectl describe n8ninstance n8n-local-test
```

### 3. Test Enterprise Features

```bash
# Apply enterprise example (basic)
kubectl apply -f examples/enterprise/basic-enterprise-n8n.yaml

# Apply multi-tenant example
kubectl apply -f examples/enterprise/multi-tenant-n8n.yaml
```

### 4. Verify Webhooks

The operator includes admission webhooks for validation and defaulting:

```bash
# Test validation by creating an invalid resource
cat <<EOF | kubectl apply -f -
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: invalid-test
spec:
  image: ""  # This should fail validation
EOF
```

## Development Workflow

### 1. Make Code Changes

Edit the operator code in `internal/`, `api/`, or `cmd/`.

### 2. Rebuild and Redeploy

```bash
# Rebuild the operator
make build

# Rebuild Docker image
docker build -t n8n-eks-operator:dev .

# Load new image into Kind cluster
kind load docker-image n8n-eks-operator:dev --name n8n-operator-dev

# Restart the operator deployment
kubectl rollout restart deployment/n8n-eks-operator -n n8n-system
```

### 3. Test Changes

```bash
# Run quick test
./scripts/quick-test.sh

# Or create/update test resources
kubectl apply -f examples/local/basic-n8n-instance.yaml
```

## Debugging

### Check Operator Logs

```bash
# Follow operator logs
kubectl logs -f deployment/n8n-eks-operator -n n8n-system

# Get recent logs
kubectl logs deployment/n8n-eks-operator -n n8n-system --tail=100
```

### Check Resource Status

```bash
# List all N8nInstances
kubectl get n8ninstances -A

# Get detailed information
kubectl describe n8ninstance <name>

# Check events
kubectl get events --sort-by=.metadata.creationTimestamp
```

### Check Support Services

```bash
# Check PostgreSQL
kubectl logs deployment/postgres
kubectl exec -it deployment/postgres -- psql -U n8n_user -d n8n_local -c "\\dt"

# Check Redis
kubectl logs deployment/redis
kubectl exec -it deployment/redis -- redis-cli ping
```

### Common Issues

#### 1. Operator Not Starting

```bash
# Check if image is loaded
docker exec -it n8n-operator-dev-control-plane crictl images | grep n8n-eks-operator

# Check deployment status
kubectl describe deployment n8n-eks-operator -n n8n-system
```

#### 2. Webhook Failures

```bash
# Check cert-manager
kubectl get pods -n cert-manager

# Check webhook configuration
kubectl get validatingwebhookconfiguration
kubectl get mutatingwebhookconfiguration
```

#### 3. CRD Issues

```bash
# Check if CRDs are installed
kubectl get crd | grep n8n

# Reinstall CRDs if needed
kubectl apply -f config/crd/bases/
```

## Testing Enterprise Features

### Multi-Tenancy

```bash
# Apply multi-tenant configuration
kubectl apply -f examples/enterprise/multi-tenant-n8n.yaml

# Check tenant namespaces
kubectl get namespaces | grep n8n-enterprise

# Check tenant resources
kubectl get all -n n8n-enterprise-multi-tenant-dev-team
```

### SSO and Security

```bash
# Check RBAC resources
kubectl get roles,rolebindings -A | grep n8n

# Check network policies
kubectl get networkpolicies -A | grep n8n

# Check service accounts
kubectl get serviceaccounts -A | grep n8n
```

## Performance Testing

### Load Testing

```bash
# Create multiple N8nInstances
for i in {1..5}; do
  sed "s/n8n-local-test/n8n-test-$i/g" examples/local/basic-n8n-instance.yaml | kubectl apply -f -
done

# Monitor resource usage
kubectl top pods -n n8n-system
kubectl top nodes
```

### Cleanup

```bash
# Delete test instances
kubectl delete n8ninstances --all

# Delete support services
kubectl delete -f examples/local/support-services.yaml

# Or cleanup entire environment
make local-cleanup
```

## Advanced Testing

### Custom Resource Validation

Test the webhook validation by creating resources with invalid configurations:

```bash
# Test missing required fields
cat <<EOF | kubectl apply -f -
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: validation-test
spec: {}
EOF
```

### Controller Logic Testing

```bash
# Enable debug logging
kubectl set env deployment/n8n-eks-operator -n n8n-system LOG_LEVEL=debug

# Watch controller reconciliation
kubectl logs -f deployment/n8n-eks-operator -n n8n-system | grep "Reconciling"
```

## Cleanup

When you're done testing, cleanup the local environment:

```bash
make local-cleanup
```

This will delete the Kind cluster and all associated resources.

## Next Steps

- Review the [Enterprise Features Guide](enterprise-features.md) for advanced configurations
- Check the [API Reference](api-reference.md) for complete resource specifications
- See [Production Deployment](installation.md) for deploying to real EKS clusters