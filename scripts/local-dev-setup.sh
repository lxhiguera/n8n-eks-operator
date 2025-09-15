#!/bin/bash

set -e

echo "🚀 Setting up local development environment for n8n EKS Operator"

# Check if required tools are installed
check_tool() {
    if ! command -v $1 &> /dev/null; then
        echo "❌ $1 is not installed. Please install it first."
        exit 1
    fi
}

echo "📋 Checking required tools..."
check_tool docker
check_tool kubectl
check_tool kind

# Create kind cluster if it doesn't exist
CLUSTER_NAME="n8n-operator-dev"
if ! kind get clusters | grep -q "$CLUSTER_NAME"; then
    echo "🔧 Creating kind cluster: $CLUSTER_NAME"
    cat <<EOF | kind create cluster --name $CLUSTER_NAME --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 80
    protocol: TCP
  - containerPort: 443
    hostPort: 443
    protocol: TCP
- role: worker
- role: worker
EOF
else
    echo "✅ Kind cluster $CLUSTER_NAME already exists"
fi

# Set kubectl context
kubectl config use-context kind-$CLUSTER_NAME

echo "📦 Installing cert-manager (required for webhooks)..."
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

echo "⏳ Waiting for cert-manager to be ready..."
kubectl wait --for=condition=ready pod -l app=cert-manager -n cert-manager --timeout=300s
kubectl wait --for=condition=ready pod -l app=cainjector -n cert-manager --timeout=300s
kubectl wait --for=condition=ready pod -l app=webhook -n cert-manager --timeout=300s

echo "🔧 Creating n8n-system namespace..."
kubectl create namespace n8n-system --dry-run=client -o yaml | kubectl apply -f -

echo "🏗️  Building operator image..."
make build
docker build -t n8n-eks-operator:dev .

echo "📤 Loading image into kind cluster..."
kind load docker-image n8n-eks-operator:dev --name $CLUSTER_NAME

echo "✅ Local development environment is ready!"
echo ""
echo "📝 Next steps:"
echo "1. Deploy the operator: make deploy-local"
echo "2. Create a test N8nInstance: kubectl apply -f examples/basic/n8n-instance.yaml"
echo "3. Check operator logs: kubectl logs -f deployment/n8n-eks-operator-controller-manager -n n8n-system"
echo ""
echo "🔧 Useful commands:"
echo "- kubectl get n8ninstances -A"
echo "- kubectl describe n8ninstance <name>"
echo "- kubectl logs -f deployment/n8n-eks-operator-controller-manager -n n8n-system"
echo "- kind delete cluster --name $CLUSTER_NAME  # to cleanup"