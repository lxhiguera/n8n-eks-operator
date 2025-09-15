#!/bin/bash

set -e

echo "🧪 Quick test of n8n EKS Operator"

# Check if we're in a Kubernetes cluster
if ! kubectl cluster-info &> /dev/null; then
    echo "❌ No Kubernetes cluster found. Please run 'make local-setup' first."
    exit 1
fi

echo "📋 Current cluster info:"
kubectl cluster-info

echo "🔍 Checking if operator is running..."
if kubectl get deployment n8n-eks-operator -n n8n-system &> /dev/null; then
    echo "✅ Operator is deployed"
    kubectl get pods -n n8n-system -l app=n8n-eks-operator
else
    echo "❌ Operator not found. Please run 'make local-deploy' first."
    exit 1
fi

echo "🔍 Checking for N8nInstance CRD..."
if kubectl get crd n8ninstances.n8n.io &> /dev/null; then
    echo "✅ N8nInstance CRD is installed"
else
    echo "❌ N8nInstance CRD not found"
    exit 1
fi

echo "📦 Checking support services..."
kubectl get pods -l app=postgres
kubectl get pods -l app=redis

echo "🧪 Testing N8nInstance creation..."
if kubectl get n8ninstance n8n-local-test &> /dev/null; then
    echo "✅ Test N8nInstance already exists"
    kubectl get n8ninstance n8n-local-test -o wide
else
    echo "Creating test N8nInstance..."
    kubectl apply -f examples/local/basic-n8n-instance.yaml
    echo "✅ Test N8nInstance created"
fi

echo "📊 Current N8nInstances:"
kubectl get n8ninstances -A

echo "📝 Operator logs (last 20 lines):"
kubectl logs deployment/n8n-eks-operator -n n8n-system --tail=20

echo ""
echo "✅ Quick test completed!"
echo ""
echo "🔧 Useful commands:"
echo "- Watch N8nInstances: kubectl get n8ninstances -w"
echo "- Describe instance: kubectl describe n8ninstance n8n-local-test"
echo "- Operator logs: kubectl logs -f deployment/n8n-eks-operator -n n8n-system"
echo "- Delete test instance: kubectl delete n8ninstance n8n-local-test"