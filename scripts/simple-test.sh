#!/bin/bash

set -e

echo "🧪 Simple test of n8n EKS Operator (Docker only)"

# Check if Podman or Docker is available
if command -v podman &> /dev/null; then
    CONTAINER_RUNTIME="podman"
    echo "✅ Podman is available"
elif command -v docker &> /dev/null; then
    CONTAINER_RUNTIME="docker"
    echo "✅ Docker is available"
else
    echo "❌ Neither Podman nor Docker is installed. Please install one of them first."
    exit 1
fi

# Build the operator
echo "🏗️  Building operator..."
make build

if [ -f "bin/manager" ]; then
    echo "✅ Operator binary built successfully"
    ls -la bin/manager
else
    echo "❌ Failed to build operator binary"
    exit 1
fi

# Test the operator binary
echo "🧪 Testing operator binary..."
echo "Running operator with --help flag:"
./bin/manager --help

echo ""
echo "✅ Operator binary is working!"
echo ""
echo "📝 The operator is ready for deployment. To test in a real Kubernetes cluster:"
echo "1. Install kubectl, kind, and Docker"
echo "2. Run: make local-setup"
echo "3. Run: make local-deploy"
echo "4. Run: make local-test"
echo ""
echo "🔧 For now, you can:"
echo "- Review the code in internal/managers/enterprise_manager.go"
echo "- Check the examples in examples/enterprise/"
echo "- Read the documentation in docs/enterprise-features.md"