#!/bin/bash

set -e

echo "🐳 Testing n8n EKS Operator with Podman"

# Check if Podman is available
if ! command -v podman &> /dev/null; then
    echo "❌ Podman is not installed. Please install Podman first."
    echo "   On macOS: brew install podman"
    echo "   On Linux: sudo apt-get install podman (Ubuntu/Debian)"
    exit 1
fi

echo "✅ Podman is available"
podman --version

# Build the operator
echo "🏗️  Building operator binary..."
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
echo "🐳 Building container image with Podman..."
podman build -t n8n-eks-operator:dev -f Dockerfile .

echo "✅ Container image built successfully!"
podman images | grep n8n-eks-operator

echo ""
echo "🧪 Testing container image..."
echo "Running container with --help flag:"
podman run --rm n8n-eks-operator:dev --help

echo ""
echo "✅ Container test successful!"
echo ""
echo "📋 What was tested:"
echo "  ✅ Go compilation of the operator"
echo "  ✅ Binary execution and help output"
echo "  ✅ Container image build with Podman"
echo "  ✅ Container execution"
echo ""
echo "🚀 The operator is ready! Next steps:"
echo "1. For local Kubernetes testing:"
echo "   - Install kubectl and kind: brew install kubectl kind"
echo "   - Run: make local-setup"
echo "   - Run: make local-deploy"
echo ""
echo "2. For production deployment:"
echo "   - Push image to registry: podman push n8n-eks-operator:dev <your-registry>"
echo "   - Deploy to EKS cluster using Helm charts"
echo ""
echo "📚 Documentation:"
echo "   - Enterprise features: docs/enterprise-features.md"
echo "   - Local development: docs/local-development.md"
echo "   - Examples: examples/enterprise/"