#!/bin/bash

set -e

echo "🚀 Initializing n8n EKS Operator repository for lxhiguera"

# Check if we're already in a git repository
if [ -d ".git" ]; then
    echo "⚠️  Git repository already exists. Skipping git init."
else
    echo "📁 Initializing Git repository..."
    git init
    echo "✅ Git repository initialized"
fi

# Create .gitignore if it doesn't exist
if [ ! -f ".gitignore" ]; then
    echo "📝 Creating .gitignore..."
    cat > .gitignore << 'EOF'
# Binaries for programs and plugins
*.exe
*.exe~
*.dll
*.so
*.dylib
bin/
dist/

# Test binary, built with `go test -c`
*.test

# Output of the go coverage tool, specifically when used with LiteIDE
*.out
coverage.html

# Dependency directories (remove the comment below to include it)
vendor/

# Go workspace file
go.work

# IDE files
.vscode/
.idea/
*.swp
*.swo
*~

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Kubernetes
kubeconfig
*.kubeconfig

# Helm
charts/*.tgz

# Temporary files
*.tmp
*.temp
.tmp/
.temp/

# Logs
*.log
logs/

# Environment files
.env
.env.local
.env.*.local

# Build artifacts
*.tar.gz
*.zip

# Test results
test-results/
coverage/

# Local development
.local/
local/

# Secrets (just in case)
secrets/
*.pem
*.key
*.crt

# Kiro specs (development artifacts)
.kiro/
EOF
    echo "✅ .gitignore created"
fi

# Add all files
echo "📦 Adding files to Git..."
git add .

# Check if there are any changes to commit
if git diff --cached --quiet; then
    echo "ℹ️  No changes to commit"
else
    echo "💾 Creating initial commit..."
    git commit -m "Initial commit: n8n EKS Operator with Enterprise features

- Complete Kubernetes operator for n8n on EKS
- Enterprise features: multi-tenancy, SSO, audit logging
- AWS native integration: RDS, ElastiCache, S3, CloudFront
- Comprehensive documentation and examples
- Local development and testing setup
- Helm charts for easy deployment

This is a community-maintained operator, not affiliated with n8n.io"
    echo "✅ Initial commit created"
fi

# Set up main branch
echo "🌿 Setting up main branch..."
git branch -M main

echo ""
echo "✅ Repository initialized successfully!"
echo ""
echo "📋 Repository details:"
echo "   - Repository: github.com/lxhiguera/n8n-eks-operator"
echo "   - Branch: main"
echo "   - License: Apache 2.0"
echo "   - Files: $(git ls-files | wc -l | tr -d ' ') files committed"
echo ""
echo "🔄 Next steps:"
echo "1. Create GitHub repository:"
echo "   gh repo create lxhiguera/n8n-eks-operator --public --description 'Community Kubernetes operator for n8n on EKS with enterprise features'"
echo ""
echo "2. Push to GitHub:"
echo "   git remote add origin https://github.com/lxhiguera/n8n-eks-operator.git"
echo "   git push -u origin main"
echo ""
echo "3. Set up GitHub Pages for Helm charts (optional):"
echo "   - Go to repository Settings > Pages"
echo "   - Select 'Deploy from a branch' and choose 'gh-pages'"
echo ""
echo "4. Test the operator:"
echo "   make build"
echo "   ./scripts/test-operator.sh"
echo ""
echo "🎉 Your n8n EKS Operator repository is ready!"