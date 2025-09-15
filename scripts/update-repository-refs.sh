#!/bin/bash

set -e

echo "🔄 Updating repository references to lxhiguera/n8n-eks-operator"

# Define the new repository details
NEW_USER="lxhiguera"
NEW_REPO="n8n-eks-operator"
OLD_USER="n8n-io"
OLD_REPO="n8n-eks-operator"

echo "📝 Updating Go module references..."

# Update go.mod
if [ -f "go.mod" ]; then
    sed -i '' "s|github.com/${OLD_USER}/${OLD_REPO}|github.com/${NEW_USER}/${NEW_REPO}|g" go.mod
    echo "✅ Updated go.mod"
fi

# Update go.sum if it exists
if [ -f "go.sum" ]; then
    sed -i '' "s|github.com/${OLD_USER}/${OLD_REPO}|github.com/${NEW_USER}/${NEW_REPO}|g" go.sum
    echo "✅ Updated go.sum"
fi

echo "📝 Updating Go source files..."

# Update all Go files
find . -name "*.go" -type f -exec sed -i '' "s|github.com/${OLD_USER}/${OLD_REPO}|github.com/${NEW_USER}/${NEW_REPO}|g" {} +
echo "✅ Updated Go source files"

echo "📝 Updating GitHub workflows..."

# Update GitHub workflows
find .github -name "*.yml" -o -name "*.yaml" -type f -exec sed -i '' "s|${OLD_USER}/${OLD_REPO}|${NEW_USER}/${NEW_REPO}|g" {} +
find .github -name "*.yml" -o -name "*.yaml" -type f -exec sed -i '' "s|ghcr.io/${OLD_USER}/|ghcr.io/${NEW_USER}/|g" {} +
echo "✅ Updated GitHub workflows"

echo "📝 Updating Helm charts..."

# Update Helm charts
find charts -name "*.yaml" -o -name "*.yml" -type f -exec sed -i '' "s|${OLD_USER}/${OLD_REPO}|${NEW_USER}/${NEW_REPO}|g" {} +
find charts -name "*.yaml" -o -name "*.yml" -type f -exec sed -i '' "s|ghcr.io/${OLD_USER}/|ghcr.io/${NEW_USER}/|g" {} +
echo "✅ Updated Helm charts"

echo "📝 Updating documentation..."

# Update documentation files
find docs -name "*.md" -type f -exec sed -i '' "s|${OLD_USER}/${OLD_REPO}|${NEW_USER}/${NEW_REPO}|g" {} +
find docs -name "*.md" -type f -exec sed -i '' "s|ghcr.io/${OLD_USER}/|ghcr.io/${NEW_USER}/|g" {} +
find docs -name "*.md" -type f -exec sed -i '' "s|charts.n8n.io|charts.${NEW_USER}.io|g" {} +
echo "✅ Updated documentation"

echo "📝 Updating examples..."

# Update example files
find examples -name "*.yaml" -o -name "*.yml" -type f -exec sed -i '' "s|${OLD_USER}/${OLD_REPO}|${NEW_USER}/${NEW_REPO}|g" {} +
find examples -name "*.yaml" -o -name "*.yml" -type f -exec sed -i '' "s|ghcr.io/${OLD_USER}/|ghcr.io/${NEW_USER}/|g" {} +
echo "✅ Updated examples"

echo "📝 Updating root files..."

# Update root markdown files
for file in *.md; do
    if [ -f "$file" ]; then
        sed -i '' "s|${OLD_USER}/${OLD_REPO}|${NEW_USER}/${NEW_REPO}|g" "$file"
        sed -i '' "s|ghcr.io/${OLD_USER}/|ghcr.io/${NEW_USER}/|g" "$file"
        sed -i '' "s|charts.n8n.io|charts.${NEW_USER}.io|g" "$file"
    fi
done
echo "✅ Updated root files"

echo "📝 Updating Makefile..."

# Update Makefile
if [ -f "Makefile" ]; then
    sed -i '' "s|${OLD_USER}/${OLD_REPO}|${NEW_USER}/${NEW_REPO}|g" Makefile
    sed -i '' "s|ghcr.io/${OLD_USER}/|ghcr.io/${NEW_USER}/|g" Makefile
    echo "✅ Updated Makefile"
fi

echo "📝 Updating Dockerfile..."

# Update Dockerfile
if [ -f "Dockerfile" ]; then
    sed -i '' "s|${OLD_USER}/${OLD_REPO}|${NEW_USER}/${NEW_REPO}|g" Dockerfile
    echo "✅ Updated Dockerfile"
fi

echo "📝 Updating scripts..."

# Update script files
find scripts -name "*.sh" -type f -exec sed -i '' "s|${OLD_USER}/${OLD_REPO}|${NEW_USER}/${NEW_REPO}|g" {} +
find scripts -name "*.sh" -type f -exec sed -i '' "s|ghcr.io/${OLD_USER}/|ghcr.io/${NEW_USER}/|g" {} +
echo "✅ Updated scripts"

echo "📝 Updating test files..."

# Update test files
find test -name "*.go" -o -name "*.yaml" -o -name "*.yml" -type f -exec sed -i '' "s|${OLD_USER}/${OLD_REPO}|${NEW_USER}/${NEW_REPO}|g" {} +
find test -name "*.go" -o -name "*.yaml" -o -name "*.yml" -type f -exec sed -i '' "s|ghcr.io/${OLD_USER}/|ghcr.io/${NEW_USER}/|g" {} +
echo "✅ Updated test files"

echo ""
echo "✅ Repository references updated successfully!"
echo ""
echo "📋 Summary of changes:"
echo "   - Repository: github.com/${NEW_USER}/${NEW_REPO}"
echo "   - Container registry: ghcr.io/${NEW_USER}/"
echo "   - Helm repository: charts.${NEW_USER}.io"
echo ""
echo "🔄 Next steps:"
echo "1. Review the changes: git diff"
echo "2. Test the build: make build"
echo "3. Initialize git repository: git init"
echo "4. Add files: git add ."
echo "5. Commit: git commit -m 'Initial commit'"
echo "6. Create GitHub repository: gh repo create ${NEW_USER}/${NEW_REPO} --public"
echo "7. Push: git push -u origin main"