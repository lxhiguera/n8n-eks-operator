# n8n EKS Operator Makefile

# Image URL to use all building/pushing image targets
IMG ?= ghcr.io/lxhiguera/n8n-eks-operator:latest

# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.28.0

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Automatically detect podman or docker
CONTAINER_TOOL ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null || echo docker)

# Setting SHELL to bash allows bash commands to be executed by recipes.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter & yamllint
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

.PHONY: test
test: manifests generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test ./... -coverprofile cover.out

.PHONY: test-unit
test-unit: envtest ## Run unit tests only.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test ./... -short -coverprofile cover.out

.PHONY: test-integration
test-integration: ## Run integration tests.
	cd test/integration && make test

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests.
	cd test/e2e && make test

.PHONY: test-performance
test-performance: ## Run performance tests.
	cd test/performance && make test

.PHONY: test-security
test-security: ## Run security tests.
	cd test/security && make test

.PHONY: test-all
test-all: test test-integration test-e2e test-performance test-security ## Run all tests.

##@ Build

.PHONY: build
build: ## Build manager binary.
	go build -o bin/manager cmd/main_simple.go

.PHONY: build-full
build-full: manifests generate fmt vet ## Build manager binary with full code generation.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

# If you wish built the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64 ). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/dev-best-practices/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS defines the target platforms for  the manager image be build to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - able to use docker buildx . More info: https://docs.docker.com/build/buildx/
# - have a multi-arch builder. More info: https://docs.docker.com/build/building/multi-platform/
# - be able to push the image for your registry (i.e. if you do not inform a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To properly provided solutions that supports more than one platform you should use this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name project-v3-builder
	$(CONTAINER_TOOL) buildx use project-v3-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm project-v3-builder
	rm Dockerfile.cross

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

##@ Build Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUBECTL ?= kubectl
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
KUSTOMIZE_VERSION ?= v5.0.4-0.20230601165947-6ce0bf390ce3
CONTROLLER_TOOLS_VERSION ?= v0.11.4
GOLANGCI_LINT_VERSION ?= v1.54.2

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary. If wrong version is installed, it will be removed before downloading.
$(KUSTOMIZE): $(LOCALBIN)
	@if test -x $(LOCALBIN)/kustomize && ! $(LOCALBIN)/kustomize version | grep -q $(KUSTOMIZE_VERSION); then \
		echo "$(LOCALBIN)/kustomize version is not expected $(KUSTOMIZE_VERSION). Removing it before installing."; \
		rm -rf $(LOCALBIN)/kustomize; \
	fi
	test -s $(LOCALBIN)/kustomize || GOBIN=$(LOCALBIN) GO111MODULE=on go install sigs.k8s.io/kustomize/kustomize/v5@$(KUSTOMIZE_VERSION)

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary. If wrong version is installed, it will be overwritten.
$(CONTROLLER_GEN): $(LOCALBIN)
	test -s $(LOCALBIN)/controller-gen && $(LOCALBIN)/controller-gen --version | grep -q $(CONTROLLER_TOOLS_VERSION) || \
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
$(ENVTEST): $(LOCALBIN)
	test -s $(LOCALBIN)/setup-envtest || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	test -s $(LOCALBIN)/golangci-lint && $(LOCALBIN)/golangci-lint --version | grep -q $(GOLANGCI_LINT_VERSION) || \
	GOBIN=$(LOCALBIN) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

##@ Security

.PHONY: scan-vulnerabilities
scan-vulnerabilities: ## Scan for vulnerabilities using govulncheck
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not found. Installing..."; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
		govulncheck ./...; \
	fi

.PHONY: scan-image
scan-image: ## Scan Docker image for vulnerabilities using Trivy
	@if command -v trivy >/dev/null 2>&1; then \
		trivy image $(IMG); \
	else \
		echo "Trivy not found. Please install Trivy to scan images."; \
		echo "Installation: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"; \
	fi

##@ Quality

.PHONY: coverage
coverage: test ## Generate test coverage report
	go tool cover -html=cover.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: benchmark
benchmark: ## Run benchmarks
	go test -bench=. -benchmem ./...

.PHONY: mod-tidy
mod-tidy: ## Run go mod tidy
	go mod tidy

.PHONY: mod-verify
mod-verify: ## Verify go modules
	go mod verify

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf bin/
	rm -rf dist/
	rm -f cover.out coverage.html
	rm -f Dockerfile.cross

.PHONY: clean-tools
clean-tools: ## Clean downloaded tools
	rm -rf $(LOCALBIN)

##@ Release

.PHONY: release-dry-run
release-dry-run: ## Dry run of release process
	@echo "This would create a release with the following artifacts:"
	@echo "- Binary for linux/amd64"
	@echo "- Binary for linux/arm64"
	@echo "- Binary for darwin/amd64"
	@echo "- Binary for darwin/arm64"
	@echo "- Binary for windows/amd64"
	@echo "- Docker image: $(IMG)"
	@echo "- Helm chart"

.PHONY: release-build
release-build: ## Build release artifacts
	@echo "Building release artifacts..."
	mkdir -p dist
	
	# Build binaries for multiple platforms
	GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o dist/n8n-eks-operator-linux-amd64 cmd/main.go
	GOOS=linux GOARCH=arm64 go build -ldflags="-w -s" -o dist/n8n-eks-operator-linux-arm64 cmd/main.go
	GOOS=darwin GOARCH=amd64 go build -ldflags="-w -s" -o dist/n8n-eks-operator-darwin-amd64 cmd/main.go
	GOOS=darwin GOARCH=arm64 go build -ldflags="-w -s" -o dist/n8n-eks-operator-darwin-arm64 cmd/main.go
	GOOS=windows GOARCH=amd64 go build -ldflags="-w -s" -o dist/n8n-eks-operator-windows-amd64.exe cmd/main.go
	
	# Generate checksums
	cd dist && sha256sum * > checksums.txt

##@ Documentation

.PHONY: docs-serve
docs-serve: ## Serve documentation locally
	@if command -v mkdocs >/dev/null 2>&1; then \
		mkdocs serve; \
	else \
		echo "MkDocs not found. Install with: pip install mkdocs mkdocs-material"; \
	fi

.PHONY: docs-build
docs-build: ## Build documentation
	@if command -v mkdocs >/dev/null 2>&1; then \
		mkdocs build; \
	else \
		echo "MkDocs not found. Install with: pip install mkdocs mkdocs-material"; \
	fi

##@ Helm

.PHONY: helm-lint
helm-lint: ## Lint Helm chart
	@if command -v helm >/dev/null 2>&1; then \
		helm lint charts/n8n-eks-operator; \
	else \
		echo "Helm not found. Please install Helm to lint charts."; \
	fi

.PHONY: helm-template
helm-template: ## Generate Helm templates
	@if command -v helm >/dev/null 2>&1; then \
		helm template n8n-operator charts/n8n-eks-operator; \
	else \
		echo "Helm not found. Please install Helm to generate templates."; \
	fi

.PHONY: helm-package
helm-package: ## Package Helm chart
	@if command -v helm >/dev/null 2>&1; then \
		helm package charts/n8n-eks-operator -d dist/; \
	else \
		echo "Helm not found. Please install Helm to package charts."; \
	fi

##@ Development Environment

.PHONY: dev-setup
dev-setup: ## Setup development environment
	@echo "Setting up development environment..."
	go mod download
	$(MAKE) controller-gen
	$(MAKE) kustomize
	$(MAKE) envtest
	$(MAKE) golangci-lint
	@echo "Development environment setup complete!"

.PHONY: dev-reset
dev-reset: clean ## Reset development environment
	rm -rf $(LOCALBIN)
	go clean -modcache

.PHONY: pre-commit
pre-commit: fmt vet lint test-unit ## Run pre-commit checks
	@echo "Pre-commit checks passed!"

##@ CI/CD

.PHONY: ci-test
ci-test: ## Run CI test suite
	$(MAKE) lint
	$(MAKE) test-unit
	$(MAKE) scan-vulnerabilities

.PHONY: ci-build
ci-build: ## Run CI build
	$(MAKE) docker-build

.PHONY: ci-security
ci-security: ## Run CI security checks
	$(MAKE) scan-vulnerabilities
	$(MAKE) test-security

##@ Local Development

.PHONY: local-setup
local-setup: ## Setup local development environment with Kind
	@chmod +x scripts/local-dev-setup.sh
	@scripts/local-dev-setup.sh

.PHONY: local-deploy
local-deploy: build docker-build ## Deploy operator to local Kind cluster
	@echo "Deploying operator to local cluster..."
	kind load docker-image n8n-eks-operator:dev --name n8n-operator-dev
	kubectl apply -f config/crd/bases/ || true
	kubectl apply -f examples/local/support-services.yaml
	@echo "Waiting for support services to be ready..."
	kubectl wait --for=condition=ready pod -l app=postgres --timeout=300s
	kubectl wait --for=condition=ready pod -l app=redis --timeout=300s
	@echo "Deploying operator..."
	kubectl create deployment n8n-eks-operator --image=n8n-eks-operator:dev -n n8n-system --dry-run=client -o yaml | kubectl apply -f -
	@echo "✅ Operator deployed! You can now create N8nInstance resources."

.PHONY: local-test
local-test: ## Deploy a test N8nInstance to local cluster
	kubectl apply -f examples/local/basic-n8n-instance.yaml
	@echo "✅ Test N8nInstance created!"
	@echo "Monitor with: kubectl get n8ninstances -w"

.PHONY: local-logs
local-logs: ## Show operator logs in local cluster
	kubectl logs -f deployment/n8n-eks-operator -n n8n-system

.PHONY: local-cleanup
local-cleanup: ## Cleanup local development environment
	kind delete cluster --name n8n-operator-dev || true

##@ Utilities

.PHONY: version
version: ## Show version information
	@echo "n8n EKS Operator"
	@echo "Go version: $(shell go version)"
	@echo "Git commit: $(shell git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
	@echo "Build date: $(shell date -u +%Y-%m-%dT%H:%M:%SZ)"

.PHONY: deps-update
deps-update: ## Update dependencies
	go get -u ./...
	go mod tidy

.PHONY: deps-check
deps-check: ## Check for outdated dependencies
	@echo "Checking for outdated dependencies..."
	@go list -u -m all | grep '\['

# Default target
.DEFAULT_GOAL := help