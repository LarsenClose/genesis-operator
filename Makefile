# Genesis Makefile

# Version info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Image configuration
IMG ?= ghcr.io/larsenclose/genesis-operator:$(VERSION)

# Go configuration
GOFLAGS ?= -trimpath
LDFLAGS = -w -s -X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildDate=$(BUILD_DATE)

# Tools
CONTROLLER_GEN ?= $(shell which controller-gen)
HELM ?= $(shell which helm)
KIND ?= $(shell which kind)
KUBECTL ?= $(shell which kubectl)

# --- Rust Core ---
RUST_DIR := genesis-core
RUST_LIB := $(RUST_DIR)/target/release/libgenesis_core.a
RUST_HEADER := internal/bridge/genesis_core.h

.PHONY: rust-build rust-build-test rust-test rust-lint rust-header rust-clean rust-audit

rust-build: ## Build the Rust static library
	cd $(RUST_DIR) && cargo build --release

rust-build-test: ## Build Rust static library with mock feature for testing
	cd $(RUST_DIR) && cargo build --release --features mock

rust-test: ## Run Rust tests
	cd $(RUST_DIR) && cargo test

rust-lint: ## Run Rust linter (clippy)
	cd $(RUST_DIR) && cargo clippy --all-targets -- -D warnings
	cd $(RUST_DIR) && cargo fmt --check

rust-header: rust-build ## Generate C header from Rust and copy to bridge
	cd $(RUST_DIR) && cbindgen --config cbindgen.toml --output genesis_core.h
	cp $(RUST_DIR)/genesis_core.h $(RUST_HEADER)

rust-clean: ## Clean Rust build artifacts
	cd $(RUST_DIR) && cargo clean

rust-audit: ## Run cargo audit on Rust dependencies
	cd $(RUST_DIR) && cargo audit

# --- Go ---

.PHONY: all
all: rust-build build

##@ General

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: generate
generate: ## Generate code (deepcopy, CRDs)
	$(CONTROLLER_GEN) object:headerFile="" paths="./pkg/api/..."
	$(CONTROLLER_GEN) crd paths="./pkg/api/..." output:crd:artifacts:config=config/crd/bases
	cp config/crd/bases/*.yaml charts/genesis-operator/crds/

.PHONY: fmt
fmt: ## Run go fmt
	go fmt ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: rust-lint ## Run linters
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, skipping"; \
	fi

# Coverage excludes auto-generated code and test mocks
COVERAGE_EXCLUDE_PATTERN := "(pkg/api/v1alpha1|cmd/operator|internal/kms/mock)$$"
COVERAGE_PACKAGES := $(shell go list ./... | grep -v -E $(COVERAGE_EXCLUDE_PATTERN))

.PHONY: test
test: rust-build-test rust-test ## Run unit tests
	go test -tags genesis_mock ./... -v -coverprofile=coverage.out

.PHONY: test-coverage
test-coverage: test ## Run tests with coverage report
	go tool cover -html=coverage.out -o coverage.html

.PHONY: test-filtered
test-filtered: rust-build-test ## Run unit tests with filtered coverage (excludes generated code)
	go test -tags genesis_mock $(COVERAGE_PACKAGES) -v -coverprofile=coverage-filtered.out
	@echo "Coverage report (excluding auto-generated code):"
	@go tool cover -func=coverage-filtered.out | tail -1

.PHONY: test-coverage-filtered
test-coverage-filtered: test-filtered ## Run filtered tests with HTML coverage report
	go tool cover -html=coverage-filtered.out -o coverage-filtered.html
	@echo "Coverage report saved to coverage-filtered.html"

##@ Build

.PHONY: build
build: rust-build ## Build the CLI and operator binaries
	CGO_ENABLED=1 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/genesis ./cmd/genesis
	CGO_ENABLED=1 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/genesis-operator ./cmd/operator

.PHONY: build-cli
build-cli: rust-build ## Build only the CLI
	CGO_ENABLED=1 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/genesis ./cmd/genesis

.PHONY: build-operator
build-operator: rust-build ## Build only the operator
	CGO_ENABLED=1 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/genesis-operator ./cmd/operator

.PHONY: docker-build
docker-build: ## Build Docker image
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_DATE=$(BUILD_DATE) -t $(IMG) .

.PHONY: docker-push
docker-push: ## Push Docker image
	docker push $(IMG)

##@ Security

.PHONY: check-key-material
check-key-material: ## Verify no unexpected key material references in Go layer
	@echo "Checking for key material in Go layer..."
	@VIOLATIONS=$$(grep -rn 'privateKey\|PrivateKey\|\.agekey\|age\.Identity\|AgeDecrypt\|AgeKeypair' \
		--include='*.go' \
		internal/bridge/ internal/controller/ cmd/ \
		| grep -v '_test.go' \
		| grep -v 'bridge.go' \
		| grep -v '// safe: public key only' \
		| grep -v '// safe: bridge handle' \
		| grep -v 'unseal\.go' \
		| grep -v 'rotate\.go' \
		| grep -v 'age\.agekey' \
		| grep -v 'LegacyBootstrapInjector' \
		| grep -v '// legacy-go-path: test-only' \
	); \
	if [ -n "$$VIOLATIONS" ]; then \
		echo "$$VIOLATIONS"; \
		echo "FAIL: Unexpected key material reference in Go layer"; \
		exit 1; \
	else \
		echo "PASS: No unexpected key material references in Go layer"; \
	fi
	@echo "Checking for unauthorized crypto/envelope package imports..."
	@IMPORT_VIOLATIONS=$$(grep -rn '"github.com/larsenclose/genesis/internal/crypto\|"github.com/larsenclose/genesis/internal/envelope' \
		internal/ cmd/ \
		--include="*.go" \
		| grep -v '_test.go' \
		| grep -v 'bridge.go' \
		| grep -v 'unseal.go' \
		| grep -v 'rotate.go' \
		| grep -v 'internal/crypto/' \
		| grep -v 'internal/envelope/' \
		|| true); \
	if [ -n "$$IMPORT_VIOLATIONS" ]; then \
		echo "FAIL: Unauthorized crypto/envelope imports found:"; \
		echo "$$IMPORT_VIOLATIONS"; \
		exit 1; \
	fi
	@echo "No unauthorized imports found."

##@ Deployment

.PHONY: install-crds
install-crds: ## Install CRDs into the cluster
	$(KUBECTL) apply -f config/crd/bases/

.PHONY: uninstall-crds
uninstall-crds: ## Uninstall CRDs from the cluster
	$(KUBECTL) delete -f config/crd/bases/ --ignore-not-found

.PHONY: helm-install
helm-install: ## Install the operator using Helm
	$(HELM) upgrade --install genesis-operator charts/genesis-operator \
		--namespace genesis-system --create-namespace

.PHONY: helm-uninstall
helm-uninstall: ## Uninstall the operator using Helm
	$(HELM) uninstall genesis-operator --namespace genesis-system

.PHONY: helm-template
helm-template: ## Render Helm chart templates
	$(HELM) template genesis-operator charts/genesis-operator --namespace genesis-system

.PHONY: helm-lint
helm-lint: ## Lint Helm chart
	$(HELM) lint charts/genesis-operator

##@ E2E Testing

.PHONY: kind-create
kind-create: ## Create a kind cluster for testing
	$(KIND) create cluster --name genesis-test --wait 5m

.PHONY: kind-delete
kind-delete: ## Delete the kind test cluster
	$(KIND) delete cluster --name genesis-test

.PHONY: kind-load
kind-load: docker-build ## Load the image into kind
	$(KIND) load docker-image $(IMG) --name genesis-test

.PHONY: e2e-setup
e2e-setup: kind-create kind-load install-crds ## Setup E2E test environment
	@echo "E2E environment ready"

.PHONY: e2e-test
e2e-test: ## Run E2E tests (requires e2e-setup first)
	go test ./test/e2e/... -v -tags=e2e -timeout 10m

.PHONY: e2e-cleanup
e2e-cleanup: kind-delete ## Cleanup E2E test environment

.PHONY: e2e
e2e: e2e-setup e2e-test e2e-cleanup ## Run full E2E test cycle

##@ Utilities

.PHONY: clean
clean: rust-clean ## Clean all build artifacts
	rm -rf bin/ coverage.out coverage.html

.PHONY: tidy
tidy: ## Run go mod tidy
	go mod tidy

.PHONY: verify
verify: rust-lint rust-test fmt vet lint test ## Run all verification steps
	@echo "All verification passed"
