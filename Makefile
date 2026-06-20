# vctl Makefile
BINARY      := vctl
PKG         := ./cmd/vctl
BIN_DIR     := bin
BIN         := $(BIN_DIR)/$(BINARY)
VERSION     ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)
GOFILES     := $(shell find . -name '*.go' -not -path './vendor/*')

# Pass arguments with: make run ARGS="ssh 0047"
ARGS ?=

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: $(BIN) ## Build binary to bin/vctl

$(BIN): $(GOFILES) go.mod
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)
	@echo "built $(BIN)"

.PHONY: install
install: ## Install to $GOBIN with go install
	go install -trimpath -ldflags '$(LDFLAGS)' $(PKG)

.PHONY: run
run: ## Run without building: make run ARGS="status"
	go run $(PKG) $(ARGS)

.PHONY: fmt
fmt: ## Format Go files
	gofmt -w $(GOFILES)

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: test
test: ## Run unit tests
	go test ./...

.PHONY: check
check: fmt vet test ## fmt + vet + test

.PHONY: trivy
trivy: ## Scan dependencies, config, and secrets with Trivy
	trivy fs --scanners vuln,secret,misconfig .

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy

.PHONY: smoke
smoke: build ## Run Vault-backed smoke tests
	@VCTL_BIN=$(BIN) ./scripts/smoke.sh

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)
