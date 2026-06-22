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

# --- Fleet onboarding (Ansible) — see deploy/ansible/README.md ---
# Needs ansible + a control-node Vault token (VAULT_TOKEN) for vctl-host secret_id.
#   make onboard LIMIT=sre-srv-0023                 # one canary
#   make onboard LIMIT=seoul_wave1                  # a wave
#   make onboard LIMIT=k8s_nodes EXTRA="-e install_tetragon=false"
ANSIBLE_DIR := deploy/ansible
INVENTORY   ?= inventory.ini
LIMIT       ?=
EXTRA       ?=
_ANSIBLE     = cd $(ANSIBLE_DIR) && ansible-playbook -i $(INVENTORY) $(if $(LIMIT),-l $(LIMIT),) $(EXTRA)

.PHONY: onboard-syntax
onboard-syntax: ## Syntax-check the onboarding playbooks
	cd $(ANSIBLE_DIR) && ansible-playbook --syntax-check audit-onboard.yml trust-vault-ssh-ca.yml

.PHONY: trust-ca-fleet
trust-ca-fleet: ## Install Vault SSH CA trust on hosts: make trust-ca-fleet LIMIT=<host|group>
	$(_ANSIBLE) trust-vault-ssh-ca.yml

.PHONY: onboard-check
onboard-check: ## Dry-run the full host-stack install: make onboard-check LIMIT=<host>
	$(_ANSIBLE) audit-onboard.yml --check --diff

.PHONY: onboard
onboard: ## Install full host stack (collector+watch+node-agent): make onboard LIMIT=<host|group>
	$(_ANSIBLE) audit-onboard.yml

.PHONY: onboard-rollback
onboard-rollback: ## Remove the host stack: make onboard-rollback LIMIT=<host>
	$(_ANSIBLE) audit-onboard.yml -e state=absent

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)
