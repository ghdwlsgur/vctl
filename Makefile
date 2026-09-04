# vctl Makefile
BINARY      := vctl
PKG         := ./cmd/vctl
BIN_DIR     := bin
BIN         := $(BIN_DIR)/$(BINARY)
# The fleet-host slice: daemons and login hooks only, no operator commands.
AGENT_PKG   := ./cmd/vctl-agent
AGENT_BIN   := $(BIN_DIR)/$(BINARY)-agent
VERSION     ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)
GOFILES     := $(shell find . -name '*.go' -not -path './vendor/*')
EMBED_FILES := internal/cli/wg_serve.html internal/cli/wg_model.js internal/cli/wg_view.js

# Pass arguments with: make run ARGS="ssh 0047"
ARGS ?=

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: $(BIN) $(AGENT_BIN) ## Build binaries to bin/vctl and bin/vctl-agent

$(BIN): $(GOFILES) $(EMBED_FILES) go.mod
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)
	@echo "built $(BIN)"

$(AGENT_BIN): $(GOFILES) $(EMBED_FILES) go.mod
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(AGENT_BIN) $(AGENT_PKG)
	@echo "built $(AGENT_BIN)"

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

.PHONY: lint
# Run through `go run` at pinned versions so the tools are built against the
# toolchain in use: a linter binary installed by an older Go dies on a newer
# stdlib with "file requires newer Go version", and a silent linter is worse
# than none. Not folded into `check` — it needs the module cache warm.
lint: ## staticcheck + deadcode
	go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
	go run golang.org/x/tools/cmd/deadcode@v0.49.0 -test ./...

.PHONY: check
check: fmt vet test ## fmt + vet + test

.PHONY: trivy
trivy: ## Scan dependencies, config, and secrets with Trivy
	trivy fs --scanners vuln,secret,misconfig .

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy

# --- WireGuard dashboard (vctl wg serve) --------------------------------------
# Start it, get a link, stop it. The point of the pair is the second half: the
# dashboard holds an SSH session open to every gateway and polls them every two
# seconds, so one left running is load on production hardware nobody is looking
# at. wg-down is what makes wg-up safe to run casually.
#
#   make wg-up                 # prints http://127.0.0.1:8420
#   make wg-up WG_PORT=9000    # when 8420 is taken
#   make wg-down
#
# Loopback only, and deliberately not a variable. The topology names every
# gateway, subnet and VM in the fleet, and a bind address is one careless flag
# away from putting that on a coffee-shop network. Anyone who genuinely wants it
# on a LAN can say so themselves and own the choice:
#
#   ./bin/vctl wg serve --addr 0.0.0.0:8420
#
# The drawing comes from Postgres and is only as current as the last
# `vctl wg sync` — the title bar says how old. The traffic on it is live.
WG_PORT ?= 8420
WG_URL  := http://127.0.0.1:$(WG_PORT)
WG_PID  := $(BIN_DIR)/wg-serve.pid
WG_LOG  := $(BIN_DIR)/wg-serve.log

.PHONY: wg-up
# One shell for the whole recipe, not one per line.
#
# Make gives each recipe line its own shell, so the `exit 0` in the
# already-running guard ended that line and make cheerfully ran the next one —
# a second dashboard, and the pid file overwritten with the second pid. The
# first was then unkillable by wg-down and kept polling every gateway with
# nothing on disk pointing at it. Measured: two `make wg-up` in a row left an
# orphan holding SSH sessions open to twelve production gateways.
wg-up: build ## Start the WireGuard dashboard on 127.0.0.1 and print the link
	@set -e; \
	if [ -f $(WG_PID) ] && kill -0 "$$(cat $(WG_PID))" 2>/dev/null; then \
		echo "already running (pid $$(cat $(WG_PID))) — $(WG_URL)"; exit 0; \
	fi; \
	rm -f $(WG_PID); \
	echo "starting — the first contact with Vault and Postgres takes a moment"; \
	nohup $(BIN) wg serve --addr 127.0.0.1:$(WG_PORT) > $(WG_LOG) 2>&1 & \
	pid=$$!; echo $$pid > $(WG_PID); \
	i=0; while [ $$i -lt 90 ]; do \
		if ! kill -0 "$$pid" 2>/dev/null; then \
			echo "it exited before it was listening:"; \
			sed 's/^/    /' $(WG_LOG); rm -f $(WG_PID); exit 1; \
		fi; \
		if curl -sf -o /dev/null --max-time 2 $(WG_URL); then \
			printf '\n    %s\n\n' "$(WG_URL)"; \
			echo "    log:  $(WG_LOG)"; \
			echo "    stop: make wg-down    # leaves the gateways alone again"; \
			exit 0; \
		fi; \
		i=$$((i+1)); sleep 1; \
	done; \
	echo "no answer after 90s; last output:"; sed 's/^/    /' $(WG_LOG); exit 1

.PHONY: wg-down
wg-down: ## Stop the dashboard and its gateway polling
	@set -e; \
	if [ ! -f $(WG_PID) ]; then echo "not running (no $(WG_PID))"; exit 0; fi; \
	pid=$$(cat $(WG_PID)); \
	if [ -z "$$pid" ] || ! kill -0 "$$pid" 2>/dev/null; then \
		echo "stale pid file ($${pid:-empty}) — removing"; rm -f $(WG_PID); exit 0; \
	fi; \
	kill "$$pid" 2>/dev/null || true; \
	i=0; while kill -0 "$$pid" 2>/dev/null && [ $$i -lt 10 ]; do i=$$((i+1)); sleep 1; done; \
	if kill -0 "$$pid" 2>/dev/null; then \
		echo "pid $$pid ignored SIGTERM; sending SIGKILL"; kill -9 "$$pid" 2>/dev/null || true; \
	fi; \
	rm -f $(WG_PID); echo "stopped (pid $$pid) — gateway polling has ended"

.PHONY: wg-check
# What the dashboard actually draws, measured under headless Chrome against the
# page Go serves. `make check` cannot see this: the Go tests assert on what the
# model returns, and every filtering bug so far has been in what was left on the
# screen afterwards. Needs node and Chrome; set CHROME=/path/to/chrome if it is
# not where the script looks. No database, no SSH, no gateway is touched.
#
# CI runs it too, as the "WireGuard Dashboard" job, so a layout change that only
# breaks in a browser fails the pull request rather than the next person to open
# the page.
wg-check: ## Measure the WireGuard dashboard under headless Chrome
	@node scripts/wg-dashboard-check.mjs

.PHONY: smoke
smoke: build ## Run Vault-backed smoke tests
	@VCTL_BIN=$(BIN) ./scripts/smoke.sh

# --- Fleet onboarding (Ansible role: deploy/ansible) — see deploy/ansible/README.md ---
# Needs ansible + a control-node Vault token (VAULT_TOKEN) for the vctl-host secret_id.
# Inventory comes from ansible.cfg (inventory/hosts.ini); LIMIT scopes the run.
#   make onboard LIMIT=sre-srv-0023                                    # one canary
#   make onboard LIMIT=seoul_onprem EXTRA="-e vctl_host_install_collect=false -e vctl_host_install_tetragon=false"
#   make onboard LIMIT=incheon_onprem EXTRA="-e vctl_host_sre_lb_ip=<lb>"
ANSIBLE_DIR := deploy/ansible
LIMIT       ?=
EXTRA       ?=
_ANSIBLE     = cd $(ANSIBLE_DIR) && ansible-playbook $(if $(LIMIT),-l $(LIMIT),) $(EXTRA)

.PHONY: onboard-syntax
onboard-syntax: ## Syntax-check the onboarding playbooks
	cd $(ANSIBLE_DIR) && ansible-playbook --syntax-check site.yml trust-vault-ssh-ca.yml

.PHONY: trust-ca-fleet
trust-ca-fleet: ## Install Vault SSH CA trust on hosts: make trust-ca-fleet LIMIT=<host|group>
	$(_ANSIBLE) trust-vault-ssh-ca.yml

.PHONY: onboard-check
onboard-check: ## Dry-run the host-stack install: make onboard-check LIMIT=<host>
	$(_ANSIBLE) site.yml --check --diff

.PHONY: onboard
onboard: ## Install host stack (node-agent+watch[+collect]): make onboard LIMIT=<host|group>
	$(_ANSIBLE) site.yml

.PHONY: onboard-rollback
onboard-rollback: ## Remove the host stack: make onboard-rollback LIMIT=<host>
	$(_ANSIBLE) site.yml -e vctl_host_state=absent

.PHONY: clean
# Stops the dashboard first. bin/ holds its pid file, so removing the directory
# under a running one orphans a process that keeps polling every gateway with
# nothing left on disk to say it exists.
clean: wg-down ## Remove build artifacts
	rm -rf $(BIN_DIR)
