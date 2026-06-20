# vctl — Makefile
BINARY      := vctl
PKG         := ./cmd/vctl
BIN_DIR     := bin
BIN         := $(BIN_DIR)/$(BINARY)
VERSION     ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)
GOFILES     := $(shell find . -name '*.go' -not -path './vendor/*')

# `make run ARGS="ssh 0047"` 처럼 인자 전달
ARGS ?=

.DEFAULT_GOAL := help

.PHONY: help
help: ## 사용 가능한 타깃 목록
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: $(BIN) ## 바이너리 빌드 → bin/vctl

$(BIN): $(GOFILES) go.mod
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)
	@echo "→ $(BIN)"

.PHONY: install
install: ## $GOBIN 에 설치 (go install)
	go install -trimpath -ldflags '$(LDFLAGS)' $(PKG)

.PHONY: run
run: ## 빌드 없이 실행:  make run ARGS="status"
	go run $(PKG) $(ARGS)

.PHONY: fmt
fmt: ## gofmt 적용
	gofmt -w $(GOFILES)

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: test
test: ## 단위 테스트
	go test ./...

.PHONY: check
check: fmt vet test ## fmt + vet + test

.PHONY: trivy
trivy: ## Trivy 로 의존성/설정/시크릿 스캔
	trivy fs --scanners vuln,secret,misconfig .

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy

.PHONY: smoke
smoke: build ## 현재 Vault 연결 스모크 테스트 (scripts/smoke.sh)
	@VCTL_BIN=$(BIN) ./scripts/smoke.sh

.PHONY: clean
clean: ## 산출물 삭제
	rm -rf $(BIN_DIR)
