# Makefile to run CI via GitHub Actions (act)
#
# Executes the workflows in .github/workflows/ locally using act.
# No command duplication — runs the actual workflow definitions.
#
# Prerequisites:
#   - curl (to fetch act)
#   - Docker (required by act)
#
# Usage:
#   make ci          - run all configured CI workflows
#   make act-env     - download act to .bin/ (done automatically)
#   make ci-<name>   - run a specific workflow

.PHONY: ci ci-lint ci-static-lint ci-security-audit ci-docs-link-check ci-cie-oidc ci-docker-compose act-env help

BIN_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST)))).bin
ACT_VERSION := 0.2.84

# Default event for workflows (push to master/dev)
ACT_EVENT ?= push

help:
	@echo "CI via act (GitHub Actions runner):"
	@echo "  make ci                 - run all CI workflows"
	@echo "  make act-env             - download act to .bin/ (v$(ACT_VERSION))"
	@echo "  make ci-lint             - lint.yml"
	@echo "  make ci-static-lint      - static-lint.yml"
	@echo "  make ci-security-audit   - security-audit.yml"
	@echo "  make ci-docs-link-check  - docs-link-check.yml"
	@echo "  make ci-cie-oidc         - cie-oidc-backend.yml"
	@echo "  make ci-docker-compose   - docker-compose-test.yml"
	@echo ""
	@echo "Requires: Docker"

# Download act to .bin/ if not found in PATH
act-env:
	@if command -v act >/dev/null 2>&1; then \
		echo "Using system act"; \
	elif [ -f "$(BIN_DIR)/act" ]; then \
		echo "Using $(BIN_DIR)/act"; \
	else \
		ACT_VERSION=$(ACT_VERSION) bash .github/scripts/install-act.sh "$(BIN_DIR)"; \
	fi

ci: ci-lint ci-static-lint ci-security-audit ci-docs-link-check ci-cie-oidc ci-docker-compose

define run_act
	@ACT="$$(command -v act 2>/dev/null || echo '$(BIN_DIR)/act')"; \
	"$$ACT" $(ACT_EVENT) -W $(1)
endef

ci-lint: act-env
	$(call run_act,.github/workflows/lint.yml)

ci-static-lint: act-env
	$(call run_act,.github/workflows/static-lint.yml)

ci-security-audit: act-env
	$(call run_act,.github/workflows/security-audit.yml)

ci-docs-link-check: act-env
	$(call run_act,.github/workflows/docs-link-check.yml)

ci-cie-oidc: act-env
	$(call run_act,.github/workflows/cie-oidc-backend.yml)

ci-docker-compose: act-env
	$(call run_act,.github/workflows/docker-compose-test.yml)
