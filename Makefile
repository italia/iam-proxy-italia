# Makefile to run CI checks locally (mirrors .github/workflows/)
#
# Uses local .venv (Python), .node (Node.js), .bin (lychee) - no system pollution.
#
# Prerequisites:
#   - Python 3.10+ (for .venv)
#   - curl (to fetch Node.js, lychee)
#   - Docker (for docker-compose)
#
# Usage:
#   make ci          - run all configured CI
#   make venv        - create/update local .venv (done automatically by ci-*)
#   make node-env    - create/update local .node (Node 20, for static-lint)
#   make lychee-env  - create/update local .bin/lychee (for docs-link-check)
#   make ci-lint     - run lint only
#   make ci-<target> - run specific CI job

.PHONY: ci ci-lint ci-static-lint ci-security-audit ci-docs-link-check ci-cie-oidc ci-docker-compose patch-pyeudiw venv node-env lychee-env help

VENV := .venv
NODE_DIR := .node
NODE_BIN := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))$(NODE_DIR)/bin
BIN_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST)))).bin
LYCHEE_VERSION := 0.23.0
NODE_VERSION := 20.18.0
PYTHON ?= python3

# For patch-pyeudiw-branch.sh
CURRENT_BRANCH ?= $(shell git branch --show-current 2>/dev/null || echo master)
TARGET_BRANCH ?= master

help:
	@echo "CI targets (mirror .github/workflows/):"
	@echo "  make ci                 - run all CI"
	@echo "  make venv               - create/update local .venv"
	@echo "  make node-env           - create/update local .node (Node $(NODE_VERSION))"
	@echo "  make lychee-env         - create/update local .bin/lychee (v$(LYCHEE_VERSION))"
	@echo "  make ci-lint            - flake8 (lint.yml)"
	@echo "  make ci-static-lint     - npm run lint (static-lint.yml)"
	@echo "  make ci-security-audit  - pip-audit (security-audit.yml)"
	@echo "  make ci-docs-link-check - lychee link checker (docs-link-check.yml)"
	@echo "  make ci-cie-oidc        - pytest CIE OIDC (cie-oidc-backend.yml)"
	@echo "  make ci-docker-compose  - Docker Compose + spid-sp-test (docker-compose-test.yml)"

# Create local .venv and install dependencies (poetry + project deps)
venv:
	@if [ ! -d "$(VENV)" ]; then \
		echo "Creating $(VENV)..."; \
		$(PYTHON) -m venv $(VENV); \
	fi
	$(VENV)/bin/pip install --upgrade pip poetry
	$(VENV)/bin/poetry config virtualenvs.in-project true
	$(VENV)/bin/poetry env use $(CURDIR)/$(VENV)/bin/python
	$(VENV)/bin/poetry install --extras test

# Download Node.js $(NODE_VERSION) to .node/ (linux-x64, linux-arm64, darwin-x64, darwin-arm64)
node-env:
	@if [ ! -f "$(NODE_DIR)/bin/npm" ]; then \
		U=$$(uname -s); M=$$(uname -m); \
		case "$$U" in Linux) OS=linux;; Darwin) OS=darwin;; *) echo "Unsupported OS: $$U"; exit 1;; esac; \
		case "$$M" in x86_64) ARCH=x64;; aarch64|arm64) ARCH=arm64;; *) echo "Unsupported arch: $$M"; exit 1;; esac; \
		TARBALL="node-v$(NODE_VERSION)-$$OS-$$ARCH.tar.xz"; \
		URL="https://nodejs.org/dist/v$(NODE_VERSION)/$$TARBALL"; \
		echo "Fetching $$URL..."; \
		mkdir -p .node-dl && curl -sL "$$URL" | tar -xJ -C .node-dl; \
		rm -rf $(NODE_DIR) && mv .node-dl/node-v$(NODE_VERSION)-$$OS-$$ARCH $(NODE_DIR); \
		rmdir .node-dl 2>/dev/null || true; \
		echo "Node installed in $(NODE_DIR)/"; \
	fi

# Download lychee v$(LYCHEE_VERSION) to .bin/lychee (linux-x64, linux-arm64, darwin-arm64)
lychee-env:
	@if [ ! -f "$(BIN_DIR)/lychee" ]; then \
		U=$$(uname -s); M=$$(uname -m); \
		case "$$U-$$M" in \
			Linux-x86_64)  A="lychee-x86_64-unknown-linux-gnu.tar.gz";; \
			Linux-aarch64) A="lychee-aarch64-unknown-linux-gnu.tar.gz";; \
			Darwin-arm64)  A="lychee-arm64-macos.tar.gz";; \
			Darwin-x86_64) echo "Intel Mac: no binary. Use: cargo install lychee"; exit 1;; \
			*) echo "Unsupported platform: $$U / $$M"; exit 1;; \
		esac; \
		URL="https://github.com/lycheeverse/lychee/releases/download/lychee-v$(LYCHEE_VERSION)/$$A"; \
		echo "Fetching $$URL..."; \
		mkdir -p .lychee-dl && curl -sL "$$URL" | tar -xz -C .lychee-dl; \
		mkdir -p $(BIN_DIR) && mv .lychee-dl/lychee $(BIN_DIR)/; \
		rm -rf .lychee-dl; \
		chmod +x $(BIN_DIR)/lychee; \
		echo "Lychee installed in $(BIN_DIR)/"; \
	fi

# Run all locally-runnable CI (excludes CD: docker push, static deploy, release-drafter)
ci: ci-lint ci-static-lint ci-security-audit ci-docs-link-check ci-cie-oidc ci-docker-compose

# --- Lint (flake8) - mirrors .github/workflows/lint.yml ---
ci-lint: venv
	@echo "=== CI: Lint (flake8) ==="
	$(VENV)/bin/flake8 --count --select=E9,F63,F7,F82 --show-source --statistics iam-proxy-italia-project
	$(VENV)/bin/flake8 --max-line-length 120 --count --exit-zero --statistics iam-proxy-italia-project

# --- Static lint (HTML, CSS, JS) - mirrors .github/workflows/static-lint.yml ---
ci-static-lint: node-env
	@echo "=== CI: Static lint ==="
	PATH="$(NODE_BIN):$$PATH" $(NODE_BIN)/npm ci --prefix iam-proxy-italia-project/static
	PATH="$(NODE_BIN):$$PATH" $(NODE_BIN)/npm run lint --prefix iam-proxy-italia-project/static

# --- Security audit (pip-audit) - mirrors .github/workflows/security-audit.yml ---
ci-security-audit: venv patch-pyeudiw
	@echo "=== CI: Security audit (main project) ==="
	$(VENV)/bin/poetry run pip install pip-audit
	$(VENV)/bin/poetry run pip-audit --cache-dir /tmp/pip-audit-cache --desc \
		--ignore-vuln CVE-2024-23342
	@echo "=== CI: Security audit (djangosaml2_sp) ==="
	$(VENV)/bin/pip-audit --cache-dir /tmp/pip-audit-cache -r iam-proxy-italia-project-demo-examples/djangosaml2_sp/requirements.txt --desc

# --- Docs link check - mirrors .github/workflows/docs-link-check.yml ---
ci-docs-link-check: lychee-env
	@echo "=== CI: Docs link check ==="
	$(BIN_DIR)/lychee --verbose --no-progress --exclude 'localhost' --exclude 'iam-proxy-italia.example.org' \
		--cache --max-cache-age 1d --max-concurrency 1 --max-retries 2 --accept 200,429 \
		README.md CONTRIBUTORS.md CONTRIBUTING.md docs/*.md

# --- CIE OIDC backend (pytest + coverage) - mirrors .github/workflows/cie-oidc-backend.yml ---
ci-cie-oidc: venv patch-pyeudiw
	@echo "=== CI: CIE OIDC backend ==="
	PYTHONPATH=iam-proxy-italia-project $(VENV)/bin/poetry run pytest iam-proxy-italia-project/backends/cieoidc/tests/ \
		--cov=backends.cieoidc \
		--cov-config=pyproject.toml \
		--cov-report=term-missing \
		--cov-report=html:htmlcov \
		--cov-report=xml:coverage.xml \
		-v

# --- Docker Compose integration test - mirrors .github/workflows/docker-compose-test.yml ---
ci-docker-compose: venv patch-pyeudiw
	@echo "=== CI: Docker Compose test ==="
	(cd Docker-compose && ./run-docker-compose.sh)
	@echo "=== Checking containers ==="
	docker ps -a
	docker container inspect iam-proxy-italia
	docker container logs iam-proxy-italia
	docker container logs django_sp
	@echo "=== Fetching djangosaml2 SP metadata ==="
	wget http://localhost:8000/saml2/metadata -O Docker-compose/iam-proxy-italia-project/metadata/sp/djangosaml2_sp.xml
	@echo "=== Copying Satosa IDP metadata ==="
	wget -v --no-check-certificate https://iam-proxy-italia.example.org/Saml2IDP/metadata -O Docker-compose/djangosaml2_sp/saml2_sp/saml2_config/iam-proxy-italia.xml
	@echo "=== spid-sp-test SPID ==="
	mkdir -p Docker-compose/iam-proxy-italia-project/metadata/idp
	docker run --rm --network host \
		-v "$(CURDIR)/Docker-compose/iam-proxy-italia-project:/spid" -w /spid \
		ghcr.io/italia/spid-sp-test:latest --idp-metadata > Docker-compose/iam-proxy-italia-project/metadata/idp/spid-sp-test.xml
	docker run --rm --network host \
		-v "$(CURDIR)/Docker-compose/iam-proxy-italia-project:/spid" -w /spid \
		ghcr.io/italia/spid-sp-test:latest --metadata-url https://iam-proxy-italia.example.org/spidSaml2/metadata --authn-url "http://localhost:8000/saml2/login/?idp=https://iam-proxy-italia.example.org/Saml2IDP/metadata&next=/saml2/echo_attributes&idphint=https%253A%252F%252Flocalhost%253A8443" -ap spid_sp_test.plugins.authn_request.SatosaSaml2Spid --extra --debug ERROR -tr
	@echo "=== spid-sp-test CIE id metadata ==="
	docker run --rm --network host \
		-v "$(CURDIR)/Docker-compose/iam-proxy-italia-project:/spid" -w /spid \
		ghcr.io/italia/spid-sp-test:latest --profile cie-sp-public --metadata-url https://iam-proxy-italia.example.org/cieSaml2/metadata
	@echo "=== spid-sp-test eIDAS FiCEP metadata ==="
	docker run --rm --network host \
		-v "$(CURDIR)/Docker-compose/iam-proxy-italia-project:/spid" -w /spid \
		ghcr.io/italia/spid-sp-test:latest --profile ficep-eidas-sp --metadata-url https://iam-proxy-italia.example.org/spidSaml2/metadata

# Patch pyproject.toml for eudi-wallet-it-python branch (used by security-audit, cie-oidc, docker-compose)
patch-pyeudiw:
	CURRENT_BRANCH="$(CURRENT_BRANCH)" TARGET_BRANCH="$(TARGET_BRANCH)" bash .github/scripts/patch-pyeudiw-branch.sh
