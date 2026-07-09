# VORTEX Chat — Makefile
#
# Usage:
#   make help          Show all available commands
#   make install       Install dependencies
#   make dev           Run development server
#   make test          Run tests with coverage
#   make lint          Run linter
#   make docker-build  Build Docker image
#   make ci            Run full CI pipeline locally
#

.DEFAULT_GOAL := help
.PHONY: help install install-dev dev test test-fast lint format security \
        docker-build docker-up docker-down migrate migrate-create \
        clean ci check-deps db-backup db-restore

PYTHON      ?= python3
PIP         ?= pip
PYTEST      ?= pytest
RUFF        ?= ruff
DOCKER      ?= docker
COMPOSE     ?= docker compose
APP_NAME    := vortex-chat
VERSION     := 5.0.0
PORT        ?= 9000

# Colors
CYAN  := \033[36m
GREEN := \033[32m
RESET := \033[0m

help: ## Show this help message
	@echo ""
	@echo "$(CYAN)VORTEX Chat v$(VERSION)$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}'
	@echo ""

install: ## Install production dependencies
	$(PIP) install -r requirements.txt

install-dev: install ## Install all dependencies (including dev tools)
	$(PIP) install -e ".[dev]"
	pre-commit install

dev: ## Run development server with hot-reload
	# FIX F13: do NOT trust X-Forwarded-* on this launch path. Without --no-proxy-headers
	# uvicorn defaults to proxy_headers=True / forwarded-allow-ips=127.0.0.1, so a loopback
	# peer could spoof XFF and bypass the per-IP auth rate limiters. If you front this with a
	# real reverse proxy, drop --no-proxy-headers and add --forwarded-allow-ips=<proxy IP/CIDR>.
	# FIX F15: --no-server-header suppresses uvicorn's own "Server: uvicorn" header
	# (it is emitted by the server below the ASGI app, so the stealth middleware
	# cannot strip it) — leaving only the decoy Server value.
	$(PYTHON) -m uvicorn app.main:app --host 0.0.0.0 --port $(PORT) --no-proxy-headers --no-server-header --reload --reload-dir app

run: ## Run production server
	$(PYTHON) run.py

test: ## Run tests with coverage report
	TESTING=true \
	DB_PATH="file::memory:?cache=shared" \
	JWT_SECRET="test_secret_key_minimum_32_chars_long_1234" \
	CSRF_SECRET="test_csrf_secret_minimum_32_chars_1234567" \
	NODE_INITIALIZED=true \
	DEVICE_NAME=TestNode \
	PORT=8001 HOST=127.0.0.1 \
	UDP_PORT=4201 \
	MAX_FILE_MB=100 \
	WAF_RATE_LIMIT_REQUESTS=9999 \
	$(PYTEST) --cov=app --cov-report=term-missing --cov-report=html:htmlcov -x -v

test-fast: ## Run tests without coverage (faster)
	TESTING=true \
	DB_PATH="file::memory:?cache=shared" \
	JWT_SECRET="test_secret_key_minimum_32_chars_long_1234" \
	CSRF_SECRET="test_csrf_secret_minimum_32_chars_1234567" \
	NODE_INITIALIZED=true \
	DEVICE_NAME=TestNode \
	PORT=8001 HOST=127.0.0.1 \
	UDP_PORT=4201 \
	MAX_FILE_MB=100 \
	WAF_RATE_LIMIT_REQUESTS=9999 \
	$(PYTEST) -x -q --no-cov

test-security: ## Run security-marked tests only
	$(PYTEST) -m security -v

lint: ## Run linter (ruff check)
	$(RUFF) check app/ --fix

format: ## Format code (ruff format)
	$(RUFF) format app/

check: lint format ## Run linter + formatter

security: ## Run security scan (bandit)
	bandit -r app/ -x app/tests,app/benchmarks -s B101,B104 -ll

typecheck: ## Run type checker (mypy)
	mypy app/ --ignore-missing-imports

migrate: ## Apply all pending database migrations
	alembic upgrade head

migrate-create: ## Create a new migration (usage: make migrate-create MSG="description")
	alembic revision --autogenerate -m "$(MSG)"

migrate-history: ## Show migration history
	alembic history --verbose

migrate-stamp: ## Stamp existing DB with latest revision (for existing installs)
	alembic stamp head

db-backup: ## Backup vortex.db to backups/ with timestamp
	@mkdir -p backups
	@if [ -f vortex.db ]; then \
		cp vortex.db "backups/vortex-$$(date +%Y%m%d-%H%M%S).db"; \
		echo "$(GREEN)Backup created: backups/vortex-$$(date +%Y%m%d-%H%M%S).db$(RESET)"; \
	else \
		echo "vortex.db not found"; exit 1; \
	fi

db-restore: ## Restore vortex.db from latest backup
	@LATEST=$$(ls -t backups/vortex-*.db 2>/dev/null | head -1); \
	if [ -z "$$LATEST" ]; then \
		echo "No backups found in backups/"; exit 1; \
	else \
		cp "$$LATEST" vortex.db; \
		echo "$(GREEN)Restored from $$LATEST$(RESET)"; \
	fi

docker-build: ## Build Docker image
	$(DOCKER) build -t $(APP_NAME):$(VERSION) -t $(APP_NAME):latest .

docker-up: ## Start with Docker Compose
	$(COMPOSE) up -d

docker-down: ## Stop Docker Compose
	$(COMPOSE) down

docker-logs: ## Show Docker logs
	$(COMPOSE) logs -f vortex

docker-dev: ## Start dev mode with Docker Compose
	$(COMPOSE) --profile dev up vortex-dev

docker-monitoring: ## Start with monitoring (Prometheus)
	$(COMPOSE) --profile monitoring up -d

ci: lint test security ## Run full CI pipeline: lint + test + security

check-deps: ## Check for dependency vulnerabilities
	pip install safety && safety check

clean: ## Remove build artifacts, caches, logs
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name htmlcov -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -f .coverage coverage.xml
	rm -rf logs/*.log
	@echo "$(GREEN)Cleaned!$(RESET)"
