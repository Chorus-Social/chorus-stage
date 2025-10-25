# --------- Chorus Makefile (Python 3.14 + psycopg) ----------

SHELL := /bin/bash
PY := python3.14
UVICORN := uvicorn
TEST := pytest
APP_MODULE := chorus_stage.main:app
PORT ?= 8080
PYTHONPATH := src
export PYTHONPATH

POETRY := poetry
ALEMBIC := $(POETRY) run alembic

# Sync URL for Alembic (psycopg sync); app uses async via settings
LIVE_URL ?= postgresql+psycopg://chorus:is-cool@localhost:5432/chorus_live

TEST_URL ?= postgresql+pyscopg://chorus_testing:blowItUp@localhost:5432/chorus_testing

.PHONY: help install lock venv info run dev db-init migrate revision downgrade reset-db db-hard-reset lint fmt test clean
.PHONY: live-up test-up live-down test-down live-logs test-logs live-shell test-shell live-migrate test-migrate dev-up dev-down dev-shell clean-docker

help:
	@echo "=== Chorus Stage Development ==="
	@echo "setup:     install | lock | venv | info"
	@echo "app:       run | dev | db-init | migrate"
	@echo "database:  live-revision | test-revision | downgrade | reset-db | db-hard-reset"
	@echo "quality:   lint | fmt | test | test-unit | test-services"
	@echo "cleanup:   clean"
	@echo ""
	@echo "=== Docker Compose Management ==="
	@echo "live:      live-up | live-down | live-logs | live-shell | live-migrate"
	@echo "test:      test-up | test-down | test-logs | test-shell | test-migrate"
	@echo "dev:       dev-up | dev-down | dev-shell"
	@echo "cleanup:   clean-docker"
	@echo ""
	@echo "Environment URLs:"
	@echo "  Live API:    http://localhost:8000"
	@echo "  Test API:    http://localhost:8001"
	@echo "  Live Admin:  http://localhost:8080"
	@echo "  Test Admin:  http://localhost:8081"
	@echo "  Live Grafana: http://localhost:3001"
	@echo "  Test Grafana: http://localhost:3002"

# ----- setup -----
install:
	$(POETRY) install

lock:
	$(POETRY) lock --no-update

venv:
	$(POETRY) env use $(PY)

info:
	@echo "PYTHONPATH=$(PYTHONPATH)"
	@$(POETRY) run $(PY) -V
	@$(POETRY) run $(PY) -c "import psycopg, sqlalchemy; print('psycopg OK, SQLAlchemy OK')"

# ----- app -----
run:
	docker compose down --remove-orphans || true
	docker compose up -d
	$(POETRY) run $(UVICORN) $(APP_MODULE) --host 0.0.0.0 --port $(PORT)

dev: db-init run

# ----- checkpoints -----
alpha:
	$(POETRY) run $(PY) -m chorus_stage.scripts.test_checkpoint_alpha --base-url http://127.0.0.1:8080

# ----- database bootstrap + migrations -----
db-init:
	$(POETRY) run $(PY) -m chorus_stage.scripts.ensure_db
	$(POETRY) run $(PY) -m chorus_stage.scripts.migrate

migrate:
	$(POETRY) run $(PY) -m chorus_stage.scripts.migrate

live-revision:
	# Autogenerate a migration from current models
	SQLALCHEMY_URL="$(LIVE_URL)" $(ALEMBIC) revision --autogenerate -m "$(m)"

test-revision:
	# Autogenerate a migration from current models
	SQLALCHEMY_URL="$(TEST_URL)" $(ALEMBIC) revision --autogenerate -m "$(m)"

downgrade:
	# Example: make downgrade r=-1  (or r=base)
	$(POETRY) run alembic downgrade $(r)

db-hard-reset:
	$(POETRY) run $(PY) -m chorus_stage.scripts.ensure_db --drop-tables
	$(POETRY) run $(PY) -m chorus_stage.scripts.migrate

# ----- quality -----
lint:
	$(POETRY) run ruff check src

fmt:
	$(POETRY) run ruff check --fix src

test:
	$(POETRY) run pytest -q --asyncio-mode=auto --maxfail=1

.PHONY: test-unit test-services
test-unit:
	# Run fast, unit-only tests (no DB/Redis required)
	$(POETRY) run pytest -q tests/v1/test_services.py -k "pow_leases or replay_pow_nonce_tracking_in_memory or auth_challenge_binding_negative" --maxfail=1

test-services:
	$(POETRY) run pytest -q tests/v1/test_services.py --maxfail=1

clean:
	@find . -name "__pycache__" -type d -prune -exec rm -rf {} + || true
	@rm -rf .pytest_cache .ruff_cache dist build *.egg-info || true

# ----- Docker Compose Management -----
live-up: ## Start live environment
	docker-compose -f docker-compose.live.yml up -d

test-up: ## Start test environment
	docker-compose -f docker-compose.test.yml up -d

live-down: ## Stop live environment
	docker-compose -f docker-compose.live.yml down

test-down: ## Stop test environment
	docker-compose -f docker-compose.test.yml down

live-logs: ## Show live environment logs
	docker-compose -f docker-compose.live.yml logs -f

test-logs: ## Show test environment logs
	docker-compose -f docker-compose.test.yml logs -f

live-shell: ## Open shell in live chorus-stage container
	docker exec -it chorus-stage-live /bin/bash

test-shell: ## Open shell in test chorus-stage container
	docker exec -it chorus-stage-test /bin/bash

live-migrate: ## Run migrations on live database
	docker-compose -f docker-compose.live.yml run --rm migrate

test-migrate: ## Run migrations on test database
	docker-compose -f docker-compose.test.yml run --rm migrate

dev-up: ## Start test environment (uses dev Dockerfile)
	docker-compose -f docker-compose.test.yml up -d

dev-down: ## Stop dev environment
	docker-compose -f docker-compose.test.yml down

dev-shell: ## Open shell in dev container
	docker exec -it chorus-stage-test /bin/bash

clean-docker: ## Remove all containers, networks, and volumes
	docker-compose -f docker-compose.live.yml down -v --remove-orphans
	docker-compose -f docker-compose.test.yml down -v --remove-orphans
	docker system prune -f