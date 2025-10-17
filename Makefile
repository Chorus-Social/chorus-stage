# --------- Chorus Makefile (Python 3.14 + psycopg) ----------
# Boring. Reliable. Future-you will thank past-you.

SHELL := /bin/bash
PY := python3.14
UVICORN := uvicorn
APP_MODULE := chorus_stage.main:app
PORT ?= 8080
PYTHONPATH := src
export PYTHONPATH

POETRY := poetry
ALEMBIC := $(POETRY) run alembic

# Sync URL for Alembic (psycopg sync); app uses async via settings
ALEMBIC_URL ?= postgresql+psycopg://chorus:is-cool@localhost:5432/chorus

.PHONY: help install lock venv info run dev db-init migrate revision downgrade reset-db lint fmt test clean

help:
	@echo "targets: install | run | dev | db-init | migrate | revision | downgrade | reset-db | lint | fmt | test | info | clean"

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
	$(POETRY) run $(UVICORN) $(APP_MODULE) --host 0.0.0.0 --port $(PORT)

dev: db-init run

# ----- database bootstrap + migrations -----
db-init:
	# Create DB if missing (sync psycopg connection)
	$(POETRY) run $(PY) -m chorus_stage.scripts.ensure_db
	# Apply migrations to head
	SQLALCHEMY_URL="$(ALEMBIC_URL)" $(ALEMBIC) upgrade head

migrate:
	SQLALCHEMY_URL="$(ALEMBIC_URL)" $(ALEMBIC) upgrade head

revision:
	# Autogenerate a migration from current models
	SQLALCHEMY_URL="$(ALEMBIC_URL)" $(ALEMBIC) revision --autogenerate -m "$(m)"

downgrade:
	# Example: make downgrade r=-1  (or r=base)
	SQLALCHEMY_URL="$(ALEMBIC_URL)" $(ALEMBIC) downgrade $(r)

db-check:
	PYTHONPATH=src poetry run python3 -c "from chorus_stage.db.session import Base; print(sorted(Base.metadata.tables))"

# ----- quality -----
lint:
	$(POETRY) run ruff check src

fmt:
	$(POETRY) run ruff check --fix src

test:
	$(POETRY) run pytest -q --asyncio-mode=auto --maxfail=1

clean:
	@find . -name "__pycache__" -type d -prune -exec rm -rf {} + || true
	@rm -rf .pytest_cache .ruff_cache dist build *.egg-info || true