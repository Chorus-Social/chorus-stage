.PHONY: run test lint fmt migrate revision

run:
	poetry run uvicorn chorus.main:app --reload --port 8080

test:
	poetry run pytest -q

lint:
	poetry run ruff check .

fmt:
	poetry run ruff check --fix .

revision:
	poetry run alembic revision -m "auto"

migrate:
	poetry run alembic upgrade head
