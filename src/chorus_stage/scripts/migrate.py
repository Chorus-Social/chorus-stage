"""Helper script to run Alembic migrations from the CLI."""
from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from chorus_stage.core.settings import settings


def run_upgrade_head() -> None:
    """Run Alembic migrations up to the latest revision."""
    project_root = Path(__file__).resolve().parents[3]
    migrations_dir = project_root / "migrations"
    alembic_ini = migrations_dir / "alembic.ini"

    cfg = Config(str(alembic_ini))
    cfg.set_main_option("sqlalchemy.url", settings.database_url_sync)
    cfg.set_main_option("script_location", str(migrations_dir.resolve()))

    command.upgrade(cfg, "head")


if __name__ == "__main__":
    run_upgrade_head()
