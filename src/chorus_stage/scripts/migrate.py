# src/chorus_stage/scripts/migrate.py
from __future__ import annotations
import os
from alembic import command
from alembic.config import Config

from chorus_stage.core.settings import settings

def run_upgrade_head() -> None:
    # Point Alembic at your migrations folder
    cfg = Config(os.path.join(os.path.dirname(__file__), "..", "..", "..", "migrations", "alembic.ini"))
    # Inject sync URL for Alembic (psycopg driver)
    cfg.set_main_option("sqlalchemy.url", settings.database_url.replace("+psycopg_async", "+psycopg"))
    # Script location relative to the project root (adjust if yours differs)
    script_location = os.path.join(os.path.dirname(__file__), "..", "..", "..", "migrations")
    cfg.set_main_option("script_location", os.path.abspath(script_location))
    command.upgrade(cfg, "head")

if __name__ == "__main__":
    run_upgrade_head()