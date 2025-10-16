from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

from src.chorus_stage.db.session import Base

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
# pylint: disable=method-hidden,no-member
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.

# --- Alembic bootstrap for src/ layout ---
from logging.config import fileConfig
from alembic import context
from sqlalchemy import engine_from_config, pool

import os, sys, pathlib

# Ensure project root and src/ are importable no matter where alembic runs
ROOT = pathlib.Path(__file__).resolve().parents[1]      # .../migrations/..
SRC  = ROOT / "src"
for p in (str(ROOT), str(SRC)):
    if p not in sys.path:
        sys.path.insert(0, p)

# Import settings so we can inject a URL for Alembic (sync driver)
try:
    from chorus_stage.core.settings import settings
    DEFAULT_URL = settings.database_url.replace("+psycopg_async", "+psycopg")
except Exception:
    DEFAULT_URL = None

config = context.config
if config is not None and DEFAULT_URL and not config.get_main_option("sqlalchemy.url"):
    config.set_main_option("sqlalchemy.url", DEFAULT_URL)

# Import Base and, crucially, load model modules so they register with Base.metadata
from chorus_stage.db.session import Base  # this module imports the models after defining Base

# If you prefer to be explicit, you can force-import the packages too:
# from chorus_stage.models import community, message, moderation, post, rate, user, vote  # noqa: F401

# Tell Alembic what to diff against
target_metadata = Base.metadata

# Optional: don’t try to diff Alembic’s own table
def include_object(obj, name, type_, reflected, compare_to):
    if type_ == "table" and name == "alembic_version":
        return False
    return True


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
