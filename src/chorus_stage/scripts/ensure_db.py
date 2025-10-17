"""Utility script to ensure the configured Postgres database exists."""
from __future__ import annotations

import os
import sys
from urllib.parse import urlsplit, urlunsplit

import psycopg
from psycopg import sql

from chorus_stage.core.settings import settings


def normalize_to_psycopg(uri: str) -> str:
    """Return a Postgres URI suitable for psycopg.connect().

    - Strips quotes and whitespace.
    - Converts SQLAlchemy schemes (postgresql+*) to plain "postgresql".
    - Recovers from odd parsing when the scheme is present but urlsplit fails.
    """
    uri = (uri or "").strip()
    if (uri.startswith("'") and uri.endswith("'")) or (uri.startswith('"') and uri.endswith('"')):
        uri = uri[1:-1]
    if not uri:
        raise ValueError("DATABASE_URL is empty")

    # If scheme is present but urlsplit doesn't see it, reassemble manually.
    if "://" in uri and uri.split("://", 1)[0]:  # looks like a scheme
        scheme_hint, rest = uri.split("://", 1)
        if scheme_hint.startswith("postgresql+"):
            scheme_hint = "postgresql"
        # urlsplit needs the leading // for netloc parsing
        parts = urlsplit(f"{scheme_hint}://{rest}")
    else:
        parts = urlsplit(uri)

    scheme = parts.scheme
    if scheme.startswith("postgresql+"):
        scheme = "postgresql"

    return urlunsplit((scheme, parts.netloc, parts.path, parts.query, parts.fragment))


def _split_db_url(db_url: str) -> tuple[str, str]:
    """Return `(admin_url, target_db)` using the maintenance database."""
    norm = normalize_to_psycopg(db_url)
    parts = urlsplit(norm)

    # If urlsplit still failed to find a scheme/netloc, bail with a loud message.
    if not parts.scheme.startswith("postgresql"):
        raise ValueError(f"Unparseable DATABASE_URL (no scheme): {db_url!r}")

    target_db = parts.path.lstrip("/") or "postgres"

    if parts.netloc:
        admin_url = urlunsplit(
            ("postgresql", parts.netloc, "/postgres", parts.query, parts.fragment)
        )
    else:
        # hostless/local-socket style
        admin_url = "postgresql:///postgres"

    return admin_url, target_db


def ensure_database_exists(db_url: str) -> None:
    """Create the configured database if it is missing."""
    admin_url, target_db = _split_db_url(db_url)

    if os.getenv("ENSURE_DB_DEBUG") == "1":
        print(f"[ensure_db] admin_url={admin_url!r}, target_db={target_db!r}")

    # Connect to maintenance DB
    with psycopg.connect(admin_url, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (target_db,))
        exists = cur.fetchone() is not None
        if not exists:
            query = sql.SQL("CREATE DATABASE {}").format(sql.Identifier(target_db))
            cur.execute(query)
            print(f"[ensure_db] created database {target_db}")
        else:
            print(f"[ensure_db] database {target_db} already exists")


if __name__ == "__main__":
    try:
        ensure_database_exists(normalize_to_psycopg(settings.database_url))
    except Exception as e:
        print(f"[ensure_db] ERROR: {e}", file=sys.stderr)
        sys.exit(1)
