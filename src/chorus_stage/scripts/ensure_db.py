"""Utility script to manage the configured Postgres database."""
from __future__ import annotations

import argparse
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


def drop_all_tables(db_url: str) -> None:
    """Drop and recreate the public schema for the configured database."""
    with psycopg.connect(db_url, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("DROP SCHEMA IF EXISTS public CASCADE")
        cur.execute("CREATE SCHEMA public")
        cur.execute("GRANT ALL ON SCHEMA public TO CURRENT_USER")
        cur.execute("GRANT ALL ON SCHEMA public TO public")
    print("[ensure_db] dropped all tables in public schema")


def main() -> None:
    parser = argparse.ArgumentParser(description="Ensure or reset the configured database")
    parser.add_argument(
        "--drop-tables",
        action="store_true",
        help="Drop and recreate the public schema before ensuring the database exists.",
    )
    parser.add_argument(
        "--url",
        default=None,
        help="Override database URL (defaults to effective settings URL)",
    )
    args = parser.parse_args()

    raw_url = args.url or settings.effective_database_url
    try:
        normalized_url = normalize_to_psycopg(raw_url)
        ensure_database_exists(normalized_url)
        if args.drop_tables:
            drop_all_tables(normalized_url)
    except Exception as exc:
        print(f"[ensure_db] ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
