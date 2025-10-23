"""anon key refactor

Revision ID: 0473dd218910
Revises: 7ff6d5cbf5b0
Create Date: 2025-10-22 11:25:26.090177

"""
from __future__ import annotations

from typing import Any, Sequence, Union

from alembic import op
import sqlalchemy as sa

from chorus_stage.utils.hash import blake3_digest

# revision identifiers, used by Alembic.
revision: str = "0473dd218910"
down_revision: Union[str, Sequence[str], None] = "7ff6d5cbf5b0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to anonymous key storage."""
    bind = op.get_bind()
    metadata = sa.MetaData()

    user_account = sa.Table("user_account", metadata, autoload_with=bind)

    op.create_table(
        "anon_key",
        sa.Column("user_id", sa.LargeBinary(length=32), nullable=False),
        sa.Column("pubkey", sa.LargeBinary(length=32), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column("accent_color", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("user_id"),
        sa.UniqueConstraint("pubkey"),
    )
    op.create_table(
        "user_state",
        sa.Column("user_id", sa.LargeBinary(length=32), nullable=False),
        sa.Column("mod_tokens_remaining", sa.Integer(), nullable=False),
        sa.Column("mod_tokens_day_seq", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["anon_key.user_id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("user_id"),
    )

    anon_key = sa.table(
        "anon_key",
        sa.column("user_id", sa.LargeBinary(length=32)),
        sa.column("pubkey", sa.LargeBinary(length=32)),
        sa.column("display_name", sa.Text()),
        sa.column("accent_color", sa.Text()),
    )
    user_state = sa.table(
        "user_state",
        sa.column("user_id", sa.LargeBinary(length=32)),
        sa.column("mod_tokens_remaining", sa.Integer()),
        sa.column("mod_tokens_day_seq", sa.BigInteger()),
    )

    rows = bind.execute(
        sa.select(
            user_account.c.id,
            user_account.c.ed25519_pubkey,
            user_account.c.display_name,
            user_account.c.mod_tokens_remaining,
            user_account.c.mod_tokens_day_seq,
        )
    ).fetchall()

    id_mapping: dict[int, bytes] = {}
    anon_buffer: list[dict[str, Any]] = []
    state_buffer: list[dict[str, Any]] = []

    for row in rows:
        new_id = blake3_digest(row.ed25519_pubkey)
        id_mapping[row.id] = new_id
        anon_buffer.append(
            {
                "user_id": new_id,
                "pubkey": row.ed25519_pubkey,
                "display_name": row.display_name,
                "accent_color": None,
            }
        )
        state_buffer.append(
            {
                "user_id": new_id,
                "mod_tokens_remaining": row.mod_tokens_remaining,
                "mod_tokens_day_seq": row.mod_tokens_day_seq,
            }
        )

    if anon_buffer:
        op.bulk_insert(anon_key, anon_buffer)
    if state_buffer:
        op.bulk_insert(user_state, state_buffer)

    inspector = sa.inspect(bind)

    def _transition_column(
        table_name: str,
        column_name: str,
        fk_name: str,
        *,
        ondelete: str | None = None,
    ) -> None:
        nullable = any(
            col["name"] == column_name and col["nullable"]
            for col in inspector.get_columns(table_name)
        )
        pk_info = inspector.get_pk_constraint(table_name)
        pk_cols = pk_info.get("constrained_columns", []) if pk_info else []
        pk_name = pk_info.get("name") if pk_info else None
        column_in_pk = column_name in pk_cols

        temp_column = f"{column_name}_anon"
        op.add_column(
            table_name,
            sa.Column(temp_column, sa.LargeBinary(length=32), nullable=True),
        )

        update_stmt = sa.text(
            f"UPDATE {table_name} SET {temp_column} = :new_id WHERE {column_name} = :old_id"
        )
        for old_id, new_id in id_mapping.items():
            bind.execute(update_stmt, {"new_id": new_id, "old_id": old_id})

        if column_in_pk and pk_name:
            op.drop_constraint(pk_name, table_name, type_="primary")

        existing_fks = {fk["name"] for fk in inspector.get_foreign_keys(table_name)}
        if fk_name in existing_fks:
            op.drop_constraint(fk_name, table_name, type_="foreignkey")
        op.drop_column(table_name, column_name)
        op.alter_column(
            table_name,
            temp_column,
            new_column_name=column_name,
            existing_type=sa.LargeBinary(length=32),
        )
        op.create_foreign_key(
            fk_name,
            table_name,
            "anon_key",
            [column_name],
            ["user_id"],
            ondelete=ondelete,
        )

        if not nullable:
            op.alter_column(table_name, column_name, nullable=False)

        if column_in_pk and pk_name:
            op.create_primary_key(pk_name, table_name, pk_cols)

    _transition_column("community_member", "user_id", "community_member_user_id_fkey", ondelete="CASCADE")
    _transition_column("direct_message", "sender_user_id", "direct_message_sender_user_id_fkey")
    _transition_column("direct_message", "recipient_user_id", "direct_message_recipient_user_id_fkey")
    _transition_column("moderation_trigger", "trigger_user_id", "moderation_trigger_trigger_user_id_fkey")
    _transition_column("moderation_vote", "voter_user_id", "moderation_vote_voter_user_id_fkey")
    _transition_column("post_vote", "voter_user_id", "post_vote_voter_user_id_fkey")
    _transition_column("post", "author_user_id", "post_author_user_id_fkey")

    op.drop_table("user_account")


def downgrade() -> None:
    """Irreversible migration."""
    raise RuntimeError("anon key refactor is not reversible")
