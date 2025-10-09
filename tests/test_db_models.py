"""Unit tests for the ORM models defined in chorus_stage.models.db_models.

These tests verify basic mapping correctness: table names, composite
primary keys, JSON column naming (metadata vs metadata_), and that
relationships are instrumented attributes. The entire module is skipped
automatically if SQLAlchemy is not installed in the runtime.
"""

from sqlalchemy.orm import attributes
import pytest
from chorus_stage.models import db_models

# Skip the whole module if SQLAlchemy isn't available in the runtime.
pytest.importorskip("sqlalchemy")

def test_table_names():
    """Model classes expose expected __tablename__ values."""
    assert getattr(db_models.User, "__tablename__") == "tbl_users"
    assert getattr(db_models.Posts, "__tablename__") == "tbl_posts"
    assert getattr(db_models.Community, "__tablename__") == "tbl_communities"
    assert getattr(db_models.Votes, "__tablename__") == "tbl_votes"
    assert getattr(db_models.CommunityMembers, "__tablename__") == "tbl_community_members"
    assert getattr(db_models.PostCoAuthors, "__tablename__") == "tbl_post_coauthors"


def test_votes_composite_primary_key():
    """Votes table should use a composite primary key (post_id, user_id)."""
    table = db_models.Votes.__table__
    pk_names = {c.name for c in table.primary_key}
    assert pk_names == {"post_id", "user_id"}


def test_metadata_column_and_attribute():
    """JSON metadata column should be named 'metadata' in the DB but exposed
    on the model as the attribute `metadata_` to avoid shadowing DeclarativeBase.metadata.
    """
    user_table = db_models.User.__table__
    assert "metadata" in user_table.c
    # The model attribute is metadata_
    assert hasattr(db_models.User, "metadata_")


def test_relationships_are_instrumented_attributes():
    """Simple sanity checks that common relationships are present and
    are SQLAlchemy instrumented attributes (i.e. mapped relationship descriptors).
    """
    # relationship attributes should be InstrumentedAttribute on the class
    rel_attrs = [
        db_models.User.posts_authored,
        db_models.User.communities,
        db_models.User.votes,
        db_models.Posts.author,
        db_models.Posts.community,
        db_models.Posts.votes,
        db_models.Votes.user,
        db_models.Votes.post,
    ]

    for a in rel_attrs:
        assert isinstance(a, attributes.InstrumentedAttribute)
