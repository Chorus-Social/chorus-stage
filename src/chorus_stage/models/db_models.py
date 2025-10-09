# pylint: disable=too-few-public-methods
"""Database models for the Chorus Stage application.

This module defines SQLAlchemy ORM models (Declarative) used by the
application: users, posts, communities, votes, and the association tables.
Models use SQLAlchemy 2.0 style typing with `Mapped[...]` and `mapped_column`.
"""

from __future__ import annotations

from typing import List, Optional, Dict
import datetime

from sqlalchemy import Integer, String, DateTime, JSON, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all ORM models in this module.

    All ORM models should inherit from `Base` to gain SQLAlchemy's
    DeclarativeBase behavior (mappings, metadata, etc.).

    Note:
        DeclarativeBase provides a class-level `metadata` (SQLAlchemy MetaData).
        Do not shadow that attribute name on model subclasses — use a
        different attribute name (for example `metadata_`) for JSON or
        other user-defined fields to avoid collisions.
    """

class User(Base):
    """Represents a user in the Chorus network.

    This model stores all information related to a user's identity and their
    relationships to other core components of the application.

    Attributes:
        id (int): The unique integer identifier for the user.
        user_key (str): The unique, 18-character key used for authentication.
        display_name (str): The user's public-facing, non-unique name.
        created_at (datetime): The timestamp when the user account was created.
        metadata_ (Optional[Dict]): A JSON field for storing arbitrary metadata
            (database column name is `metadata`). The attribute is named
            `metadata_` to avoid clashing with SQLAlchemy's DeclarativeBase.metadata.
        posts_authored (list[Posts]): A SQLAlchemy relationship to the posts created by the user.
        communities (list[Community]): A SQLAlchemy relationship to the
            communities the user is a member of.
        votes (list[Votes]): A SQLAlchemy relationship to the votes cast by the user.
    """

    __tablename__ = "tbl_users"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    user_key: Mapped[str] = mapped_column(
        String(18),
        unique=True,
        nullable=False,
    )
    display_name: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )  # Changed back to not nullable
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.datetime.utcnow,
    )
    metadata_: Mapped[Optional[Dict]] = mapped_column(
        JSON,
        nullable=True,
        name="metadata",
    )

    # --- ADDED RELATIONSHIPS ---
    # One-to-many: A user can create many posts
    posts_authored: Mapped[List["Posts"]] = relationship("Posts", back_populates="author")

    # Many-to-many: A user can be in many communities
    communities: Mapped[List["Community"]] = relationship(
        "Community",
        secondary="tbl_community_members",
        back_populates="members",
    )

    # Many-to-many: A user can vote on many posts
    votes: Mapped[List["Votes"]] = relationship("Votes", back_populates="user")


class Posts(Base):
    """Represents a post or comment in the Chorus network.

    The model supports hierarchical relationships for comments and rephrased posts.

    Attributes:
        id (int): The unique integer identifier for the post.
        parent_id (int): The ID of the parent post, if this is a comment or rephrasing.
        is_rephrasing (bool): Indicates if the post is a rephrasing of another post.
        body (str): The main content of the post.
        created_at (datetime): The timestamp when the post was created.
        metadata_ (Optional[Dict]): A JSON field for storing arbitrary metadata
            (database column name is `metadata`). The attribute is named
            `metadata_` to avoid clashing with SQLAlchemy's DeclarativeBase.metadata.
        community_id (int): Foreign key linking to the community this post belongs to.
        author_id (int): Foreign key linking to the user who authored this post.
        author (User): A SQLAlchemy relationship to the User who authored this post.
        community (Community): A SQLAlchemy relationship to the Community this post belongs to.
        votes (list[Votes]): A SQLAlchemy relationship to the votes associated with this post.
        parent (Posts): A SQLAlchemy relationship to the parent post, if applicable.
        children (list[Posts]): A SQLAlchemy relationship to child posts/comments.
    """

    __tablename__ = "tbl_posts"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    parent_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("tbl_posts.id"),
        nullable=True,
    )
    is_rephrasing: Mapped[bool] = mapped_column(
        Boolean,
        index=True,
    )
    body: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.datetime.utcnow,
    )
    metadata_: Mapped[Optional[Dict]] = mapped_column(
        JSON,
        nullable=True,
        name="metadata",
    )

    community_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('tbl_communities.id'),
        nullable=False,
    )

    # --- ADDED AUTHOR FOREIGN KEY and RELATIONSHIP ---
    author_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('tbl_users.id'),
        nullable=False,
    )
    author: Mapped["User"] = relationship("User", back_populates="posts_authored")

    community: Mapped["Community"] = relationship("Community", back_populates="posts")

    # --- ADDED RELATIONSHIPS ---
    # Many-to-many: A post can have many votes
    votes: Mapped[List["Votes"]] = relationship("Votes", back_populates="post")

    # Self-referencing: A post (comment) has one parent, a parent can have many children (comments)
    parent: Mapped[Optional["Posts"]] = relationship(
        "Posts",
        remote_side=[id],
        back_populates="children",
    )
    children: Mapped[List["Posts"]] = relationship("Posts", back_populates="parent")


class Community(Base):
    """Represents a Community (group) inside the Chorus network.

    A Community groups posts and users. This model stores community-level
    metadata and defines relationships to posts and member users.

    Attributes:
        id (int): Primary key for the community.
        display_name (str): Public name for the community, unique and required.
        created_at (datetime): Creation timestamp for the community.
        metadata_ (Optional[Dict]): JSON column for arbitrary community metadata.
            The actual database column name is `metadata` but the attribute is
            named `metadata_` to avoid clashing with SQLAlchemy's declarative
            base `metadata` attribute.
        posts (list[Posts]): One-to-many relationship to posts belonging to the community.
        members (list[User]): Many-to-many relationship to users who are members.

    Notes:
        - Relationship attributes use string annotations to avoid circular imports.
        - Use `metadata_` when accessing the JSON column on instances.
    """
    __tablename__ = "tbl_communities"
    
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    display_name: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        unique=True,
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.datetime.utcnow,
    )
    metadata_: Mapped[Optional[Dict]] = mapped_column(
        JSON,
        nullable=True,
        name="metadata",
    )
    
    # --- ADDED RELATIONSHIPS ---
    # One-to-many: A community has many posts
    posts: Mapped[List["Posts"]] = relationship("Posts", back_populates="community")
    
    # Many-to-many: A community has many members (users)
    members: Mapped[List["User"]] = relationship(
        "User",
        secondary="tbl_community_members",
        back_populates="communities",
    )


class Votes(Base):
    """Represents a vote cast by a user on a post.

    This table uses a composite primary key of (post_id, user_id) so that each
    user may have at most one vote per post. The `vote` column stores the vote
    value (for example 1 for upvote, -1 for downvote, or other integer scales
    depending on application logic).

    Attributes:
        post_id (int): Foreign key to the `tbl_posts` table. Part of the primary key.
        user_id (int): Foreign key to the `tbl_users` table. Part of the primary key.
        vote (int): Integer value representing the user's vote.
        created_at (datetime): Timestamp when the vote was recorded.
        user (User): Relationship to the User who cast the vote.
        post (Posts): Relationship to the Post that was voted on.

    Notes:
        - The composite primary key prevents duplicate votes by the same user
          on the same post at the database level. If you need to allow multiple
          votes (e.g., vote history), consider using a surrogate PK instead.
    """
    __tablename__ = "tbl_votes"

    post_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("tbl_posts.id"),
        primary_key=True,
    )
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("tbl_users.id"),
        primary_key=True,
    )
    vote: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.datetime.utcnow,
    )

    # --- ADDED RELATIONSHIPS ---
    # These link the vote back to the specific user and post objects
    user: Mapped["User"] = relationship("User", back_populates="votes")
    post: Mapped["Posts"] = relationship("Posts", back_populates="votes")


class CommunityMembers(Base):
    """Association table linking users to communities (many-to-many).

    This table records membership of users in communities. It uses a composite
    primary key of (community_id, user_id) to ensure a user cannot be added
    to the same community more than once.

    Attributes:
        community_id (int): FK to `tbl_communities.id`. Part of composite PK.
        user_id (int): FK to `tbl_users.id`. Part of composite PK.
        created_at (datetime): When the membership record was created.
    """
    __tablename__ = "tbl_community_members"
    
    community_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("tbl_communities.id"),
        primary_key=True,
    )
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("tbl_users.id"),
        primary_key=True,
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.datetime.utcnow,
    )

class PostCoAuthors(Base):
    """Association table for co-authors of posts.

    Each row represents a relationship between a post and a co-authoring user.
    The composite primary key (post_id, user_id) prevents duplicate co-author
    entries for the same post and user.

    Attributes:
        post_id (int): FK to `tbl_posts.id`. Part of composite PK.
        user_id (int): FK to `tbl_users.id`. Part of composite PK.
        created_at (datetime): When the co-author relationship was created.
    """
    __tablename__ = "tbl_post_coauthors"
    
    post_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("tbl_posts.id"),
        primary_key=True,
        nullable=False,
    )
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("tbl_users.id"),
        primary_key=True,
        nullable=False,
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.datetime.utcnow,
    )
    