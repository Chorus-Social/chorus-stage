# src/chorus_stage/api/v1/endpoints/__init__.py
"""API endpoint modules for version 1."""

from .auth import router as auth_router
from .communities import router as communities_router
from .messages import router as messages_router
from .moderation import router as moderation_router
from .posts import router as posts_router
from .votes import router as votes_router

__all__ = [
    "auth_router",
    "posts_router",
    "votes_router",
    "communities_router",
    "messages_router",
    "moderation_router",
]
