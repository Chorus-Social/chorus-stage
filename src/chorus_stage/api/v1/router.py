"""Versioned API router wiring for v1.

This module composes the version 1 API surface by including the sub-routers
that define their own endpoints. It intentionally contains **no** business
logic and **no** endpoint definitions.

Import order is local to avoid package path ambiguities and to keep v1
self-contained. Downstream code should import and mount `api_v1` only.
"""
from __future__ import annotations

from typing import Final
from fastapi import APIRouter

# Local imports: keep v1 routing modular and testable
from . import routes_feed, routes_moderation, routes_posts, routes_pow

# Single router for v1; sub-routers declare their own tags and responses
api_v1: Final[APIRouter] = APIRouter()
api_v1.include_router(routes_pow.router, prefix="/pow")
api_v1.include_router(routes_posts.router, prefix="/posts")
api_v1.include_router(routes_feed.router, prefix="/feed")
api_v1.include_router(routes_moderation.router, prefix="/moderation")

__all__ = ["api_v1"]
