"""Versioned API router wiring."""
from fastapi import APIRouter
from . import routes_posts, routes_pow

api_v1 = APIRouter()
api_v1.include_router(routes_pow.router, prefix="/pow")
api_v1.include_router(routes_posts.router, prefix="/posts")
