# src/chorus_stage/main.py
"""Main entry point for the Chorus application."""

from __future__ import annotations

import asyncio
import random
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from chorus_stage.api.v1 import (
    auth_router,
    communities_router,
    messages_router,
    moderation_router,
    posts_router,
    system_router,
    users_router,
    votes_router,
)
from chorus_stage.core.settings import settings
from chorus_stage.services.bridge import bridge_enabled, get_bridge_client
from chorus_stage.services.bridge_sync import BridgeSyncWorker

# Initialize FastAPI app
app = FastAPI(
    title="Chorus API",
    description="Anonymous-by-design social network API",
    version="1.0.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)

# Add GZip middleware for compression
app.add_middleware(GZipMiddleware)

# Include API routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(posts_router, prefix="/api/v1")
app.include_router(votes_router, prefix="/api/v1")
app.include_router(communities_router, prefix="/api/v1")
app.include_router(messages_router, prefix="/api/v1")
app.include_router(moderation_router, prefix="/api/v1")
app.include_router(system_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")


async def _render_ascii_art() -> None:
    if not settings.ascii_art_enabled:
        return

    art_dir = Path(__file__).resolve().parents[2] / "art" / "ascii"
    if not art_dir.exists():
        return

    art_files = [path for path in art_dir.glob("*.txt") if path.is_file()]
    if not art_files:
        return

    art_file = random.choice(art_files)
    try:
        content = art_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as exc:  # pragma: no cover - decorative path
        print(f"[chorus-art] Failed to read {art_file}: {exc}")
        return

    print(f"[chorus-art] Displaying {art_file.name}")
    delay = max(0.0, float(settings.ascii_art_line_delay))
    for line in content:
        print(line)
        if delay:
            await asyncio.sleep(delay)


@app.on_event("startup")
async def on_startup() -> None:
    await _render_ascii_art()
    if bridge_enabled():
        worker = BridgeSyncWorker(get_bridge_client())
        await worker.start()
        app.state.bridge_worker = worker
    else:
        app.state.bridge_worker = None


@app.on_event("shutdown")
async def on_shutdown() -> None:
    worker: BridgeSyncWorker | None = getattr(app.state, "bridge_worker", None)
    if worker:
        await worker.stop()
    if bridge_enabled():
        await get_bridge_client().close()

@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint to verify the service is running."""
    return {"status": "ok"}

@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint with basic information about the API."""
    return {
        "name": "Chorus API",
        "version": "1.0.0",
        "description": "Anonymous-by-design social network API",
        "docs": "/docs",
        "redoc": "/redoc"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.chorus_stage.main:app", host="0.0.0.0", port=8000, reload=settings.debug)
