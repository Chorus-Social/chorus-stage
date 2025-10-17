# src/chorus_stage/main.py
"""Main entry point for the Chorus application."""

from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware

from chorus_stage.api.v1 import (
    auth_router,
    communities_router,
    messages_router,
    moderation_router,
    posts_router,
    votes_router,
)
from chorus_stage.core.settings import settings

# Initialize FastAPI app
app = FastAPI(
    title="Chorus API",
    description="Anonymous-by-design social network API",
    version="1.0.0",
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
