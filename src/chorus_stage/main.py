"""Application entrypoint for the Chorus API service."""
from fastapi import FastAPI

from chorus_stage.api.v1.router import api_v1

app = FastAPI(title="Chorus API", version="0.1.0")


@app.get("/health", tags=["meta"])
async def health() -> dict:
    """Return a minimal payload that signals the service is alive.

    Returns:
        A static `{"status": "ok"}` payload.
    """
    return {"status": "ok"}

# Mount versioned API routes under the canonical prefix.
app.include_router(api_v1, prefix="/api/v1", tags=["v1"])
