"""Application entrypoint for Chorus.

Run locally:
    poetry run uvicorn chorus.main:app --reload

This module wires up:
- settings
- database/redis connections
- v1 API router
- health endpoints
"""

from fastapi import FastAPI
from chorus_stage.core.settings import settings
from chorus_stage.api.v1.router import api_v1

app = FastAPI(title="Chorus API", version="0.1.0")

@app.get("/health", tags=["meta"])
async def health() -> dict:
    """Health endpoint. Returns a minimal OK payload.

    Returns
    -------
    dict
        Always {"status": "ok"} if the app is running.
    """
    return {"status": "ok"}

app.include_router(api_v1, prefix="/api/v1", tags=["v1"])
