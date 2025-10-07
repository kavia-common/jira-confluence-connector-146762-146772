"""
Compatibility entrypoint so environments starting `uvicorn src.api.main:app` load the canonical FastAPI app.

This module intentionally does not instantiate a new FastAPI app to avoid duplicate instances.
All routers, middleware, and startup hooks are defined in `src.app`.

Health check: Importing this module should succeed and expose `app` for uvicorn.
"""

# Re-export the canonical FastAPI app instance
from src.app import app  # noqa: F401

# Optional explicit export for clarity
__all__ = ["app"]
