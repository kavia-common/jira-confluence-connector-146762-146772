"""
Compatibility entrypoint so environments starting `uvicorn src.api.main:app` load the canonical FastAPI app.

This module intentionally does not instantiate a new FastAPI app to avoid duplicate instances.
All routers, middleware, and startup hooks are defined in `src.app`.

Design:
- Keep this shim minimal. It must not import anything from modules that import src.api.main back,
  or from code that imports `app` via this shim, to avoid circular imports.
- Only re-export `app` from src.app.

Health check: Importing this module should succeed and expose `app` for uvicorn.
"""

# PUBLIC_INTERFACE
# Re-export the canonical FastAPI app instance from src.app without introducing circular imports.
from src.app import app  # noqa: F401

# Optional explicit export for clarity
__all__ = ["app"]
