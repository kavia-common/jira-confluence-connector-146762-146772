"""
ASGI entrypoint for the integration_backend container.

Allows starting the app with:
  uvicorn asgi:app --host 0.0.0.0 --port 3001

Import strategy priorities when the working directory is this folder:
1) main_app:app (preferred stable entrypoint, handles src path)
2) main:app (compatibility)
3) Add ./src to sys.path and import api.main:app
4) Add this folder to sys.path and import src.api.main:app

This ensures startup does not depend on external PYTHONPATH and missing env vars do not block binding to port 3001.
"""

from typing import Any


# PUBLIC_INTERFACE
def _load_app() -> Any:
    """Attempt to load the FastAPI app from multiple known entrypoints with safe fallbacks."""
    # Preferred stable entrypoint in this directory
    try:
        from main_app import app  # type: ignore
        return app
    except Exception:
        pass

    # Compatibility entrypoint
    try:
        from main import app  # type: ignore
        return app
    except Exception:
        pass

    # Compute path to ./src for direct import attempts
    import os
    import sys

    here = os.path.dirname(os.path.abspath(__file__))
    src = os.path.join(here, "src")

    # Attempt importing using ./src as sys.path and api.main
    try:
        if src not in sys.path:
            sys.path.insert(0, src)
        from api.main import app  # type: ignore
        return app
    except Exception:
        pass

    # Final fallback: ensure this folder itself is on sys.path and import src.api.main
    if here not in sys.path:
        sys.path.insert(0, here)
    try:
        from src.api.main import app  # type: ignore
        return app
    except Exception as e:
        # Surface a clear error so logs show why startup failed
        raise RuntimeError("Failed to import FastAPI app from any known entrypoint") from e


# PUBLIC_INTERFACE
# Expose FastAPI app instance for ASGI servers like uvicorn to import via "asgi:app"
app = _load_app()
