"""
ASGI compatibility entrypoint.

Allows starting the app with:
  uvicorn asgi:app --host 0.0.0.0 --port 3001

Import strategy:
1) Try integration_backend.main_app:app (preferred stable entrypoint from repo root)
2) Fallback to integration_backend.main:app (works when CWD is integration_backend)
3) Try computing integration_backend/src and import src.api.main:app
4) As last resort, put integration_backend/src on sys.path and import api.main:app
"""

# PUBLIC_INTERFACE
# Expose FastAPI app for uvicorn
def _load_app():
    """Attempt to load the FastAPI app from multiple known entrypoints."""
    # Preferred stable entrypoint
    try:
        from integration_backend.main_app import app  # type: ignore
        return app
    except Exception:
        pass

    # Fallback entrypoint
    try:
        from integration_backend.main import app  # type: ignore
        return app
    except Exception:
        pass

    # Compute path to integration_backend/src for direct import attempts
    import os
    import sys
    here = os.path.dirname(os.path.abspath(__file__))
    ib = os.path.join(here, "integration_backend")
    src = os.path.join(ib, "src")

    # Attempt importing using package path first: src.api.main
    try:
        if src not in sys.path:
            sys.path.insert(0, src)
        from src.api.main import app  # type: ignore
        return app
    except Exception:
        # Clean failure and try the final fallback below
        pass

    # Last resort: ensure src is on sys.path and import api.main (relative to src)
    if src not in sys.path:
        sys.path.insert(0, src)
    from api.main import app  # type: ignore
    return app


app = _load_app()
