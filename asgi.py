"""
ASGI compatibility entrypoint.

Allows starting the app with:
  uvicorn asgi:app --host 0.0.0.0 --port 3001

Import strategy:
1) Try integration_backend.main_app:app (preferred stable entrypoint from repo root)
2) Fallback to integration_backend.main:app (works when CWD is integration_backend)
3) As last resort, compute integration_backend/src on sys.path and import api.main:app
"""

# PUBLIC_INTERFACE
# Expose FastAPI app for uvicorn
def _load_app():
    """Attempt to load the FastAPI app from multiple known entrypoints."""
    try:
        from integration_backend.main_app import app  # type: ignore
        return app
    except Exception:
        pass
    try:
        from integration_backend.main import app  # type: ignore
        return app
    except Exception:
        pass

    # Last resort: compute path to integration_backend/src and import api.main
    import os
    import sys
    here = os.path.dirname(os.path.abspath(__file__))
    ib = os.path.join(here, "integration_backend")
    src = os.path.join(ib, "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    from api.main import app  # type: ignore
    return app


app = _load_app()
