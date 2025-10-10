"""
Compatibility module exposing FastAPI `app` for environments that expect uvicorn main:app.

Supported import paths for the app:
- integration_backend.main_app:app (preferred)
- integration_backend.main:app (this module)
- asgi:app (compat)

Preferred start command:
  uvicorn integration_backend.main_app:app --host 0.0.0.0 --port 3001

This module avoids relying on external PYTHONPATH by importing app from src.api.main,
adding ./src to sys.path only if needed.
"""

import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
_src = os.path.join(_here, "src")

# PUBLIC_INTERFACE
# Expose FastAPI app for uvicorn to import via "main:app" with robust import strategy
try:
    from src.api.main import app  # type: ignore  # noqa: F401
except ModuleNotFoundError:
    if _src not in sys.path:
        sys.path.insert(0, _src)
    from api.main import app  # type: ignore  # noqa: F401
