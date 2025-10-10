"""
Compatibility module exposing FastAPI `app` for environments that expect uvicorn main:app.

Preferred entrypoint remains:
  uvicorn integration_backend.main_app:app --host 0.0.0.0 --port 3001

This module avoids relying on external PYTHONPATH by adjusting sys.path to include ./src
and then importing app from src.api.main.
"""

import os
import sys

# Ensure local ./src is importable when CWD is the integration_backend directory
_here = os.path.dirname(os.path.abspath(__file__))
_src = os.path.join(_here, "src")
if _src not in sys.path:
    sys.path.insert(0, _src)

# PUBLIC_INTERFACE
# Expose FastAPI app for uvicorn to import via "main:app"
from src.api.main import app  # noqa: E402,F401
