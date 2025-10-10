"""
Stable top-level FastAPI application module.

Use from repository root:
    uvicorn integration_backend.main_app:app --host 0.0.0.0 --port 3001

This avoids relying on external PYTHONPATH by adding the local `src` directory
to sys.path at import time, then importing the actual app from src.api.main.
"""

import os
import sys

# Compute local ./src path relative to this file
_here = os.path.dirname(os.path.abspath(__file__))
_src = os.path.join(_here, "src")

# PUBLIC_INTERFACE
# Re-export FastAPI app object for uvicorn with robust import strategy
try:
    # First attempt: if environment already has 'src' package available
    from src.api.main import app  # type: ignore  # noqa: F401
except ModuleNotFoundError:
    # Fallback: prepend computed src path and retry import
    if _src not in sys.path:
        sys.path.insert(0, _src)
    from api.main import app  # type: ignore  # noqa: F401
