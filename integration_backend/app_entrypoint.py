#!/usr/bin/env python3
"""
Application entrypoint for running the FastAPI server in environments where
the working directory may not include the 'src' path by default.

Usage examples:
- python integration_backend/app_entrypoint.py
- python -m integration_backend.app_entrypoint
- Or configure your process manager to execute this module to ensure app boots.

This script:
- Ensures integration_backend/src is on sys.path
- Imports src.api.main:app
- Runs uvicorn on 0.0.0.0:3001 by default (override via HOST/PORT envs)
"""

# PUBLIC_INTERFACE
def main():
    """Boot the FastAPI app with proper sys.path adjustments and run uvicorn."""
    import os
    import sys
    import traceback

    # Compute absolute path to 'src' directory within integration_backend
    here = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(here, "src")

    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    try:
        from src.api.main import app  # noqa: F401
    except Exception:
        print("Failed to import src.api.main:app. Traceback follows:")
        traceback.print_exc()
        raise

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "3001"))

    # Run via uvicorn using module path to avoid re-importing the app twice
    import uvicorn
    uvicorn.run("src.api.main:app", host=host, port=port, reload=False, lifespan="on")

if __name__ == "__main__":
    main()
