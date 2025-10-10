#!/usr/bin/env python3
"""
Convenience launcher to run the FastAPI app bound to 0.0.0.0:3001.

Usage:
  python -m integration_backend.run_server
  or
  python integration_backend/run_server.py

This module ensures the correct application object is used from src.api.main:app
without requiring any secrets at import time.
"""

# PUBLIC_INTERFACE
def main():
    """Start uvicorn for the integration backend on the configured host/port."""
    import os
    import uvicorn

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "3001"))

    # Use the fully qualified path to avoid double-importing the app
    uvicorn.run("integration_backend.main_app:app", host=host, port=port, reload=False, lifespan="on")


if __name__ == "__main__":
    main()
