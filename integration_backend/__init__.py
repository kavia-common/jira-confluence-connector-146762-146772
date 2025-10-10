"""
Package marker for integration_backend.

This ensures 'integration_backend' is importable from the repository root,
so uvicorn integration_backend.main_app:app works without modifying PYTHONPATH.
"""
# PUBLIC_INTERFACE
def get_version() -> str:
    """Return the integration backend package version (static for now)."""
    return "0.1.0"
