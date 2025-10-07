"""
Top-level package initializer for the backend source tree.

Ensures that 'src' is recognized as a Python package for imports like 'from src.app import app'.
This file intentionally has no side effects.
"""
# PUBLIC_INTERFACE
def package_ready() -> bool:
    """Simple indicator used by diagnostics or tests to ensure src is a package."""
    return True
