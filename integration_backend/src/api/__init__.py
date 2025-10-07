"""
API package initializer for FastAPI routers and configuration.

This module exposes commonly used routers and helpers so other modules can import
from src.api import <module> consistently.
"""

# Re-export modules for convenient imports
# NOTE: Do NOT import src.api.main here to avoid circular import when src.app imports from src.api.*
from . import health  # noqa: F401
from . import oauth_atlassian  # noqa: F401
from . import oauth_return_flow  # noqa: F401

__all__ = [
    "health",
    "oauth_atlassian",
    "oauth_return_flow",
]
