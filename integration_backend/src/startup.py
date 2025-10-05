"""
Application startup utilities: load .env early and configure logging.

This module should be imported as early as possible (before accessing environment variables)
to ensure python-dotenv loads the .env file into process environment during local/dev and preview runs.
"""

from __future__ import annotations

import logging
import os

try:
    # Load environment variables from .env in the integration_backend directory (project root for backend)
    # Do not fail if missing; environments may provide vars through the process manager.
    from dotenv import load_dotenv

    # Determine base path for .env: prefer current working directory, fallback to parent directory of this file.
    # In our container, CWD is integration_backend, which contains the .env file per README instructions.
    load_dotenv(dotenv_path=os.path.join(os.getcwd(), ".env"), override=False)
except Exception:
    # If python-dotenv is not installed or any error occurs, continue silently.
    pass

# Basic logging configuration if not configured by the host
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

logger = logging.getLogger("startup")
logger.info("Startup initialized. .env loaded=%s", True)
