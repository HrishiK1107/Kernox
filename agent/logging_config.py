"""
Kernox — Centralized Logging Configuration

Provides a single logger for the entire agent.
All modules should use:
    from agent.logging_config import logger
"""

import logging
import os

LOG_LEVEL = os.environ.get("KERNOX_LOG_LEVEL", "INFO").upper()

# ── Create the logger ───────────────────────────────────────
logger = logging.getLogger("kernox")
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

# ── Console handler (stderr) ────────────────────────────────
_handler = logging.StreamHandler()
_handler.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
_formatter = logging.Formatter(
    "[%(asctime)s] [%(levelname)-5s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_handler.setFormatter(_formatter)
logger.addHandler(_handler)

# Prevent duplicate logs if imported multiple times
logger.propagate = False
