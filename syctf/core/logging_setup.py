"""Logging setup utilities for SYCTF."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_logging(log_file: Path) -> logging.Logger:
    """Configure and return the application logger."""

    log_file.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("syctf")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        filename=log_file,
        maxBytes=5_000_000,
        backupCount=5,
        encoding="utf-8",
        delay=True,
    )
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    return logger
