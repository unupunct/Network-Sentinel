"""Logging setup: rotating file handler plus console output."""

from __future__ import annotations

import logging
import logging.handlers
import sys

from networksentinel.core.paths import log_dir

_CONFIGURED = False


def setup_logging(level: int = logging.INFO) -> str:
    global _CONFIGURED
    log_file = log_dir() / "sentinel.log"
    if _CONFIGURED:
        return str(log_file)
    root = logging.getLogger()
    root.setLevel(level)
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)-34s %(message)s", "%Y-%m-%d %H:%M:%S"
    )
    try:
        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(fmt)
        root.addHandler(handler)
    except OSError:
        pass
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(fmt)
    console.setLevel(logging.WARNING)
    root.addHandler(console)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    _CONFIGURED = True
    return str(log_file)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
