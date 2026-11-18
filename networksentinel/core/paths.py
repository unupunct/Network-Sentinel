"""Filesystem locations used by Network Sentinel.

Everything is local to the user account: no data is written anywhere outside
these directories, and no data leaves the computer.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from networksentinel import APP_NAME


def _app_dir_name() -> str:
    return "NetworkSentinel"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def config_dir() -> Path:
    """Per-user configuration and database directory."""
    override = os.environ.get("NETSENTINEL_HOME")
    if override:
        path = Path(override)
    elif sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        path = Path(base or Path.home()) / _app_dir_name()
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / _app_dir_name()
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        path = Path(base) / "network-sentinel"
    path.mkdir(parents=True, exist_ok=True)
    return path


def data_dir() -> Path:
    path = config_dir() / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def log_dir() -> Path:
    path = config_dir() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def reports_dir() -> Path:
    path = config_dir() / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def database_path() -> Path:
    return data_dir() / "sentinel.db"


def agent_dir() -> Path:
    path = config_dir() / "agent"
    path.mkdir(parents=True, exist_ok=True)
    return path


def resource_path(*parts: str) -> Path:
    """Path to a bundled resource, working both from source and frozen."""
    if is_frozen():
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    else:
        base = Path(__file__).resolve().parent.parent / "resources"
    return base.joinpath(*parts)


def describe() -> str:
    return f"{APP_NAME} data directory: {config_dir()}"
