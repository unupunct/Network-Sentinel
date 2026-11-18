"""Render every page to PNG (used for the documentation screenshots)."""

from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtWidgets import QApplication

from networksentinel.core.logging import get_logger

log = get_logger(__name__)

PAGES = [
    ("dashboard", "01-dashboard"),
    ("devices", "02-devices"),
    ("domains", "03-domains"),
    ("applications", "04-applications"),
    ("traffic", "05-live-traffic"),
    ("bandwidth", "06-bandwidth"),
    ("timeline", "07-timeline"),
    ("security", "08-security"),
    ("connections", "09-connections"),
    ("topology", "10-topology"),
    ("agents", "11-agents"),
    ("alerts", "12-alerts"),
    ("reports", "13-reports"),
    ("settings", "14-settings"),
]


def capture_all(window, directory: str | Path) -> list[Path]:
    """Walk every page, let it refresh, and save a PNG for each."""
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    # give the monitoring loop time to collect a real sample before capturing
    for _ in range(6):
        QApplication.processEvents()
        time.sleep(1.0)
    written: list[Path] = []
    for key, name in PAGES:
        if key not in window.pages:
            continue
        window.navigate(key)
        for _ in range(3):
            QApplication.processEvents()
            time.sleep(0.25)
        page = window.pages[key]
        refresh = getattr(page, "refresh", None)
        if callable(refresh):
            try:
                refresh()
            except Exception as exc:  # a broken page should not stop the run
                log.warning("page %s refresh failed: %s", key, exc)
        QApplication.processEvents()
        time.sleep(0.35)
        QApplication.processEvents()
        path = target / f"{name}.png"
        window.grab().save(str(path), "PNG")
        written.append(path)
        log.info("screenshot %s", path)
    return written
