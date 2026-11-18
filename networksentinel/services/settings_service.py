"""Persisted settings with defaults and validation.

Settings are stored in the SQLite ``settings`` table as JSON values.  Anything
that is not explicitly stored falls back to :data:`DEFAULTS`.
"""

from __future__ import annotations

from typing import Any

from networksentinel.core.database import Database
from networksentinel.core.logging import get_logger

log = get_logger(__name__)

DEFAULTS: dict[str, Any] = {
    # monitoring scope
    "interface": "",              # selected capture interface (OS name)
    "monitoring_enabled": True,
    "capture_enabled": False,     # raw packet capture needs privileges
    "capture_filter": "not port 22",
    "dns_capture_enabled": True,
    "active_scan_interval": 60,   # seconds between ARP sweeps
    "passive_window": 15,         # seconds of packet buffering
    "sample_interval": 5,         # bandwidth sampling interval (seconds)
    # retention
    "retention_days": 30,
    "traffic_row_limit": 200_000,
    "auto_purge": True,
    # alerts
    "alerts_enabled": True,
    "desktop_notifications": True,
    "alert_new_device": True,
    "alert_unknown_device": True,
    "alert_device_offline": False,
    "alert_agent_offline": True,
    "alert_suspicious": True,
    "alert_upload_threshold_mb": 500,     # per 10 minutes, 0 = off
    "alert_download_threshold_mb": 2000,
    "alert_bandwidth_spike_mb": 100,      # per sample interval, 0 = off
    "alert_new_application": False,
    # security
    "security_enabled": True,
    "threat_intel_enabled": True,
    "threat_intel_last_update": 0,
    "port_scan_threshold": 12,
    "connection_failure_threshold": 8,
    # agent server
    "agent_server_enabled": True,
    "agent_server_host": "0.0.0.0",
    "agent_server_port": 8765,
    "agent_offline_after": 90,
    "agent_interval": 5,
    "agent_collect_dns": True,
    "agent_collect_traffic": True,
    "agent_collect_processes": True,
    # ui
    "last_section": "dashboard",
    "window_width": 1500,
    "window_height": 940,
    "remember_window": True,
    "ui_mode": "advanced",
    "theme": "sentinel",
    "onboarded": False,
    "language": "en",
    # privacy
    "telemetry_consent": False,   # never used unless the user opts in
    "store_hostnames": True,
    "store_dns": True,
}


class SettingsService:
    def __init__(self, db: Database) -> None:
        self.db = db
        self._cache: dict[str, Any] = {}
        self._cache.update(DEFAULTS)
        self._cache.update(db.all_settings())

    # -- reading ---------------------------------------------------------
    def get(self, key: str, default: Any = None) -> Any:
        if key in self._cache:
            return self._cache[key]
        return DEFAULTS.get(key, default)

    def as_dict(self) -> dict[str, Any]:
        return dict(self._cache)

    def __getitem__(self, key: str) -> Any:
        return self.get(key)

    # -- writing ---------------------------------------------------------
    def set(self, key: str, value: Any) -> None:
        self._cache[key] = value
        self.db.set_setting(key, value)

    def update(self, **values: Any) -> None:
        for key, value in values.items():
            self.set(key, value)

    def reset(self) -> None:
        self.db.execute("DELETE FROM settings")
        self._cache = dict(DEFAULTS)

    def validated(self) -> dict[str, str]:
        """Return a mapping of setting -> problem for out-of-range values."""
        problems: dict[str, str] = {}
        if not (1 <= int(self.get("retention_days", 30)) <= 3650):
            problems["retention_days"] = "must be between 1 and 3650 days"
        if not (5 <= int(self.get("active_scan_interval", 60)) <= 3600):
            problems["active_scan_interval"] = "must be between 5 and 3600 seconds"
        if not (1 <= int(self.get("sample_interval", 5)) <= 60):
            problems["sample_interval"] = "must be between 1 and 60 seconds"
        port = int(self.get("agent_server_port", 8765))
        if not (1024 <= port <= 65535):
            problems["agent_server_port"] = "must be between 1024 and 65535"
        return problems
