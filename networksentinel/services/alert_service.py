"""Alert engine: thresholds, history and desktop notifications."""

from __future__ import annotations

import threading

from networksentinel.core.logging import get_logger
from networksentinel.core.util import fmt_bytes, now_ts

log = get_logger(__name__)

SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]


class AlertService:
    def __init__(self, db, settings) -> None:
        self.db = db
        self.settings = settings
        self._lock = threading.Lock()
        self.recent: list[dict] = []
        self.unread = 0
        self.listeners: list = []
        self._last_device_state: dict[int, bool] = {}
        self._last_agent_seen: dict[str, float] = {}
        self._cooldowns: dict[str, float] = {}
        self.desktop_available = self._probe_desktop()

    # -- desktop notifications -------------------------------------------
    def _probe_desktop(self) -> bool:
        try:
            from PySide6.QtWidgets import QApplication  # noqa: F401

            return True
        except Exception:
            return False

    def _notify_desktop(self, title: str, body: str) -> None:
        if not self.settings.get("desktop_notifications", True):
            return
        if not self.desktop_available:
            return
        try:
            from PySide6.QtWidgets import QApplication, QSystemTrayIcon

            app = QApplication.instance()
            if app is None:
                return
            icon = getattr(app, "_sentinel_icon", None)
            tray = getattr(app, "_sentinel_tray", None)
            if tray is None:
                tray = QSystemTrayIcon(icon)
                tray.setToolTip("Network Sentinel")
                tray.show()
                setattr(app, "_sentinel_tray", tray)
            if icon is not None:
                tray.setIcon(icon)
            tray.showMessage(title, body, QSystemTrayIcon.Information, 8000)
        except Exception as exc:  # pragma: no cover - platform specific
            log.debug("desktop notification failed: %s", exc)

    # -- core ------------------------------------------------------------
    def emit(self, kind: str, severity: str, title: str, body: str,
             device_id: int | None = None, cooldown: float = 0.0,
             notify: bool = True) -> int | None:
        if not self.settings.get("alerts_enabled", True):
            return None
        key = f"{kind}:{device_id}"
        now = now_ts()
        if cooldown:
            last = self._cooldowns.get(key, 0)
            if now - last < cooldown:
                return None
            self._cooldowns[key] = now
        cur = self.db.execute(
            "INSERT INTO alerts(ts, kind, severity, title, body, device_id, read) "
            "VALUES(?,?,?,?,?,?,0)",
            (now, kind, severity, title, body, device_id),
        )
        alert = {
            "id": int(cur.lastrowid), "ts": now, "kind": kind, "severity": severity,
            "title": title, "body": body, "device_id": device_id, "read": False,
        }
        with self._lock:
            self.recent.insert(0, alert)
            self.recent = self.recent[:200]
            self.unread += 1
        if notify:
            self._notify_desktop(title, body)
        for listener in self.listeners:
            try:
                listener(alert)
            except Exception:
                pass
        return alert["id"]

    # -- event helpers ---------------------------------------------------
    def device_joined(self, device) -> None:
        if not self.settings.get("alert_new_device", True):
            return
        vendor = device.vendor or "Unknown manufacturer"
        severity = "Medium" if not device.trusted else "Informational"
        title = f"New device on the network: {device.name}"
        body = (
            f"{device.ip or 'no address'} · {device.mac} · {vendor}. "
            f"{'Device type: ' + device.device_type if device.device_type != 'Unknown' else 'Type not identified'}. "
            "Mark it as trusted once you recognise it."
        )
        self.emit("new_device", severity, title, body, device.id)
        if self.settings.get("alert_unknown_device", True) and not device.trusted:
            self.emit(
                "unknown_device", "Medium", f"Untrusted device online: {device.name}",
                f"{device.ip or device.mac} has no trust mark. Review it in the Devices page.",
                device.id, cooldown=1800,
            )

    def device_offline(self, device) -> None:
        if not self.settings.get("alert_device_offline", False):
            return
        self.emit("device_offline", "Informational", f"Device offline: {device.name}",
                  f"{device.ip or device.mac} has not been seen recently.", device.id)

    def agent_status(self, agent: dict) -> None:
        if agent.get("status") == "offline" and self.settings.get("alert_agent_offline", True):
            self.emit(
                "agent_offline", "Medium", f"Monitoring agent offline: {agent.get('name')}",
                f"The agent on {agent.get('hostname') or agent.get('name')} has not reported "
                f"within the configured interval. Application attribution for that computer "
                "is unavailable until it reconnects.",
                agent.get("device_id"), cooldown=900,
            )

    def suspicious_destination(self, device_name: str, ip: str, domain: str | None,
                               reason: str, device_id: int | None = None) -> None:
        if not self.settings.get("alert_suspicious", True):
            return
        self.emit(
            "suspicious_destination", "High",
            f"Connection to a flagged destination from {device_name}",
            f"{ip}{' (' + domain + ')' if domain else ''}: {reason}",
            device_id, cooldown=600,
        )

    def bandwidth_threshold(self, direction: str, value: float, device_id: int | None = None) -> None:
        key = "alert_upload_threshold_mb" if direction == "upload" else "alert_download_threshold_mb"
        threshold_mb = float(self.settings.get(key, 0) or 0)
        if threshold_mb <= 0:
            return
        if value < threshold_mb * 1024 * 1024:
            return
        self.emit(
            "bandwidth", "Medium",
            f"Unusual {direction} volume",
            f"{fmt_bytes(value)} {direction}ed within 10 minutes (threshold "
            f"{threshold_mb:.0f} MB).",
            device_id, cooldown=1800,
        )

    def tracking_state(self, devices: list) -> None:
        """Detect devices that went offline since the previous pass."""
        for device in devices:
            previous = self._last_device_state.get(device.id)
            if previous is True and not device.online:
                self.device_offline(device)
            self._last_device_state[device.id] = device.online

    # -- queries ---------------------------------------------------------
    def list(self, limit: int = 300, severity: str | None = None,
             unread_only: bool = False) -> list[dict]:
        sql = "SELECT * FROM alerts WHERE 1=1"
        params: list = []
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if unread_only:
            sql += " AND read = 0"
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.db.query(sql, params)]

    def mark_read(self, alert_id: int | None = None) -> None:
        if alert_id:
            self.db.execute("UPDATE alerts SET read = 1 WHERE id = ?", (alert_id,))
        else:
            self.db.execute("UPDATE alerts SET read = 1 WHERE read = 0")
        self.unread = self.db.scalar("SELECT COUNT(*) FROM alerts WHERE read = 0")

    def clear(self) -> None:
        self.db.execute("DELETE FROM alerts")
        with self._lock:
            self.recent.clear()
            self.unread = 0

    def counts_by_severity(self) -> dict[str, int]:
        rows = self.db.query(
            "SELECT severity, COUNT(*) FROM alerts WHERE read = 0 GROUP BY severity"
        )
        return {row[0]: row[1] for row in rows}

    def unread_count(self) -> int:
        self.unread = self.db.scalar("SELECT COUNT(*) FROM alerts WHERE read = 0")
        return int(self.unread or 0)
