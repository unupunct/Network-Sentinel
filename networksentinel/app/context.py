"""Composition root: builds every service and runs the background workers.

Threading model
---------------
* **GUI thread** - Qt widgets only.  Services are read from it.
* **monitor thread** - discovery, inventory sync, local connection poll,
  bandwidth sampling, security analysis.  Runs every ``sample_interval``.
* **capture thread(s)** - started by :class:`TrafficMonitorService` only when
  the user enables packet capture.
* **agent server thread** - uvicorn, only when the user enables it.

Services never touch Qt objects; the UI polls them with a QTimer, which keeps
the interface responsive regardless of what the network is doing.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from networksentinel.core.database import Database
from networksentinel.core.logging import get_logger
from networksentinel.core.util import now_ts
from networksentinel.services.agent_server import AgentServerService
from networksentinel.services.alert_service import AlertService
from networksentinel.services.bandwidth_service import BandwidthService
from networksentinel.services.connection_explorer import ConnectionExplorerService
from networksentinel.services.connection_service import ConnectionService
from networksentinel.services.discovery_service import NetworkDiscoveryService
from networksentinel.services.dns_service import DnsMonitorService, DnsResolver
from networksentinel.services.inventory_service import DeviceInventoryService
from networksentinel.services.interface_service import InterfaceService
from networksentinel.services.report_service import ReportService
from networksentinel.services.security_service import SecurityDetectionService
from networksentinel.services.settings_service import SettingsService
from networksentinel.services.timeline_service import TimelineService
from networksentinel.services.traffic_service import TrafficMonitorService

log = get_logger(__name__)


@dataclass
class ContextStatus:
    monitoring: bool = False
    started_at: float = 0.0
    last_cycle: float = 0.0
    cycle_count: int = 0
    last_error: str | None = None


class AppContext:
    def __init__(self, db_path: str | None = None) -> None:
        self.db = Database(db_path) if db_path else Database()
        self.settings = SettingsService(self.db)
        self.interfaces = InterfaceService()
        self.interfaces.discover()
        self.resolver = DnsResolver()
        self.dns = DnsMonitorService(self.db, self.resolver, self.settings)
        self.discovery = NetworkDiscoveryService(self.settings, self.dns, self.interfaces)
        self.alerts = AlertService(self.db, self.settings)
        self.inventory = DeviceInventoryService(self.db, self.settings, self.discovery, self.alerts)
        self.connections = ConnectionService()
        self.explorer = ConnectionExplorerService(
            self.db, self.settings, self.connections, self.inventory, self.dns, self.resolver
        )
        self.bandwidth = BandwidthService(
            self.db, self.settings, self.interfaces, self.connections, self.inventory
        )
        self.traffic = TrafficMonitorService(
            self.db, self.settings, self.interfaces, self.discovery, self.dns, self.inventory
        )
        self.timeline = TimelineService(self.db, self.inventory)
        self.agents = AgentServerService(
            self.db, self.settings, self.inventory, self.explorer, self.dns,
            self.traffic, self.bandwidth, self.alerts,
        )
        self.security = SecurityDetectionService(
            self.db, self.settings, self.inventory, self.explorer, self.traffic,
            self.dns, self.bandwidth, self.alerts, self.agents,
        )
        self.agents.security = self.security
        self.reports = ReportService(
            self.db, self.inventory, self.explorer, self.dns, self.bandwidth,
            self.security, self.alerts, self.timeline, self.settings, self.interfaces,
        )
        self.status = ContextStatus()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._known_conn_keys: set[str] = set()
        self._last_dns_count = 0
        self._last_purge = 0.0
        self._last_discovery = 0.0
        self._last_security = 0.0
        self.interface = self.interfaces.select(self.settings.get("interface"))
        if self.interface and not self.settings.get("interface"):
            self.settings.set("interface", self.interface.name)
        self.db.audit("app", "start", "", f"interface {self.interface.name if self.interface else 'none'}")

    # -- lifecycle -------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self.status.monitoring = True
        self.status.started_at = now_ts()
        self._thread = threading.Thread(target=self._loop, name="sentinel-monitor", daemon=True)
        self._thread.start()
        if self.settings.get("agent_server_enabled", True):
            result = self.agents.start()
            if not result.get("running"):
                log.warning("agent server did not start: %s", result.get("error"))
        log.info("monitoring started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self.status.monitoring = False
        try:
            self.traffic.stop()
        except Exception:
            pass
        try:
            self.agents.stop()
        except Exception:
            pass
        for service in (self.dns,):
            try:
                service.flush()
            except Exception:
                pass
        self.db.audit("app", "stop", "", "")
        log.info("monitoring stopped")

    def shutdown(self) -> None:
        self.stop()
        self.db.close()

    @property
    def monitoring(self) -> bool:
        return self.status.monitoring

    def set_monitoring(self, enabled: bool) -> None:
        if enabled:
            self.start()
        else:
            self.stop()

    def select_interface(self, name: str) -> None:
        self.settings.set("interface", name)
        self.interface = self.interfaces.select(name)
        if self.interface:
            self.traffic.local_ips = {self.interface.ipv4} if self.interface.ipv4 else set()
            if self.traffic.status.running:
                self.traffic.stop()
                self.traffic.start(self.interface.name)
        self.db.audit("user", "interface.select", name, "")

    # -- background loop -------------------------------------------------
    def _loop(self) -> None:
        interval = float(self.settings.get("sample_interval", 5))
        while not self._stop.is_set():
            started = time.time()
            try:
                self._cycle()
                self.status.last_error = None
            except Exception as exc:  # pragma: no cover - defensive
                self.status.last_error = str(exc)
                log.exception("monitor cycle failed: %s", exc)
            self.status.last_cycle = now_ts()
            self.status.cycle_count += 1
            elapsed = time.time() - started
            self._stop.wait(max(0.5, interval - elapsed))

    def _cycle(self) -> None:
        if not self.settings.get("monitoring_enabled", True):
            return
        now = now_ts()
        # 1. discovery + inventory
        if now - self._last_discovery >= float(self.settings.get("active_scan_interval", 60)):
            self.discovery.scan(self.settings.get("interface"))
            self.inventory.sync()
            self._last_discovery = now
            self.alerts.tracking_state(self.inventory.all_devices())
        # 2. this computer's sockets -> connection history
        before = self.explorer.new_connections
        self.explorer.poll_local(self.interface.ipv4 if self.interface else None)
        if self.explorer.new_connections > before:
            for entry in self.explorer.query(since=now - 60, limit=40):
                if entry["conn_key"] in self._known_conn_keys:
                    continue
                self._known_conn_keys.add(entry["conn_key"])
                device_id = entry.get("device_id")
                self.timeline.record(
                    device_id, "connection",
                    f"{entry.get('application') or 'Unattributed'} → {entry.get('domain') or entry.get('remote_ip')}",
                    f"{entry['protocol']} {entry['remote_ip']}:{entry['remote_port']}",
                    "observed", entry.get("source") or "OS socket table",
                )
        # 3. DNS observations -> timeline
        dns_total = self.db.scalar("SELECT COUNT(*) FROM dns_queries")
        if dns_total and dns_total != self._last_dns_count:
            for row in self.db.query(
                "SELECT * FROM dns_queries ORDER BY ts DESC LIMIT 20"
            ):
                self.timeline.record(
                    row["device_id"], "dns", f"DNS query: {row['domain']}",
                    f"{row['qtype']} · {row['category'] or ''}", "observed", row["source"] or "DNS",
                )
            self._last_dns_count = dns_total
        # 4. bandwidth sample
        self.bandwidth.sample(self.interface.name if self.interface else None)
        # 5. security analysis (less often)
        if now - self._last_security >= max(30.0, float(self.settings.get("sample_interval", 5)) * 3):
            self.security.run()
            self._last_security = now
        # 6. agent liveness
        self.agents.check_offline()
        # 7. retention
        if self.settings.get("auto_purge", True) and now - self._last_purge > 3600:
            self.purge_old_data()
            self._last_purge = now

    # -- maintenance -----------------------------------------------------
    def purge_old_data(self) -> dict:
        days = int(self.settings.get("retention_days", 30))
        cutoff = now_ts() - days * 86400
        removed = {}
        for table, column in (
            ("traffic", "ts"), ("dns_queries", "ts"), ("connections", "last_seen"),
            ("bandwidth_samples", "ts"), ("findings", "ts"), ("alerts", "ts"),
            ("events", "ts"), ("audit_log", "ts"),
        ):
            removed[table] = self.db.purge_older_than(table, column, cutoff)
        limit = int(self.settings.get("traffic_row_limit", 200_000))
        count = self.db.scalar("SELECT COUNT(*) FROM traffic")
        if count > limit:
            self.db.execute(
                "DELETE FROM traffic WHERE id IN (SELECT id FROM traffic ORDER BY ts ASC LIMIT ?)",
                (count - limit,),
            )
            removed["traffic_rotation"] = count - limit
        return removed

    # -- dashboard data --------------------------------------------------
    def dashboard(self) -> dict:
        now = now_ts()
        devices = self.inventory.all_devices()
        online = [d for d in devices if d.online]
        agent_devices = {a["device_id"] for a in self.agents.list_agents() if a.get("device_id")}
        transferring = []
        usage = {u["device_id"]: u for u in self.bandwidth.device_usage()}
        for device in online:
            rate = usage.get(device.id, {}).get("download_bps", 0) + usage.get(device.id, {}).get("upload_bps", 0)
            if rate > 1024:
                transferring.append(device)
        top_domains = self.dns.top_domains(now - 86400, 8)
        apps = self.explorer.applications(since=now - 3600)[:8]
        bandwidth = self.bandwidth.summary()
        most_active = None
        if usage:
            best = max(usage.values(), key=lambda u: u["download_bytes"] + u["upload_bytes"])
            most_active = best
        return {
            "devices_total": len(devices),
            "devices_online": len(online),
            "devices_offline": len(devices) - len(online),
            "devices_transferring": len(transferring),
            "agents_online": len(agent_devices),
            "download_bps": bandwidth["download_bps"],
            "upload_bps": bandwidth["upload_bps"],
            "today_download": bandwidth["today_download"],
            "today_upload": bandwidth["today_upload"],
            "peak_download": bandwidth["peak_download"],
            "peak_upload": bandwidth["peak_upload"],
            "interface": bandwidth["interface"],
            "most_active_device": most_active,
            "top_domains": top_domains,
            "top_apps": apps,
            "suspicious": self.security.open_count(),
            "findings_by_severity": self.security.counts(),
            "recent_alerts": self.alerts.list(limit=8),
            "unread_alerts": self.alerts.unread_count(),
            "connections_active": self.explorer.stats()["active"],
            "dns_today": self.db.scalar("SELECT COUNT(*) FROM dns_queries WHERE ts >= ?", (now - 86400,)),
            "capture": self.traffic.stats(),
            "monitoring": self.status.monitoring,
            "per_device_available": bool(self.bandwidth.per_device),
            "per_device_note": (
                "Per-device traffic for other computers needs packet capture or an enrolled agent; "
                "only this computer's traffic is measured directly."
            ),
        }

    def interface_info(self) -> dict:
        iface = self.interface
        if iface is None:
            return {"available": False, "privileges": self.interfaces.privileges}
        return {
            "available": True,
            "name": iface.name,
            "description": iface.description,
            "ipv4": iface.ipv4,
            "mac": iface.mac,
            "gateway": iface.gateway,
            "cidr": iface.cidr,
            "hosts": iface.usable_hosts,
            "dns_servers": iface.dns_servers,
            "is_up": iface.is_up,
            "privileges": self.interfaces.privileges,
            "capture": self.traffic.stats(),
            "agent_server": self.agents.status(),
        }

    def health(self) -> dict:
        return {
            "database": str(self.db.path),
            "database_bytes": self.db.size_bytes(),
            "monitoring": self.status.monitoring,
            "cycles": self.status.cycle_count,
            "last_cycle": self.status.last_cycle,
            "error": self.status.last_error,
            "agents": len(self.agents.list_agents()),
            "capture": self.traffic.stats(),
            "security": self.security.stats(),
            "dns": self.dns.stats(),
            "connections": self.explorer.stats(),
            "discovery": self.discovery.stats(),
        }


def build_context(db_path: str | None = None) -> AppContext:
    return AppContext(db_path)
