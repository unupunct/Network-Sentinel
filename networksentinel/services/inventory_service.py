"""Device inventory: persistence, user annotations and inventory statistics."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from networksentinel.core.logging import get_logger
from networksentinel.core.util import now_ts
from networksentinel.services.oui import normalize_mac

log = get_logger(__name__)

DEFAULT_OFFLINE_AFTER = 300.0  # seconds without an observation


@dataclass
class Device:
    id: int
    mac: str
    ip: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    os_guess: str | None = None
    os_confidence: str = "Unidentified"
    device_type: str = "Unknown"
    custom_name: str | None = None
    custom_category: str | None = None
    description: str | None = None
    trusted: bool = False
    is_self: bool = False
    is_gateway: bool = False
    is_agent: bool = False
    first_seen: float | None = None
    last_seen: float | None = None
    online: bool = False
    source: str = "arp"
    evidence: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.custom_name or self.hostname or self.ip or self.mac

    @property
    def category(self) -> str:
        return self.custom_category or self.device_type or "Unknown"

    @property
    def display_os(self) -> str:
        if self.os_guess:
            return self.os_guess
        return "Unidentified"

    @property
    def os_label(self) -> str:
        if not self.os_guess:
            return "Unidentified"
        return f"{self.os_guess} ({self.os_confidence.lower()})"

    @property
    def status(self) -> str:
        return "Online" if self.online else "Offline"


class DeviceInventoryService:
    """Keeps the device table up to date and stores user annotations."""

    def __init__(self, db, settings, discovery, alerts=None) -> None:
        self.db = db
        self.settings = settings
        self.discovery = discovery
        self.alerts = alerts
        self._lock = threading.Lock()
        self.last_sync: float = 0.0
        self.new_devices: list[int] = []

    # -- persistence -----------------------------------------------------
    def _row_to_device(self, row) -> Device:
        return Device(
            id=row["id"],
            mac=row["mac"],
            ip=row["ip"],
            hostname=row["hostname"],
            vendor=row["vendor"],
            os_guess=row["os_guess"],
            os_confidence=row["os_confidence"] or "Unidentified",
            device_type=row["device_type"] or "Unknown",
            custom_name=row["custom_name"],
            custom_category=row["custom_category"],
            description=row["description"],
            trusted=bool(row["trusted"]),
            is_self=bool(row["is_self"]),
            is_gateway=bool(row["is_gateway"]),
            is_agent=bool(row["is_agent"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            online=bool(row["online"]),
            source=row["source"] or "",
            evidence=(row["evidence"] or "").split("|") if row["evidence"] else [],
        )

    def all_devices(self, include_offline: bool = True) -> list[Device]:
        sql = "SELECT * FROM devices"
        if not include_offline:
            sql += " WHERE online = 1"
        sql += " ORDER BY online DESC, last_seen DESC"
        return [self._row_to_device(row) for row in self.db.query(sql)]

    def get(self, device_id: int) -> Device | None:
        row = self.db.query_one("SELECT * FROM devices WHERE id = ?", (device_id,))
        return self._row_to_device(row) if row else None

    def by_mac(self, mac: str) -> Device | None:
        row = self.db.query_one("SELECT * FROM devices WHERE mac = ?", (normalize_mac(mac),))
        return self._row_to_device(row) if row else None

    def by_ip(self, ip: str | None) -> Device | None:
        if not ip:
            return None
        row = self.db.query_one(
            "SELECT d.* FROM devices d LEFT JOIN device_ips di ON di.device_id = d.id "
            "WHERE d.ip = ? OR di.ip = ? ORDER BY d.last_seen DESC LIMIT 1",
            (ip, ip),
        )
        return self._row_to_device(row) if row else None

    def _upsert(self, observed) -> tuple[int, bool]:
        mac = normalize_mac(observed.mac)
        if not mac:
            return 0, False
        existing = self.db.query_one("SELECT * FROM devices WHERE mac = ?", (mac,))
        ts = now_ts()
        evidence = "|".join(observed.evidence[:12])
        if existing is None:
            cur = self.db.execute(
                "INSERT INTO devices(mac, ip, hostname, vendor, os_guess, os_confidence, "
                "device_type, first_seen, last_seen, online, source, evidence, is_self, "
                "is_gateway) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    mac, observed.ip, observed.hostname, observed.vendor, observed.os_guess,
                    observed.os_confidence, observed.device_type, ts, ts, 1,
                    observed.source, evidence, int(observed.is_self), int(observed.is_gateway),
                ),
            )
            device_id = int(cur.lastrowid)
            self._record_ip(device_id, observed.ip)
            return device_id, True

        device_id = int(existing["id"])
        # Only overwrite fields we actually observed; never erase a known value.
        self.db.execute(
            "UPDATE devices SET ip = COALESCE(?, ip), hostname = COALESCE(?, hostname), "
            "vendor = COALESCE(?, vendor), os_guess = COALESCE(?, os_guess), "
            "os_confidence = CASE WHEN ? != 'Unidentified' THEN ? ELSE os_confidence END, "
            "device_type = CASE WHEN ? NOT IN ('', 'Unknown') THEN ? ELSE device_type END, "
            "last_seen = ?, online = 1, source = COALESCE(?, source), "
            "evidence = CASE WHEN ? != '' THEN ? ELSE evidence END, "
            "is_self = MAX(is_self, ?), is_gateway = MAX(is_gateway, ?) "
            "WHERE id = ?",
            (
                observed.ip, observed.hostname, observed.vendor, observed.os_guess,
                observed.os_confidence, observed.os_confidence,
                observed.device_type, observed.device_type,
                ts, observed.source, evidence, evidence,
                int(observed.is_self), int(observed.is_gateway), device_id,
            ),
        )
        self._record_ip(device_id, observed.ip)
        return device_id, False

    def _record_ip(self, device_id: int, ip: str | None) -> None:
        if not ip:
            return
        self.db.execute(
            "INSERT INTO device_ips(device_id, ip, first_seen, last_seen) VALUES(?,?,?,?) "
            "ON CONFLICT(device_id, ip) DO UPDATE SET last_seen = excluded.last_seen",
            (device_id, ip, now_ts(), now_ts()),
        )

    def sync(self) -> dict:
        """Merge the discovery snapshot into the database."""
        observed = self.discovery.snapshot()
        created: list[int] = []
        updated = 0
        with self._lock:
            for item in observed:
                device_id, is_new = self._upsert(item)
                if not device_id:
                    continue
                if is_new:
                    created.append(device_id)
                else:
                    updated += 1
        # Devices that have not been seen for a while become offline.
        cutoff = now_ts() - DEFAULT_OFFLINE_AFTER
        self.db.execute(
            "UPDATE devices SET online = 0 WHERE last_seen < ? AND online = 1", (cutoff,)
        )
        self.last_sync = now_ts()
        self.new_devices = created
        if created and self.alerts:
            for device_id in created:
                device = self.get(device_id)
                if device:
                    self.alerts.device_joined(device)
        return {"created": len(created), "updated": updated, "total": len(observed)}

    # -- annotations -----------------------------------------------------
    def rename(self, device_id: int, name: str | None) -> None:
        self.db.execute(
            "UPDATE devices SET custom_name = ? WHERE id = ?", ((name or "").strip() or None, device_id)
        )
        self.db.audit("user", "device.rename", str(device_id), name or "")

    def set_category(self, device_id: int, category: str | None) -> None:
        self.db.execute(
            "UPDATE devices SET custom_category = ? WHERE id = ?",
            ((category or "").strip() or None, device_id),
        )
        self.db.audit("user", "device.category", str(device_id), category or "")

    def set_description(self, device_id: int, text: str | None) -> None:
        self.db.execute(
            "UPDATE devices SET description = ? WHERE id = ?", ((text or "").strip() or None, device_id)
        )
        self.db.audit("user", "device.describe", str(device_id), "updated")

    def set_trusted(self, device_id: int, trusted: bool) -> None:
        self.db.execute("UPDATE devices SET trusted = ? WHERE id = ?", (int(trusted), device_id))
        self.db.audit("user", "device.trust", str(device_id), str(trusted))

    def mark_agent(self, device_id: int, is_agent: bool = True) -> None:
        self.db.execute("UPDATE devices SET is_agent = ? WHERE id = ?", (int(is_agent), device_id))

    def forget(self, device_id: int) -> None:
        self.db.execute("DELETE FROM device_ips WHERE device_id = ?", (device_id,))
        self.db.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        self.db.audit("user", "device.forget", str(device_id), "")

    # -- statistics ------------------------------------------------------
    def summary(self) -> dict:
        total = self.db.scalar("SELECT COUNT(*) FROM devices")
        online = self.db.scalar("SELECT COUNT(*) FROM devices WHERE online = 1")
        trusted = self.db.scalar("SELECT COUNT(*) FROM devices WHERE trusted = 1")
        unknown = self.db.scalar(
            "SELECT COUNT(*) FROM devices WHERE trusted = 0 AND online = 1"
        )
        agents = self.db.scalar("SELECT COUNT(*) FROM devices WHERE is_agent = 1")
        return {
            "total": total,
            "online": online,
            "offline": total - online,
            "trusted": trusted,
            "untrusted_online": unknown,
            "agents": agents,
        }

    def categories(self) -> dict[str, int]:
        rows = self.db.query(
            "SELECT COALESCE(NULLIF(custom_category, ''), device_type) AS cat, COUNT(*) "
            "FROM devices GROUP BY cat ORDER BY 2 DESC"
        )
        return {(row[0] or "Unknown"): row[1] for row in rows}

    def history(self, device_id: int, since: float = 0.0, limit: int = 200) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM events WHERE device_id = ? AND ts >= ? ORDER BY ts DESC LIMIT ?",
            (device_id, since, limit),
        )
        return [dict(r) for r in rows]

    def ips(self, device_id: int) -> list[dict]:
        rows = self.db.query(
            "SELECT ip, first_seen, last_seen FROM device_ips WHERE device_id = ? "
            "ORDER BY last_seen DESC",
            (device_id,),
        )
        return [dict(r) for r in rows]

    def label_map(self) -> dict[int, str]:
        return {
            int(row["id"]): (row["custom_name"] or row["hostname"] or row["ip"] or row["mac"])
            for row in self.db.query("SELECT id, custom_name, hostname, ip, mac FROM devices")
        }
