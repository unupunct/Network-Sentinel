"""Bandwidth monitoring.

Two independent measurements, never mixed without a label:

``interface counters`` (always available)
    ``psutil.net_io_counters(pernic=True)`` on the selected interface.  Gives
    real total upload/download for the whole interface, per sample.

``per-process counters`` (this computer)
    ``psutil`` process I/O counters.  Windows and Linux both expose cumulative
    read/write bytes per process; the delta between two samples gives the rate
    and the accumulated bytes.  These counters are for the *whole process*, so
    they include disk I/O on some platforms - the UI labels them
    "process counters" rather than "network".

``agent per-connection counters`` (managed computers)
    The agent reports kernel per-connection byte counts
    (``GetPerTcpConnectionEStats`` on Windows); those are exact per connection
    and are labelled "agent (kernel counters)".

``per-device`` traffic for other devices is only available from passive packet
capture; when capture is off the UI shows ``Requires capture`` or
``Requires Agent`` rather than a made-up number.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from networksentinel.core.logging import get_logger
from networksentinel.core.util import now_ts

log = get_logger(__name__)


@dataclass
class RateSample:
    ts: float
    download_bps: float
    upload_bps: float
    download_bytes: int
    upload_bytes: int


class BandwidthService:
    def __init__(self, db, settings, interfaces, connections, inventory) -> None:
        self.db = db
        self.settings = settings
        self.interfaces = interfaces
        self.connections = connections
        self.inventory = inventory
        self._lock = threading.Lock()
        self._last_counters: dict | None = None
        self._last_ts: float = 0.0
        self._proc_prev: dict[int, tuple[int, int]] = {}
        self._proc_bytes: dict[int, dict] = {}
        self._proc_rates: dict[int, tuple[float, float]] = {}
        self.history: list[RateSample] = []
        self.max_history = 720          # 720 samples
        self.sample_interval = float(settings.get("sample_interval", 5))
        self.last_sample: float = 0.0
        self.today_start = self._midnight()
        self.today_download = 0
        self.today_upload = 0
        self.peak_download = 0.0
        self.peak_upload = 0.0
        self.current: RateSample | None = None
        self.interface_name: str | None = None
        self.per_device: dict[int, dict] = {}
        self.capture_device_rates: dict[str, dict] = {}

    @staticmethod
    def _midnight() -> float:
        lt = time.localtime()
        start = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1))
        return start

    # -- sampling --------------------------------------------------------
    def sample(self, interface_name: str | None = None) -> RateSample | None:
        import psutil

        iface = self.interfaces.select(interface_name or self.settings.get("interface"))
        if iface is None:
            return None
        name = iface.name
        self.interface_name = name
        try:
            counters = psutil.net_io_counters(pernic=True).get(name)
        except Exception as exc:  # pragma: no cover
            log.warning("net_io_counters failed: %s", exc)
            return None
        if counters is None:
            return None
        ts = now_ts()
        if self._last_counters is None or self._last_ts == 0:
            self._last_counters = counters
            self._last_ts = ts
            sample = RateSample(ts, 0.0, 0.0, counters.bytes_recv, counters.bytes_sent)
            self.current = sample
            return sample
        elapsed = max(0.001, ts - self._last_ts)
        d_recv = max(0, counters.bytes_recv - self._last_counters.bytes_recv)
        d_sent = max(0, counters.bytes_sent - self._last_counters.bytes_sent)
        sample = RateSample(
            ts=ts,
            download_bps=d_recv / elapsed,
            upload_bps=d_sent / elapsed,
            download_bytes=d_recv,
            upload_bytes=d_sent,
        )
        self._last_counters = counters
        self._last_ts = ts
        self.current = sample
        self.last_sample = ts

        if ts - self.today_start > 86400 or time.localtime(ts)[:3] != time.localtime(self.today_start)[:3]:
            self.today_start = self._midnight()
            self.today_download = 0
            self.today_upload = 0
        self.today_download += d_recv
        self.today_upload += d_sent
        self.peak_download = max(self.peak_download, sample.download_bps)
        self.peak_upload = max(self.peak_upload, sample.upload_bps)

        with self._lock:
            self.history.append(sample)
            if len(self.history) > self.max_history:
                self.history = self.history[-self.max_history:]

        self._sample_processes(ts, elapsed, d_recv, d_sent)
        self._persist(sample)
        return sample

    def _sample_processes(self, ts: float, elapsed: float, d_recv: int, d_sent: int) -> None:
        """Per-process cumulative bytes from process counters."""
        traffic = self.connections.process_traffic()
        total_read = sum(p.read_bytes for p in traffic.values())
        total_write = sum(p.write_bytes for p in traffic.values())
        for pid, proc in traffic.items():
            prev = self._proc_prev.get(pid)
            if prev is None:
                self._proc_prev[pid] = (proc.read_bytes, proc.write_bytes)
                self._proc_bytes.setdefault(pid, {"name": proc.name, "down": 0, "up": 0})
                continue
            down = max(0, proc.read_bytes - prev[0])
            up = max(0, proc.write_bytes - prev[1])
            entry = self._proc_bytes.setdefault(pid, {"name": proc.name, "down": 0, "up": 0})
            entry["name"] = proc.name
            entry["down"] += down
            entry["up"] += up
            self._proc_prev[pid] = (proc.read_bytes, proc.write_bytes)
            self._proc_rates[pid] = (down / elapsed, up / elapsed)
        # Drop processes that vanished
        alive = set(traffic)
        for pid in list(self._proc_prev):
            if pid not in alive:
                self._proc_prev.pop(pid, None)
                self._proc_rates.pop(pid, None)
        # Spread interface delta over processes when the sum is plausible,
        # otherwise leave per-process numbers as raw process counters.
        self._proc_totals = (total_read, total_write)

    def _persist(self, sample: RateSample) -> None:
        self_device = self.inventory.by_mac(self.interfaces.primary().mac) if self.interfaces.primary() else None
        self.db.execute(
            "INSERT INTO bandwidth_samples(ts, device_id, scope, name, upload_bps, "
            "download_bps, upload_bytes, download_bytes, source) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                sample.ts, self_device.id if self_device else None, "interface",
                self.interface_name, sample.upload_bps, sample.download_bps,
                sample.upload_bytes, sample.download_bytes, "interface counters",
            ),
        )

    # -- queries ---------------------------------------------------------
    def series(self, minutes: int = 15, limit: int = 240) -> list[dict]:
        since = now_ts() - minutes * 60
        with self._lock:
            points = [s for s in self.history if s.ts >= since]
        if len(points) > limit:
            step = max(1, len(points) // limit)
            points = points[::step]
        return [
            {"ts": p.ts, "download_bps": p.download_bps, "upload_bps": p.upload_bps,
             "total_bps": p.download_bps + p.upload_bps}
            for p in points
        ]

    def stored_series(self, minutes: int = 60) -> list[dict]:
        since = now_ts() - minutes * 60
        rows = self.db.query(
            "SELECT ts, SUM(upload_bps) AS up, SUM(download_bps) AS down "
            "FROM bandwidth_samples WHERE ts >= ? AND scope = 'interface' "
            "GROUP BY CAST(ts AS INTEGER) ORDER BY ts",
            (since,),
        )
        return [{"ts": r["ts"], "upload_bps": r["up"], "download_bps": r["down"]} for r in rows]

    def process_usage(self, limit: int = 25) -> list[dict]:
        rows = []
        for pid, entry in self._proc_bytes.items():
            down_rate, up_rate = self._proc_rates.get(pid, (0.0, 0.0))
            rows.append(
                {
                    "pid": pid,
                    "name": entry["name"],
                    "download_bytes": entry["down"],
                    "upload_bytes": entry["up"],
                    "total_bytes": entry["down"] + entry["up"],
                    "download_bps": down_rate,
                    "upload_bps": up_rate,
                    "source": "process counters",
                }
            )
        rows.sort(key=lambda r: r["total_bytes"], reverse=True)
        return rows[:limit]

    def device_usage(self) -> list[dict]:
        """Per-device traffic where it is really measurable."""
        labels = self.inventory.label_map()
        devices = {d.id: d for d in self.inventory.all_devices()}
        out = []
        for device_id, data in self.per_device.items():
            device = devices.get(device_id)
            if device is None:
                continue
            out.append(
                {
                    "device_id": device_id,
                    "name": labels.get(device_id, str(device_id)),
                    "download_bps": data.get("download_bps", 0.0),
                    "upload_bps": data.get("upload_bps", 0.0),
                    "download_bytes": data.get("download_bytes", 0),
                    "upload_bytes": data.get("upload_bytes", 0),
                    "source": data.get("source", "capture"),
                }
            )
        out.sort(key=lambda r: r["download_bytes"] + r["upload_bytes"], reverse=True)
        return out

    def summary(self) -> dict:
        current = self.current
        return {
            "download_bps": current.download_bps if current else None,
            "upload_bps": current.upload_bps if current else None,
            "today_download": self.today_download,
            "today_upload": self.today_upload,
            "peak_download": self.peak_download,
            "peak_upload": self.peak_upload,
            "interface": self.interface_name,
            "last_sample": self.last_sample,
            "per_device_available": bool(self.per_device),
            "per_process_available": bool(self._proc_bytes),
        }

    def week_month_totals(self, device_id: int | None = None) -> dict:
        now = now_ts()
        day = now - 86400
        week = now - 7 * 86400
        month = now - 30 * 86400
        sql = (
            "SELECT SUM(download_bytes), SUM(upload_bytes) FROM bandwidth_samples "
            "WHERE ts >= ? AND scope = 'interface'"
        )
        return {
            "day": self.db.query_one(sql, (day,)),
            "week": self.db.query_one(sql, (week,)),
            "month": self.db.query_one(sql, (month,)),
        }

    def record_device_traffic(self, device_id: int | None, download: int, upload: int,
                              source: str = "capture") -> None:
        if not device_id:
            return
        entry = self.per_device.setdefault(
            device_id, {"download_bytes": 0, "upload_bytes": 0, "download_bps": 0.0,
                        "upload_bps": 0.0, "source": source, "ts": now_ts()}
        )
        entry["download_bytes"] += download
        entry["upload_bytes"] += upload
        elapsed = max(1.0, now_ts() - entry["ts"])
        entry["download_bps"] = download / elapsed
        entry["upload_bps"] = upload / elapsed
        entry["ts"] = now_ts()
