"""SQLite storage layer.

Design notes
------------
* One connection per thread (``threading.local``) with WAL journalling so the
  GUI thread and the background workers can read and write concurrently.
* Traffic records are written in batches and rotated by the retention policy.
* All timestamps are Unix epoch seconds (float), rendered in local time by the
  UI layer only.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable, Sequence

from networksentinel import SCHEMA_VERSION
from networksentinel.core.logging import get_logger
from networksentinel.core.paths import database_path

log = get_logger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Networks / capture sessions ------------------------------------------------
CREATE TABLE IF NOT EXISTS network_interfaces (
    interface TEXT PRIMARY KEY,
    description TEXT,
    mac TEXT,
    ipv4 TEXT,
    ipv6 TEXT,
    netmask TEXT,
    gateway TEXT,
    dns_servers TEXT,
    is_up INTEGER DEFAULT 0,
    is_default INTEGER DEFAULT 0,
    last_seen REAL
);

-- Devices --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT UNIQUE,
    ip TEXT,
    hostname TEXT,
    vendor TEXT,
    os_guess TEXT,
    os_confidence TEXT DEFAULT 'Unknown',
    device_type TEXT DEFAULT 'Unknown',
    custom_name TEXT,
    custom_category TEXT,
    description TEXT,
    trusted INTEGER DEFAULT 0,
    is_self INTEGER DEFAULT 0,
    is_gateway INTEGER DEFAULT 0,
    is_agent INTEGER DEFAULT 0,
    first_seen REAL,
    last_seen REAL,
    online INTEGER DEFAULT 0,
    source TEXT DEFAULT 'arp',
    evidence TEXT,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);

CREATE TABLE IF NOT EXISTS device_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    first_seen REAL,
    last_seen REAL,
    UNIQUE(device_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_device_ips_ip ON device_ips(ip);

-- DNS ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dns_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    device_id INTEGER,
    client_ip TEXT,
    domain TEXT,
    qtype TEXT,
    server TEXT,
    answer TEXT,
    source TEXT,
    category TEXT
);
CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_queries(ts);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_queries(domain);
CREATE INDEX IF NOT EXISTS idx_dns_device ON dns_queries(device_id);

-- Connections ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conn_key TEXT UNIQUE,
    device_id INTEGER,
    device_mac TEXT,
    application TEXT,
    pid INTEGER,
    local_ip TEXT,
    local_port INTEGER,
    remote_ip TEXT,
    remote_port INTEGER,
    domain TEXT,
    protocol TEXT,
    state TEXT,
    first_seen REAL,
    last_seen REAL,
    upload_bytes INTEGER DEFAULT 0,
    download_bytes INTEGER DEFAULT 0,
    source TEXT,
    category TEXT
);
CREATE INDEX IF NOT EXISTS idx_conn_device ON connections(device_id);
CREATE INDEX IF NOT EXISTS idx_conn_remote ON connections(remote_ip);
CREATE INDEX IF NOT EXISTS idx_conn_domain ON connections(domain);
CREATE INDEX IF NOT EXISTS idx_conn_last_seen ON connections(last_seen);

-- Traffic metadata -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    device_id INTEGER,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    length INTEGER,
    direction TEXT,
    app TEXT,
    state TEXT,
    info TEXT,
    source TEXT
);
CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic(ts);
CREATE INDEX IF NOT EXISTS idx_traffic_proto ON traffic(protocol);
CREATE INDEX IF NOT EXISTS idx_traffic_device ON traffic(device_id);

-- Bandwidth samples (per device and per application) -------------------------
CREATE TABLE IF NOT EXISTS bandwidth_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    device_id INTEGER,
    scope TEXT NOT NULL,
    name TEXT,
    upload_bps REAL DEFAULT 0,
    download_bps REAL DEFAULT 0,
    upload_bytes INTEGER DEFAULT 0,
    download_bytes INTEGER DEFAULT 0,
    source TEXT
);
CREATE INDEX IF NOT EXISTS idx_bw_ts ON bandwidth_samples(ts);
CREATE INDEX IF NOT EXISTS idx_bw_device ON bandwidth_samples(device_id, ts);

-- Security findings ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT,
    device_id INTEGER,
    title TEXT,
    evidence TEXT,
    explanation TEXT,
    impact TEXT,
    recommendation TEXT,
    dedupe_key TEXT,
    acknowledged INTEGER DEFAULT 0,
    source TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(ts);
CREATE INDEX IF NOT EXISTS idx_findings_dedupe ON findings(dedupe_key);

-- Alerts ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT,
    severity TEXT,
    title TEXT,
    body TEXT,
    device_id INTEGER,
    read INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

-- Device timeline events -----------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    device_id INTEGER,
    kind TEXT,
    title TEXT,
    detail TEXT,
    certainty TEXT DEFAULT 'observed',
    source TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id, ts);

-- Managed agents -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT UNIQUE,
    name TEXT,
    hostname TEXT,
    os_name TEXT,
    os_version TEXT,
    username TEXT,
    device_id INTEGER,
    token_hash TEXT,
    enrolled_at REAL,
    last_seen REAL,
    status TEXT DEFAULT 'pending',
    version TEXT,
    collection TEXT,
    remote_addr TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT,
    action TEXT,
    target TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""


class Database:
    """Thread-safe SQLite wrapper."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else database_path()
        self._local = threading.local()
        self._lock = threading.Lock()
        self._init_schema()

    # -- connection management ------------------------------------------
    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self.path), timeout=20.0, check_same_thread=False
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=20000")
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = sqlite3.connect(str(self.path), timeout=20.0)
            try:
                conn.executescript(SCHEMA)
                conn.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                    (str(SCHEMA_VERSION),),
                )
                conn.commit()
            finally:
                conn.close()
        log.info("Database ready at %s", self.path)

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # -- generic helpers -------------------------------------------------
    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        cur = self.conn.execute(sql, params)
        self.conn.commit()
        return cur

    def executemany(self, sql: str, rows: Iterable[Sequence[Any]]) -> None:
        with self._lock:
            self.conn.executemany(sql, rows)
            self.conn.commit()

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        return list(self.conn.execute(sql, params).fetchall())

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()

    def scalar(self, sql: str, params: Sequence[Any] = (), default: Any = 0) -> Any:
        row = self.conn.execute(sql, params).fetchone()
        if row is None or row[0] is None:
            return default
        return row[0]

    # -- settings --------------------------------------------------------
    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self.query_one("SELECT value FROM settings WHERE key = ?", (key,))
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except (ValueError, TypeError):
            return row["value"]

    def set_setting(self, key: str, value: Any) -> None:
        self.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value)),
        )

    def all_settings(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for row in self.query("SELECT key, value FROM settings"):
            try:
                out[row["key"]] = json.loads(row["value"])
            except (ValueError, TypeError):
                out[row["key"]] = row["value"]
        return out

    # -- audit -----------------------------------------------------------
    def audit(self, actor: str, action: str, target: str = "", detail: str = "") -> None:
        from networksentinel.core.util import now_ts

        self.execute(
            "INSERT INTO audit_log(ts, actor, action, target, detail) VALUES(?,?,?,?,?)",
            (now_ts(), actor, action, target, detail),
        )

    # -- retention -------------------------------------------------------
    def purge_older_than(self, table: str, column: str, cutoff: float) -> int:
        allowed = {
            "traffic", "dns_queries", "connections", "bandwidth_samples",
            "findings", "alerts", "events", "audit_log",
        }
        if table not in allowed:
            raise ValueError(f"refusing to purge unknown table {table}")
        cur = self.execute(f"DELETE FROM {table} WHERE {column} < ?", (cutoff,))
        return cur.rowcount or 0

    def wipe_activity(self) -> None:
        """Delete all collected activity but keep devices and settings."""
        for table in (
            "traffic", "dns_queries", "connections", "bandwidth_samples",
            "findings", "alerts", "events",
        ):
            self.execute(f"DELETE FROM {table}")

    def wipe_all(self) -> None:
        """Delete everything collected, including the device inventory."""
        self.wipe_activity()
        self.execute("DELETE FROM device_ips")
        self.execute("DELETE FROM devices")

    def size_bytes(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    def vacuum(self) -> None:
        self.conn.execute("VACUUM")
