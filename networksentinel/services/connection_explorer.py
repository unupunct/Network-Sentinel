"""Connection explorer: connection history, enrichment and aggregation."""

from __future__ import annotations

import threading

from networksentinel.core.logging import get_logger
from networksentinel.core.util import is_private_ip, is_public_ip, now_ts

log = get_logger(__name__)

APP_CATEGORIES = [
    ("Web browsers", ("chrome", "firefox", "msedge", "edge", "opera", "brave", "vivaldi",
                      "safari", "librewolf", "chromium", "waterfox")),
    ("Steam", ("steam", "steamwebhelper", "steamservice")),
    ("Discord", ("discord", "discordptb", "discordcanary")),
    ("Spotify", ("spotify",)),
    ("Windows Update", ("tiworker", "wuauclt", "usoclient", "trustedinstaller",
                        "windowsupdate", "svchost_deliveryoptimization")),
    ("Cloud storage", ("dropbox", "onedrive", "googledrivesync", "google drive",
                       "megasync", "pcloud", "nextcloud", "owncloud", "backblaze")),
    ("Email clients", ("thunderbird", "outlook", "mailspring", "emclient", "evolution")),
    ("Game launchers", ("epicgameslauncher", "battle.net", "galaxyclient", "origin",
                        "eadesktop", "uplay", "ubisoft", "riotclientservices",
                        "goggalaxy", "minecraft", "roblox", "rockstarlauncher")),
    ("Remote access", ("teamviewer", "anydesk", "rustdesk", "vnc", "mstsc", "logmein",
                       "screenconnect", "splashtop", "parsec", "gotohttp")),
    ("Development tools", ("code", "devenv", "jetbrains", "idea64", "pycharm64",
                           "webstorm64", "git", "docker", "node", "python", "pythonw",
                           "npm", "cargo", "rustc", "go", "dotnet", "java")),
    ("Media players", ("vlc", "mpc-hc", "mpv", "wmplayer", "foobar2000", "itunes")),
    ("Communication", ("zoom", "teams", "slack", "skype", "telegram", "whatsapp",
                       "signal", "webex", "element", "matrix")),
    ("VPN / tunnel", ("openvpn", "wireguard", "tailscale", "zerotier", "nordvpn",
                      "expressvpn", "surfshark", "protonvpn", "wg", "softether")),
    ("System services", ("svchost", "system", "lsass", "services", "spoolsv",
                         "dnsmasq", "systemd", "avahi-daemon", "NetworkManager",
                         "explorer", "searchhost")),
    ("Security software", ("msmpeng", "nissrv", "avast", "avg", "kaspersky",
                           "bitdefender", "malwarebytes", "eset", "defender")),
]


def app_category(app: str | None) -> str:
    if not app:
        return "Unattributed"
    name = app.lower()
    for category, tokens in APP_CATEGORIES:
        for token in tokens:
            if token in name:
                return category
    return "Other"


class ConnectionExplorerService:
    """Tracks connections seen on this computer (and reported by agents)."""

    def __init__(self, db, settings, connections, inventory, dns, resolver) -> None:
        self.db = db
        self.settings = settings
        self.connections = connections
        self.inventory = inventory
        self.dns = dns
        self.resolver = resolver
        self._lock = threading.Lock()
        self._seen: dict[str, dict] = {}
        self._last_remote_bytes: dict[str, tuple[int, int]] = {}
        self.last_poll: float = 0.0
        self.new_connections = 0
        self._domain_cache: dict[str, str | None] = {}
        self.enrich_budget = 12          # reverse DNS lookups per poll
        self.listen_snapshot: list[dict] = []

    # -- local poll ------------------------------------------------------
    def poll_local(self, interface_ip: str | None = None) -> list[dict]:
        """Read this computer's sockets and store new/changed connections.

        Reverse-DNS enrichment runs in the background: a slow answer never
        delays the monitoring cycle, it just fills the domain column later.
        """
        observed = []
        self._lookup_queue: list[str] = []
        budget = self.enrich_budget
        now = now_ts()
        for record in self.connections.connections():
            if record.protocol == "TCP" and record.state not in ("ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"):
                continue
            if record.protocol == "UDP" and not record.remote_ip:
                continue
            remote = record.remote_ip
            if not remote or remote.startswith("0.") or remote == "::":
                continue
            is_local = is_private_ip(remote)
            if not is_local and not is_public_ip(remote):
                continue
            key = record.key
            domain = None if is_local else self._domain_for(remote, False)
            if domain is None and not is_local:
                self._lookup_queue.append(remote)
            if domain and not self._domain_cache.get(remote):
                budget -= 1
            device = self.inventory.by_ip(record.local_ip)
            entry = {
                "conn_key": key,
                "device_id": device.id if device else None,
                "device_mac": device.mac if device else None,
                "application": record.process,
                "pid": record.pid,
                "local_ip": record.local_ip,
                "local_port": record.local_port,
                "remote_ip": remote,
                "remote_port": record.remote_port,
                "domain": domain,
                "protocol": record.protocol,
                "state": record.state,
                "first_seen": now,
                "last_seen": now,
                "upload_bytes": 0,
                "download_bytes": 0,
                "source": "this computer (OS socket table)",
                "category": app_category(record.process),
            }
            observed.append(entry)
        self._store(observed)
        self.listen_snapshot = self.connections.listening_services()
        self.last_poll = now_ts()
        self._spawn_lookups()
        return observed

    def _spawn_lookups(self) -> None:
        pending = [ip for ip in dict.fromkeys(self._lookup_queue) if ip not in self._domain_cache][:20]
        if not pending:
            return

        def worker() -> None:
            for ip in pending:
                try:
                    name = self.resolver.reverse(ip, timeout=1.5)
                except Exception:
                    name = None
                self._domain_cache[ip] = name or ""

        threading.Thread(target=worker, name="reverse-dns", daemon=True).start()

    def _domain_for(self, ip: str, allow_lookup: bool) -> str | None:
        cached = self._domain_cache.get(ip)
        if cached:
            return cached
        known = self.resolver.known_domain(ip)
        if known:
            self._domain_cache[ip] = known
            return known
        if allow_lookup:
            name = self.resolver.reverse(ip, timeout=1.0)
            if name:
                self._domain_cache[ip] = name
                return name
        return None

    def ingest_agent_connections(self, device_id: int, connections: list[dict],
                                 source: str = "agent (kernel counters)") -> int:
        now = now_ts()
        entries = []
        for item in connections:
            remote = item.get("remote_ip")
            if not remote:
                continue
            key = (
                f"{item.get('protocol', 'TCP')}|{item.get('local_ip', '')}:{item.get('local_port', 0)}|"
                f"{remote}:{item.get('remote_port', 0)}"
            )
            domain = item.get("domain") or self._domain_for(remote, True)
            app = item.get("application") or item.get("process")
            entries.append(
                {
                    "conn_key": key,
                    "device_id": device_id,
                    "device_mac": item.get("device_mac"),
                    "application": app,
                    "pid": item.get("pid"),
                    "local_ip": item.get("local_ip"),
                    "local_port": item.get("local_port"),
                    "remote_ip": remote,
                    "remote_port": item.get("remote_port"),
                    "domain": domain,
                    "protocol": item.get("protocol", "TCP"),
                    "state": item.get("state", "ESTABLISHED"),
                    "first_seen": now,
                    "last_seen": now,
                    "upload_bytes": int(item.get("upload_bytes") or 0),
                    "download_bytes": int(item.get("download_bytes") or 0),
                    "source": source,
                    "category": app_category(app),
                }
            )
        self._store(entries, allow_counters=True)
        return len(entries)

    # -- persistence -----------------------------------------------------
    def _store(self, entries: list[dict], allow_counters: bool = False) -> None:
        if not entries:
            return
        new_keys = []
        with self._lock:
            for entry in entries:
                key = entry["conn_key"]
                existing = self.db.query_one(
                    "SELECT id, first_seen, upload_bytes, download_bytes FROM connections "
                    "WHERE conn_key = ?", (key,)
                )
                if existing is None:
                    self.db.execute(
                        "INSERT INTO connections(conn_key, device_id, device_mac, application, pid, "
                        "local_ip, local_port, remote_ip, remote_port, domain, protocol, state, "
                        "first_seen, last_seen, upload_bytes, download_bytes, source, category) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            key, entry["device_id"], entry["device_mac"], entry["application"],
                            entry["pid"], entry["local_ip"], entry["local_port"],
                            entry["remote_ip"], entry["remote_port"], entry["domain"],
                            entry["protocol"], entry["state"], entry["first_seen"],
                            entry["last_seen"], entry["upload_bytes"], entry["download_bytes"],
                            entry["source"], entry["category"],
                        ),
                    )
                    new_keys.append(key)
                else:
                    up = max(int(existing["upload_bytes"] or 0), entry["upload_bytes"]) if allow_counters else (existing["upload_bytes"] or 0)
                    down = max(int(existing["download_bytes"] or 0), entry["download_bytes"]) if allow_counters else (existing["download_bytes"] or 0)
                    self.db.execute(
                        "UPDATE connections SET last_seen = ?, state = ?, "
                        "domain = COALESCE(?, domain), application = COALESCE(?, application), "
                        "pid = COALESCE(?, pid), upload_bytes = ?, download_bytes = ?, "
                        "category = COALESCE(?, category) WHERE id = ?",
                        (entry["last_seen"], entry["state"], entry["domain"], entry["application"],
                         entry["pid"], up, down, entry["category"], existing["id"]),
                    )
        self.new_connections += len(new_keys)

    # -- queries ---------------------------------------------------------
    def query(self, since: float = 0.0, device_id: int | None = None,
              application: str | None = None, protocol: str | None = None,
              search: str | None = None, domain: str | None = None,
              public_only: bool = False, limit: int = 1000,
              order: str = "last_seen") -> list[dict]:
        sql = ["SELECT c.*, d.mac AS dev_mac, d.hostname AS dev_host, d.ip AS dev_ip,",
               "d.custom_name AS dev_name FROM connections c LEFT JOIN devices d ON d.id = c.device_id",
               "WHERE c.last_seen >= ?"]
        params: list = [since]
        if device_id:
            sql.append("AND c.device_id = ?")
            params.append(device_id)
        if application:
            sql.append("AND c.application LIKE ?")
            params.append(f"%{application}%")
        if protocol:
            sql.append("AND c.protocol = ?")
            params.append(protocol)
        if domain:
            sql.append("AND c.domain LIKE ?")
            params.append(f"%{domain}%")
        if search:
            sql.append("AND (c.remote_ip LIKE ? OR c.domain LIKE ? OR c.application LIKE ? "
                       "OR c.local_ip LIKE ?)")
            params.extend([f"%{search}%"] * 4)
        order_sql = {
            "last_seen": "c.last_seen DESC",
            "traffic": "(c.download_bytes + c.upload_bytes) DESC",
            "first_seen": "c.first_seen DESC",
            "remote_ip": "c.remote_ip ASC",
        }.get(order, "c.last_seen DESC")
        sql.append(f"ORDER BY {order_sql} LIMIT ?")
        params.append(limit)
        rows = [dict(r) for r in self.db.query(" ".join(sql), params)]
        if public_only:
            rows = [r for r in rows if is_public_ip(r.get("remote_ip"))]
        return rows

    def stats(self) -> dict:
        now = now_ts()
        return {
            "total": self.db.scalar("SELECT COUNT(*) FROM connections"),
            "active": self.db.scalar(
                "SELECT COUNT(*) FROM connections WHERE last_seen >= ?", (now - 120,)
            ),
            "last_hour": self.db.scalar(
                "SELECT COUNT(*) FROM connections WHERE first_seen >= ?", (now - 3600,)
            ),
            "new_connections": self.new_connections,
            "last_poll": self.last_poll,
            "error": self.connections.last_error,
        }

    def applications(self, since: float = 0.0, device_id: int | None = None,
                     search: str | None = None) -> list[dict]:
        sql = [
            "SELECT COALESCE(c.application, 'Unattributed') AS application,",
            "COALESCE(c.category, 'Other') AS category, COUNT(*) AS connections,",
            "SUM(c.upload_bytes) AS upload, SUM(c.download_bytes) AS download,",
            "MAX(c.last_seen) AS last_seen, COUNT(DISTINCT c.remote_ip) AS remotes,",
            "GROUP_CONCAT(DISTINCT c.device_id) AS devices",
            "FROM connections c WHERE c.last_seen >= ?",
        ]
        params: list = [since]
        if device_id:
            sql.append("AND c.device_id = ?")
            params.append(device_id)
        if search:
            sql.append("AND c.application LIKE ?")
            params.append(f"%{search}%")
        sql.append("GROUP BY application ORDER BY connections DESC")
        return [dict(r) for r in self.db.query(" ".join(sql), params)]

    def domains(self, since: float = 0.0, device_id: int | None = None,
                limit: int = 300) -> list[dict]:
        sql = [
            "SELECT c.domain, COUNT(*) AS connections, SUM(c.upload_bytes) AS upload,",
            "SUM(c.download_bytes) AS download, MIN(c.first_seen) AS first_seen,",
            "MAX(c.last_seen) AS last_seen, GROUP_CONCAT(DISTINCT c.remote_ip) AS ips,",
            "GROUP_CONCAT(DISTINCT c.device_id) AS devices",
            "FROM connections c WHERE c.last_seen >= ? AND c.domain IS NOT NULL",
        ]
        params: list = [since]
        if device_id:
            sql.append("AND c.device_id = ?")
            params.append(device_id)
        sql.append("GROUP BY c.domain ORDER BY (SUM(c.download_bytes) + SUM(c.upload_bytes)) DESC LIMIT ?")
        params.append(limit)
        return [dict(r) for r in self.db.query(" ".join(sql), params)]

    def detail(self, connection_id: int) -> dict | None:
        row = self.db.query_one(
            "SELECT c.*, d.mac AS dev_mac, d.hostname AS dev_host, d.custom_name AS dev_name "
            "FROM connections c LEFT JOIN devices d ON d.id = c.device_id WHERE c.id = ?",
            (connection_id,),
        )
        return dict(row) if row else None

    def export_rows(self, since: float = 0.0) -> list[dict]:
        return self.query(since=since, limit=20000)
