"""Agent communication: enrollment, authentication, ingest and status.

The agent server is a small FastAPI application served by uvicorn in a
background thread, bound to the address the user configures (loopback by
default on first run, LAN address once they opt in).

Security model
--------------
* Enrollment requires a one-time **enrollment token** that only exists on the
  server and is shown to the user, who pastes it into the agent installer.
* The agent then exchanges the token for a **device secret** (32 random bytes)
  which it stores locally; every request is authenticated with an HMAC-SHA256
  signature over ``method path body timestamp nonce`` so the secret itself is
  never transmitted.
* Timestamps must be within 300 seconds (replay protection) and nonces are
  remembered per agent.
* Everything is stored locally; no data leaves the machine.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import socket
import threading
import time
from dataclasses import dataclass

from networksentinel.core.logging import get_logger
from networksentinel.core.util import now_ts

log = get_logger(__name__)

MAX_SKEW = 300


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


@dataclass
class EnrollmentToken:
    token: str
    created: float
    expires: float
    used: bool = False


class AgentServerService:
    def __init__(self, db, settings, inventory, explorer, dns_monitor, traffic,
                 bandwidth, alerts, security=None) -> None:
        self.db = db
        self.settings = settings
        self.inventory = inventory
        self.explorer = explorer
        self.dns = dns_monitor
        self.traffic = traffic
        self.bandwidth = bandwidth
        self.alerts = alerts
        self.security = security
        self._server = None
        self._thread: threading.Thread | None = None
        self._tokens: dict[str, EnrollmentToken] = {}
        self._nonces: dict[str, set] = {}
        self.running = False
        self.last_error: str | None = None
        self.pending_device_updates: dict[int, dict] = {}
        self.received_reports = 0

    # -- enrollment ------------------------------------------------------
    def create_token(self, ttl_minutes: int = 30) -> str:
        token = secrets.token_urlsafe(24)
        self._tokens[token] = EnrollmentToken(token, now_ts(), now_ts() + ttl_minutes * 60)
        self.db.audit("user", "agent.enrollment_token", "new", f"valid {ttl_minutes} min")
        return token

    def pending_tokens(self) -> list[dict]:
        now = now_ts()
        return [
            {"token": t.token, "created": t.created, "expires": t.expires,
             "valid": (not t.used) and t.expires > now}
            for t in self._tokens.values()
        ]

    def _consume_token(self, token: str) -> bool:
        entry = self._tokens.get(token)
        if entry is None or entry.used or entry.expires < now_ts():
            return False
        entry.used = True
        return True

    def enroll(self, payload: dict) -> dict:
        token = str(payload.get("enrollment_token") or "")
        if not self._consume_token(token):
            return {"ok": False, "error": "invalid or expired enrollment token"}
        agent_id = payload.get("agent_id") or secrets.token_hex(8)
        secret = secrets.token_urlsafe(32)
        existing = self.db.query_one("SELECT id FROM agents WHERE agent_id = ?", (agent_id,))
        values = (
            payload.get("name") or payload.get("hostname") or agent_id,
            payload.get("hostname"),
            payload.get("os_name"),
            payload.get("os_version"),
            payload.get("username"),
            payload.get("version"),
            json.dumps(payload.get("collection") or {}),
            _hash_secret(secret),
            now_ts(),
            "active",
        )
        if existing:
            self.db.execute(
                "UPDATE agents SET name=?, hostname=?, os_name=?, os_version=?, username=?, "
                "version=?, collection=?, token_hash=?, last_seen=?, status=? WHERE agent_id=?",
                values + (agent_id,),
            )
        else:
            self.db.execute(
                "INSERT INTO agents(agent_id, name, hostname, os_name, os_version, username, "
                "version, collection, token_hash, last_seen, status, enrolled_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (agent_id,) + values + (now_ts(),),
            )
        self.db.audit("agent", "agent.enrolled", agent_id, payload.get("hostname") or "")
        log.info("agent enrolled: %s (%s)", agent_id, payload.get("hostname"))
        return {
            "ok": True,
            "agent_id": agent_id,
            "agent_secret": secret,
            "interval": int(self.settings.get("agent_interval", 5)),
            "collection": {
                "dns": bool(self.settings.get("agent_collect_dns", True)),
                "traffic": bool(self.settings.get("agent_collect_traffic", True)),
                "processes": bool(self.settings.get("agent_collect_processes", True)),
            },
        }

    # -- authentication --------------------------------------------------
    def _agent_by_id(self, agent_id: str):
        return self.db.query_one("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))

    def verify(self, agent_id: str, secret: str, signature: str, timestamp: str,
               nonce: str, method: str, path: str, body: bytes) -> tuple[bool, str]:
        row = self._agent_by_id(agent_id)
        if row is None:
            return False, "unknown agent"
        if row["status"] not in ("active", "pending"):
            return False, "agent not active"
        if _hash_secret(secret) != row["token_hash"]:
            return False, "bad secret"
        try:
            ts = float(timestamp)
        except (TypeError, ValueError):
            return False, "bad timestamp"
        if abs(now_ts() - ts) > MAX_SKEW:
            return False, "timestamp skew too large"
        if not nonce or len(nonce) < 8:
            return False, "bad nonce"
        seen = self._nonces.setdefault(agent_id, set())
        if nonce in seen:
            return False, "replayed nonce"
        if len(seen) > 5000:
            seen.clear()
        seen.add(nonce)
        expected = hmac.new(
            secret.encode("utf-8"),
            f"{method}\n{path}\n{timestamp}\n{nonce}\n".encode("utf-8") + body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, signature or ""):
            return False, "bad signature"
        return True, "ok"

    # -- ingest ----------------------------------------------------------
    def ingest_report(self, agent_id: str, payload: dict, remote_addr: str = "") -> dict:
        row = self._agent_by_id(agent_id)
        if row is None:
            return {"ok": False, "error": "unknown agent"}
        now = now_ts()
        self.received_reports += 1
        device_id = row["device_id"]
        device_mac = payload.get("mac")
        if device_mac:
            device = self.inventory.by_mac(device_mac)
            if device is None:
                # The agent's computer is a device in the inventory: create it.
                observed = self.inventory.discovery.known.get(device_mac)
                if observed is None:
                    from networksentinel.services.discovery_service import ObservedDevice

                    observed = ObservedDevice(
                        mac=device_mac,
                        ip=payload.get("ip"),
                        hostname=payload.get("hostname"),
                        source="agent report",
                        first_seen=now,
                        last_seen=now,
                    )
                    observed.os_guess = payload.get("os_name")
                    observed.os_confidence = "Observed"
                    observed.device_type = "Windows computer" if "Windows" in (payload.get("os_name") or "") else "Linux computer"
                    observed.evidence.append("Reported by the managed agent")
                    self.inventory.discovery.known[device_mac] = observed
                self.inventory.sync()
                device = self.inventory.by_mac(device_mac)
            if device:
                device_id = device.id
                self.inventory.mark_agent(device.id, True)
        self.db.execute(
            "UPDATE agents SET last_seen = ?, status = 'active', device_id = ?, remote_addr = ?, "
            "hostname = COALESCE(?, hostname), os_name = COALESCE(?, os_name) WHERE agent_id = ?",
            (now, device_id, remote_addr, payload.get("hostname"), payload.get("os_name"), agent_id),
        )
        connections = payload.get("connections") or []
        if connections and device_id:
            self.explorer.ingest_agent_connections(device_id, connections)
        dns_entries = payload.get("dns") or []
        if dns_entries and device_id:
            for entry in dns_entries:
                self.dns.record(
                    entry.get("name"), entry.get("address") or payload.get("ip"),
                    qtype=str(entry.get("type") or "A"),
                    answers=entry.get("answers") or [], source="agent DNS cache",
                    device_id=device_id,
                )
            self.dns.flush()
        totals = payload.get("totals") or {}
        if totals and device_id:
            down = int(totals.get("download_bytes") or 0)
            up = int(totals.get("upload_bytes") or 0)
            self.bandwidth.record_device_traffic(device_id, down, up, source="agent")
            self.db.execute(
                "INSERT INTO bandwidth_samples(ts, device_id, scope, name, upload_bps, "
                "download_bps, upload_bytes, download_bytes, source) VALUES(?,?,?,?,?,?,?,?,?)",
                (now, device_id, "device", payload.get("hostname"), up, down, up, down, "agent"),
            )
        return {"ok": True, "next_interval": int(self.settings.get("agent_interval", 5))}

    # -- agent list ------------------------------------------------------
    def list_agents(self) -> list[dict]:
        offline_after = float(self.settings.get("agent_offline_after", 90))
        now = now_ts()
        out = []
        for row in self.db.query("SELECT * FROM agents ORDER BY last_seen DESC"):
            data = dict(row)
            data.pop("token_hash", None)
            last = data.get("last_seen") or 0
            data["status"] = "offline" if (now - last) > offline_after else "active"
            data["seconds_since"] = int(now - last) if last else None
            out.append(data)
        return out

    def remove_agent(self, agent_id: str) -> None:
        self.db.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
        self.db.audit("user", "agent.remove", agent_id)

    def check_offline(self) -> list[dict]:
        offline = [a for a in self.list_agents() if a["status"] == "offline"]
        if self.alerts:
            for agent in offline:
                self.alerts.agent_status(agent)
        return offline

    # -- HTTP server -----------------------------------------------------
    def _build_app(self):
        from fastapi import FastAPI, Header, HTTPException, Request
        from fastapi.responses import JSONResponse

        app = FastAPI(title="Network Sentinel Agent API", docs_url=None, redoc_url=None)

        @app.get("/api/v1/health")
        def health():
            return {"ok": True, "service": "network-sentinel", "version": 1}

        @app.post("/api/v1/enroll")
        async def enroll(request: Request):
            payload = await request.json()
            result = self.enroll(payload)
            return JSONResponse(result, status_code=200 if result.get("ok") else 403)

        @app.post("/api/v1/report")
        async def report(
            request: Request,
            x_agent_id: str = Header(default=""),
            x_agent_secret: str = Header(default=""),
            x_agent_signature: str = Header(default=""),
            x_agent_timestamp: str = Header(default=""),
            x_agent_nonce: str = Header(default=""),
        ):
            body = await request.body()
            ok, reason = self.verify(
                x_agent_id, x_agent_secret, x_agent_signature, x_agent_timestamp,
                x_agent_nonce, "POST", "/api/v1/report", body,
            )
            if not ok:
                raise HTTPException(status_code=401, detail=reason)
            try:
                payload = json.loads(body or b"{}")
            except ValueError:
                raise HTTPException(status_code=400, detail="invalid JSON")
            return self.ingest_report(x_agent_id, payload, request.client.host if request.client else "")

        @app.get("/api/v1/config")
        def config():
            return {
                "interval": int(self.settings.get("agent_interval", 5)),
                "collect_dns": bool(self.settings.get("agent_collect_dns", True)),
                "collect_traffic": bool(self.settings.get("agent_collect_traffic", True)),
                "collect_processes": bool(self.settings.get("agent_collect_processes", True)),
            }

        return app

    def start(self) -> dict:
        if self.running:
            return {"running": True, "port": self.settings.get("agent_server_port")}
        host = self.settings.get("agent_server_host", "0.0.0.0")
        port = int(self.settings.get("agent_server_port", 8765))
        try:
            import uvicorn

            app = self._build_app()
            config = uvicorn.Config(app, host=host, port=port, log_level="warning",
                                    access_log=False, lifespan="off")
            self._server = uvicorn.Server(config)
            self._thread = threading.Thread(target=self._server.run, name="agent-server", daemon=True)
            self._thread.start()
            self.running = True
            self.last_error = None
            time.sleep(0.4)
            log.info("agent server listening on %s:%s", host, port)
            return {"running": True, "host": host, "port": port}
        except Exception as exc:
            self.running = False
            self.last_error = str(exc)
            log.warning("agent server failed: %s", exc)
            return {"running": False, "error": str(exc)}

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
            if self._thread:
                self._thread.join(timeout=3)
        self.running = False
        self._server = None

    def addresses(self) -> list[str]:
        """Addresses an agent on the LAN could use to reach this server."""
        out = []
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                addr = info[4][0]
                if addr not in out and not addr.startswith("127."):
                    out.append(addr)
        except OSError:
            pass
        return out

    def status(self) -> dict:
        return {
            "running": self.running,
            "host": self.settings.get("agent_server_host"),
            "port": int(self.settings.get("agent_server_port", 8765)),
            "agents": len(self.list_agents()),
            "reports": self.received_reports,
            "error": self.last_error,
            "addresses": self.addresses(),
        }
