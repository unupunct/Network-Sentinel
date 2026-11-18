"""Network Sentinel agent: optional, explicit companion for computers you administer.

What it does
------------
Reads the local socket table and byte counters, signs each report with the
secret issued at enrollment and posts it to your Network Sentinel server.  It
sends process names, addresses, ports, states and byte counts.  It never sends
payloads, keystrokes, clipboard, files, screenshots, browser history or
credentials, and it starts nothing on its own.

Usage
-----
    python -m networksentinel.agent --server http://192.168.1.9:8765 --token <TOKEN>

Uninstall: stop the process (Ctrl+C) and delete the folder.  Nothing is
registered to start at boot.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import platform
import socket
import sys
import time
import urllib.error
import urllib.request

try:  # psutil is bundled with the server; the agent can also run without it
    import psutil
except Exception:  # pragma: no cover
    psutil = None

APP_VERSION = "1.0.0"


def _sign(secret: str, timestamp: str, body: bytes) -> str:
    return hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def _post(url: str, payload: dict, headers: dict[str, str] | None = None,
          timeout: float = 10.0) -> dict:
    body = json.dumps(payload).encode()
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read() or b"{}")


def collect_connections() -> list[dict]:
    """Sockets owned by this computer, with the process that owns each."""
    if psutil is None:
        return []
    out: list[dict] = []
    try:
        table = psutil.net_connections(kind="inet")
    except Exception:
        return []
    for conn in table:
        if not conn.raddr:
            continue
        name = None
        try:
            if conn.pid:
                name = psutil.Process(conn.pid).name()
        except Exception:
            name = None
        out.append({
            "local_ip": conn.laddr[0] if conn.laddr else None,
            "local_port": conn.laddr[1] if conn.laddr else None,
            "remote_ip": conn.raddr[0],
            "remote_port": conn.raddr[1],
            "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
            "state": str(conn.status or ""),
            "application": name,
            "pid": conn.pid,
            "source": "agent socket table",
        })
    return out


def collect_traffic() -> list[dict]:
    """Per-interface counters and per-process counters since the last report."""
    counters = []
    if psutil is None:
        return counters
    try:
        per_nic = psutil.net_io_counters(pernic=True)
    except Exception:
        per_nic = {}
    for name, io in per_nic.items():
        counters.append({
            "scope": "interface", "name": name,
            "bytes_recv": io.bytes_recv, "bytes_sent": io.bytes_sent,
            "packets_recv": io.packets_recv, "packets_sent": io.packets_sent,
        })
    return counters


def process_counters(state: dict) -> list[dict]:
    """Per-process byte counters (Windows only; the OS exposes them there)."""
    if psutil is None or not sys.platform.startswith("win"):
        return []
    out = []
    seen = set()
    for proc in psutil.process_iter(["pid", "name", "io_counters"]):
        try:
            io = proc.info.get("io_counters")
            if not io:
                continue
            pid = proc.info["pid"]
            previous = state.get(pid)
            state[pid] = (io.read_bytes, io.write_bytes)
            if previous is None:
                continue
            out.append({
                "pid": pid,
                "name": proc.info.get("name"),
                "read_bytes": max(0, io.read_bytes - previous[0]),
                "write_bytes": max(0, io.write_bytes - previous[1]),
            })
            seen.add(pid)
        except Exception:
            continue
    for pid in list(state):
        if pid not in seen and pid not in {p["pid"] for p in out}:
            state.pop(pid, None)
    return out


def enroll(server: str, token: str) -> dict:
    payload = {
        "token": token,
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "os": platform.system(),
        "user": getpass.getuser(),
        "version": APP_VERSION,
    }
    return _post(server.rstrip("/") + "/api/agent/enroll", payload)


def run(server: str, token: str | None, interval: int, once: bool, verbose: bool) -> int:
    from networksentinel.core.paths import agent_dir

    store = agent_dir() / "credentials.json"
    creds: dict | None = None
    if store.exists():
        try:
            creds = json.loads(store.read_text(encoding="utf-8"))
        except Exception:
            creds = None
    if token:
        print(f"Enrolling with {server} …")
        result = enroll(server, token)
        if not result.get("agent_id") or not result.get("secret"):
            print(f"Enrollment failed: {result}", file=sys.stderr)
            return 2
        creds = {
            "server": server.rstrip("/"),
            "agent_id": result["agent_id"],
            "secret": result["secret"],
            "hostname": socket.gethostname(),
        }
        store.write_text(json.dumps(creds), encoding="utf-8")
        print(f"Enrolled as agent {result['agent_id']} (credentials in {store})")
    if not creds:
        print("No enrollment token given and no saved credentials. "
              "Run once with --token <TOKEN> from the Agents page.", file=sys.stderr)
        return 2

    state: dict = {}
    proc_state: dict = {}
    while True:
        payload = {
            "agent_id": creds["agent_id"],
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "os": platform.system(),
            "connections": collect_connections(),
            "traffic": collect_traffic(),
            "processes": process_counters(proc_state),
            "timestamp": time.time(),
        }
        body = json.dumps(payload, sort_keys=True).encode()
        timestamp = str(int(time.time()))
        headers = {
            "X-Agent-Id": creds["agent_id"],
            "X-Timestamp": timestamp,
            "X-Signature": _sign(creds["secret"], timestamp, body),
            "Content-Type": "application/json",
        }
        url = creds["server"] + "/api/agent/report"
        try:
            request = urllib.request.Request(url, data=body, method="POST", headers=headers)
            with urllib.request.urlopen(request, timeout=15) as response:
                response.read()
            if verbose:
                print(f"report sent: {len(payload['connections'])} connections")
        except urllib.error.HTTPError as exc:
            print(f"server rejected the report: HTTP {exc.code} {exc.reason}", file=sys.stderr)
            if exc.code in (401, 403):
                print("The agent was removed or its secret is wrong; enroll again.", file=sys.stderr)
                return 3
        except Exception as exc:
            print(f"could not reach {url}: {exc}", file=sys.stderr)
        if once:
            return 0
        time.sleep(max(2, interval))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Network Sentinel agent")
    parser.add_argument("--server", default=None, help="http://host:port of Network Sentinel")
    parser.add_argument("--token", default=None, help="enrollment token from the Agents page")
    parser.add_argument("--interval", type=int, default=5, help="seconds between reports")
    parser.add_argument("--once", action="store_true", help="send one report and exit")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    server = args.server
    if not server:
        print("--server is required the first time", file=sys.stderr)
        return 2
    return run(server, args.token, args.interval, args.once, args.verbose)


if __name__ == "__main__":
    sys.exit(main())
