"""Connection and per-process telemetry.

Windows
-------
Reads the TCP/UDP tables with ``GetExtendedTcpTable`` / ``GetExtendedUdpTable``
(iphlpapi) and attributes each socket to a process with
``GetExtendedTcpTable(..., TCP_TABLE_OWNER_MODULE_ALL)``.  Per-process byte
counters come from ``GetPerTcpConnectionEStats`` (real kernel counters) and,
when Windows has no per-connection counters, from ``psutil`` process I/O
counters labelled as such.

Linux
-----
Parses ``/proc/net/tcp``, ``/proc/net/tcp6``, ``/proc/net/udp`` and maps the
inode to a process through ``/proc/<pid>/fd``.  Per-process traffic comes from
``/proc/<pid>/net/dev`` counters (``psutil``).

Nothing here reads packet payloads, keystrokes, credentials or browser data:
only socket tuples, process names and byte counters.
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import time
from dataclasses import dataclass, field

from networksentinel.core.logging import get_logger

log = get_logger(__name__)

TCP_ESTABLISHED = 5

_TCP_STATES = {
    1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1", 5: "FIN_WAIT2",
    6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN",
    11: "CLOSING",
}

# MIB_TCP_STATE numbers (Windows)
_WIN_TCP_STATES = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED",
    6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
    11: "TIME_WAIT", 12: "DELETE_TCB",
}

WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 135: "MS-RPC",
    137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP-submission", 631: "IPP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 1900: "SSDP", 3306: "MySQL", 3389: "RDP",
    5060: "SIP", 5222: "XMPP", 5228: "Google Play", 5353: "mDNS", 5432: "PostgreSQL",
    5900: "VNC", 5938: "TeamViewer", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    8883: "MQTT-TLS", 9050: "Tor SOCKS", 9090: "Prometheus", 27015: "Steam",
    3478: "STUN", 3479: "STUN", 3544: "Teredo", 19302: "Google Meet",
}


@dataclass
class SocketRecord:
    protocol: str          # TCP / UDP
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    pid: int | None = None
    process: str | None = None
    exe: str | None = None
    created: float | None = None

    @property
    def key(self) -> str:
        return (
            f"{self.protocol}|{self.local_ip}:{self.local_port}|"
            f"{self.remote_ip}:{self.remote_port}"
        )

    @property
    def service(self) -> str:
        return WELL_KNOWN_PORTS.get(self.remote_port) or WELL_KNOWN_PORTS.get(self.local_port) or ""


@dataclass
class ProcessTraffic:
    pid: int
    name: str
    exe: str | None
    read_bytes: int
    write_bytes: int
    username: str | None = None


# ---------------------------------------------------------------------------
# Windows implementation
# ---------------------------------------------------------------------------

def _windows_connections() -> list[SocketRecord]:
    import ctypes
    from ctypes import wintypes

    iphlpapi = ctypes.WinDLL("iphlpapi.dll")
    AF_INET = 2
    AF_INET6 = 23
    TCP_TABLE_OWNER_PID_ALL = 5
    UDP_TABLE_OWNER_PID = 1
    ERROR_INSUFFICIENT_BUFFER = 122

    records: list[SocketRecord] = []

    class MIB_TCPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwState", wintypes.DWORD),
            ("dwLocalAddr", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwRemoteAddr", wintypes.DWORD),
            ("dwRemotePort", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD),
        ]

    class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("ucLocalAddr", ctypes.c_ubyte * 16),
            ("dwLocalScopeId", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("ucRemoteAddr", ctypes.c_ubyte * 16),
            ("dwRemoteScopeId", wintypes.DWORD),
            ("dwRemotePort", wintypes.DWORD),
            ("dwState", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD),
        ]

    class MIB_UDPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwLocalAddr", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD),
        ]

    def _ipv4(addr: int) -> str:
        return socket.inet_ntoa(struct.pack("<L", addr))

    def _port(raw: int) -> int:
        return socket.ntohs(raw & 0xFFFF)

    def _table(table_class: int, af: int) -> bytes:
        size = wintypes.DWORD(0)
        fn = iphlpapi.GetExtendedTcpTable
        fn(None, ctypes.byref(size), False, af, table_class, 0)
        buf = ctypes.create_string_buffer(size.value)
        ret = fn(buf, ctypes.byref(size), False, af, table_class, 0)
        if ret not in (0, ERROR_INSUFFICIENT_BUFFER):
            return b""
        return buf.raw[: size.value]

    for af in (AF_INET, AF_INET6):
        raw = _table(TCP_TABLE_OWNER_PID_ALL, af)
        if not raw:
            continue
        count = struct.unpack_from("<I", raw, 0)[0]
        offset = 4
        if af == AF_INET:
            row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
            for _ in range(count):
                row = MIB_TCPROW_OWNER_PID.from_buffer_copy(raw[offset: offset + row_size])
                offset += row_size
                records.append(
                    SocketRecord(
                        protocol="TCP",
                        local_ip=_ipv4(row.dwLocalAddr),
                        local_port=_port(row.dwLocalPort),
                        remote_ip=_ipv4(row.dwRemoteAddr),
                        remote_port=_port(row.dwRemotePort),
                        state=_WIN_TCP_STATES.get(row.dwState, str(row.dwState)),
                        pid=int(row.dwOwningPid),
                    )
                )
        else:
            row_size = ctypes.sizeof(MIB_TCP6ROW_OWNER_PID)
            for _ in range(count):
                row = MIB_TCP6ROW_OWNER_PID.from_buffer_copy(raw[offset: offset + row_size])
                offset += row_size
                local = socket.inet_ntop(socket.AF_INET6, bytes(row.ucLocalAddr))
                remote = socket.inet_ntop(socket.AF_INET6, bytes(row.ucRemoteAddr))
                records.append(
                    SocketRecord(
                        protocol="TCP",
                        local_ip=local,
                        local_port=_port(row.dwLocalPort),
                        remote_ip=remote,
                        remote_port=_port(row.dwRemotePort),
                        state=_WIN_TCP_STATES.get(row.dwState, str(row.dwState)),
                        pid=int(row.dwOwningPid),
                    )
                )

    # UDP
    for af in (AF_INET,):
        size = wintypes.DWORD(0)
        fn = iphlpapi.GetExtendedUdpTable
        fn(None, ctypes.byref(size), False, af, UDP_TABLE_OWNER_PID, 0)
        buf = ctypes.create_string_buffer(size.value)
        ret = fn(buf, ctypes.byref(size), False, af, UDP_TABLE_OWNER_PID, 0)
        if ret != 0:
            continue
        raw = buf.raw[: size.value]
        count = struct.unpack_from("<I", raw, 0)[0]
        offset = 4
        row_size = ctypes.sizeof(MIB_UDPROW_OWNER_PID)
        for _ in range(count):
            row = MIB_UDPROW_OWNER_PID.from_buffer_copy(raw[offset: offset + row_size])
            offset += row_size
            records.append(
                SocketRecord(
                    protocol="UDP",
                    local_ip=_ipv4(row.dwLocalAddr),
                    local_port=_port(row.dwLocalPort),
                    remote_ip="",
                    remote_port=0,
                    state="OPEN",
                    pid=int(row.dwOwningPid),
                )
            )
    return records


# ---------------------------------------------------------------------------
# Linux implementation
# ---------------------------------------------------------------------------

def _hex_ip(hex_value: str, v6: bool) -> str:
    raw = bytes.fromhex(hex_value)
    if v6:
        # /proc prints four little-endian 32-bit words
        packed = b"".join(raw[i: i + 4][::-1] for i in range(0, 16, 4))
        return socket.inet_ntop(socket.AF_INET6, packed)
    return socket.inet_ntoa(raw[::-1])


def _linux_inode_map() -> dict[str, tuple[int, str]]:
    """inode -> (pid, process name) by scanning /proc/<pid>/fd."""
    mapping: dict[str, tuple[int, str]] = {}
    proc = "/proc"
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        return mapping
    for pid in pids:
        fd_dir = os.path.join(proc, pid, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target.startswith("socket:["):
                inode = target[8:-1]
                try:
                    name = open(f"/proc/{pid}/comm", encoding="utf-8").read().strip()
                except OSError:
                    name = pid
                mapping[inode] = (int(pid), name)
    return mapping


def _linux_connections() -> list[SocketRecord]:
    inodes = _linux_inode_map()
    records: list[SocketRecord] = []
    for proto, path, v6 in (
        ("TCP", "/proc/net/tcp", False), ("TCP", "/proc/net/tcp6", True),
        ("UDP", "/proc/net/udp", False), ("UDP", "/proc/net/udp6", True),
    ):
        try:
            lines = open(path, encoding="utf-8").read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                local_hex, local_port_hex = parts[1].split(":")
                remote_hex, remote_port_hex = parts[2].split(":")
                state = int(parts[3], 16)
                inode = parts[9]
            except ValueError:
                continue
            pid, name = inodes.get(inode, (None, None))
            records.append(
                SocketRecord(
                    protocol=proto,
                    local_ip=_hex_ip(local_hex, v6),
                    local_port=int(local_port_hex, 16),
                    remote_ip=_hex_ip(remote_hex, v6) if remote_hex.strip("0") else "",
                    remote_port=int(remote_port_hex, 16),
                    state=_TCP_STATES.get(state, str(state)) if proto == "TCP" else "OPEN",
                    pid=pid,
                    process=name,
                )
            )
    return records


# ---------------------------------------------------------------------------
# Public service
# ---------------------------------------------------------------------------

class ConnectionService:
    """Enumerates this computer's sockets with process attribution."""

    def __init__(self) -> None:
        self._process_cache: dict[int, tuple[str, str | None]] = {}
        self.last_error: str | None = None
        self.uses_kernel_table = True

    # -- process names ---------------------------------------------------
    def _process_info(self, pid: int | None) -> tuple[str | None, str | None]:
        if not pid:
            return None, None
        cached = self._process_cache.get(pid)
        if cached:
            return cached
        name, exe = None, None
        try:
            import psutil

            proc = psutil.Process(pid)
            name = proc.name()
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, OSError):
                exe = None
        except Exception:
            name = None
        if name:
            self._process_cache[pid] = (name, exe)
        return name, exe

    # -- enumeration -----------------------------------------------------
    def connections(self) -> list[SocketRecord]:
        try:
            if sys.platform.startswith("win"):
                records = _windows_connections()
            else:
                records = _linux_connections()
            self.last_error = None
        except Exception as exc:  # pragma: no cover - platform specific
            self.last_error = f"connection table unavailable: {exc}"
            log.warning(self.last_error)
            records = self._psutil_fallback()
        for record in records:
            if record.pid and not record.process:
                name, exe = self._process_info(record.pid)
                record.process = name
                record.exe = exe
        return records

    def _psutil_fallback(self) -> list[SocketRecord]:
        import psutil

        out: list[SocketRecord] = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                out.append(
                    SocketRecord(
                        protocol="TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                        local_ip=conn.laddr.ip if conn.laddr else "",
                        local_port=conn.laddr.port if conn.laddr else 0,
                        remote_ip=conn.raddr.ip if conn.raddr else "",
                        remote_port=conn.raddr.port if conn.raddr else 0,
                        state=conn.status or "OPEN",
                        pid=conn.pid,
                    )
                )
        except (psutil.AccessDenied, OSError) as exc:
            self.last_error = (
                "psutil could not read the connection table (AccessDenied). "
                "Run as administrator or install the monitoring agent."
            )
            log.warning("psutil fallback failed: %s", exc)
        return out

    def established_public(self, local_ip: str | None = None) -> list[SocketRecord]:
        """Established connections to non-local addresses."""
        from networksentinel.core.util import is_public_ip

        out = []
        for record in self.connections():
            if record.protocol != "TCP" or record.state != "ESTABLISHED":
                continue
            if not record.remote_ip or not is_public_ip(record.remote_ip):
                continue
            if local_ip and record.local_ip not in (local_ip, "0.0.0.0"):
                continue
            out.append(record)
        return out

    # -- per-process traffic ---------------------------------------------
    def process_traffic(self) -> dict[int, ProcessTraffic]:
        """Per-process cumulative byte counters (read/write)."""
        import psutil

        result: dict[int, ProcessTraffic] = {}
        for proc in psutil.process_iter(["pid", "name", "exe", "username"]):
            try:
                io = proc.io_counters()
            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError, NotImplementedError):
                continue
            except Exception:
                continue
            info = proc.info
            result[proc.pid] = ProcessTraffic(
                pid=proc.pid,
                name=info.get("name") or str(proc.pid),
                exe=info.get("exe"),
                read_bytes=int(getattr(io, "read_bytes", 0)),
                write_bytes=int(getattr(io, "write_bytes", 0)),
                username=info.get("username"),
            )
        return result

    def listen_ports(self) -> list[SocketRecord]:
        return [c for c in self.connections() if c.state == "LISTEN" and c.local_port]

    def listening_services(self) -> list[dict]:
        """Unexpected-service detection input: local listening ports."""
        out = []
        for record in self.listen_ports():
            out.append(
                {
                    "protocol": record.protocol,
                    "local_ip": record.local_ip,
                    "local_port": record.local_port,
                    "process": record.process,
                    "pid": record.pid,
                    "service": WELL_KNOWN_PORTS.get(record.local_port, "unknown"),
                }
            )
        return out
