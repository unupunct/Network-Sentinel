"""Small shared helpers: formatting, time and address classification."""

from __future__ import annotations

import ipaddress
import socket
import time
from datetime import datetime, timezone


def now_ts() -> float:
    """Current time as a Unix timestamp (float seconds)."""
    return time.time()


def fmt_ts(ts: float | None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(ts).strftime(fmt)


def fmt_time(ts: float | None) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def fmt_ago(ts: float | None) -> str:
    if not ts:
        return "—"
    delta = max(0.0, now_ts() - ts)
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    if delta < 86400:
        return f"{int(delta // 3600)}h ago"
    return f"{int(delta // 86400)}d ago"


def fmt_bytes(value: float | int | None) -> str:
    if value is None:
        return "Unavailable"
    value = float(value)
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    index = 0
    while value >= 1024 and index < len(units) - 1:
        value /= 1024.0
        index += 1
    if index == 0:
        return f"{int(value)} B"
    return f"{value:.1f} {units[index]}"


def fmt_rate(bytes_per_second: float | None) -> str:
    if bytes_per_second is None:
        return "Unavailable"
    return fmt_bytes(bytes_per_second) + "/s"


def fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"


def fmt_mac(mac: str | None) -> str:
    if not mac:
        return "—"
    mac = mac.lower().replace("-", ":")
    return mac


def is_private_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def is_multicast(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_multicast
    except ValueError:
        return False


def hostname_of(ip: str, timeout: float = 0.6) -> str | None:
    """Reverse DNS, best effort; returns None rather than raising."""
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
        return name.rstrip(".")
    except (OSError, socket.error):
        return None
    finally:
        socket.setdefaulttimeout(None)


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def local_iso(ts: float | None) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, timezone.utc).astimezone().isoformat(timespec="seconds")
