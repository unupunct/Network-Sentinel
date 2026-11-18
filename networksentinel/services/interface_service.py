"""Network interface discovery.

Uses :mod:`psutil` where possible (pure Python, no privileges needed) and falls
back to platform commands for the gateway and interface descriptions:

* Windows - ``ipconfig``/``Get-NetIPConfiguration``-equivalent parsing of
  ``ipconfig /all`` for descriptions and DHCP/DNS information.
* Linux   - ``ip -j addr`` and ``ip route`` (iproute2) plus ``nmcli`` when
  NetworkManager is present.

Nothing here changes system state: it only reads.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field, asdict

from networksentinel.core.logging import get_logger

log = get_logger(__name__)

VIRTUAL_HINTS = (
    "virtual", "vmware", "vmnet", "hyper-v", "vethernet", "loopback", "bluetooth",
    "docker", "veth", "br-", "tun", "tap", "tailscale", "wireguard", "zt", "wsl",
    "npcap loopback", "teredo", "isatap", "pseudo",
)


@dataclass
class NetworkInterface:
    name: str
    description: str = ""
    mac: str = ""
    ipv4: str = ""
    ipv6: str = ""
    netmask: str = ""
    gateway: str = ""
    dns_servers: list[str] = field(default_factory=list)
    is_up: bool = False
    is_default: bool = False
    is_virtual: bool = False
    mtu: int = 0
    speed_mbps: int = 0

    @property
    def cidr(self) -> str:
        if self.ipv4 and self.netmask:
            try:
                net = ipaddress.ip_network(f"{self.ipv4}/{self.netmask}", strict=False)
                return str(net)
            except ValueError:
                return ""
        return ""

    @property
    def network(self) -> ipaddress.IPv4Network | None:
        cidr = self.cidr
        if not cidr:
            return None
        try:
            return ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return None

    @property
    def usable_hosts(self) -> int:
        net = self.network
        if net is None or net.num_addresses < 4:
            return 0
        return net.num_addresses - 2

    def as_dict(self) -> dict:
        data = asdict(self)
        data["cidr"] = self.cidr
        return data


def _run(cmd: list[str], timeout: float = 6.0) -> str:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform.startswith("win") else 0,
        )
        return result.stdout or ""
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("command %s failed: %s", cmd[0], exc)
        return ""


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

def _windows_interfaces() -> list[NetworkInterface]:
    import psutil

    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    descriptions: dict[str, str] = {}
    gateways: dict[str, str] = {}

    text = _run(["ipconfig", "/all"], timeout=12)
    current = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        header = re.match(r"^([A-Za-z0-9].*?)(?: adapter )?(.*):$", line)
        if header and not line.startswith(" "):
            label = line.rstrip(":").strip()
            # "Ethernet adapter Ethernet 2:" -> "Ethernet 2"
            label = re.sub(r"^(Ethernet|Wireless LAN|Unknown) adapter\s+", "", label)
            current = label
            continue
        if current is None:
            continue
        stripped = line.strip()
        if ":" in stripped:
            key, _, value = stripped.partition(":")
            key_l = key.strip().lower()
            value = value.strip()
            if "description" in key_l and current not in descriptions:
                descriptions[current] = value
            elif key_l.startswith("default gateway") or key_l == "default gateway":
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)", value)
                if match:
                    gateways[current] = match.group(1)

    out: list[NetworkInterface] = []
    for name, info in addrs.items():
        iface = NetworkInterface(name=name)
        iface.is_up = bool(stats.get(name) and stats[name].isup)
        if stats.get(name):
            iface.speed_mbps = int(getattr(stats[name], "speed", 0) or 0)
            iface.mtu = int(getattr(stats[name], "mtu", 0) or 0)
        for addr in info:
            family = addr.family
            if family == socket.AF_INET:
                iface.ipv4 = iface.ipv4 or addr.address
                iface.netmask = iface.netmask or addr.netmask or ""
            elif family == socket.AF_INET6:
                text_addr = addr.address.split("%")[0]
                if not text_addr.startswith("fe80") and not iface.ipv6:
                    iface.ipv6 = text_addr
            elif getattr(psutil, "AF_LINK", object()) == family:
                iface.mac = (addr.address or "").replace("-", ":").lower()
        iface.description = descriptions.get(name, name)
        iface.gateway = gateways.get(name, "")
        low = f"{name} {iface.description}".lower()
        iface.is_virtual = any(h in low for h in VIRTUAL_HINTS)
        out.append(iface)
    return out


# ---------------------------------------------------------------------------
# Linux / other POSIX
# ---------------------------------------------------------------------------

def _linux_interfaces() -> list[NetworkInterface]:
    import psutil

    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    out: dict[str, NetworkInterface] = {}
    for name, info in addrs.items():
        iface = NetworkInterface(name=name)
        iface.is_up = bool(stats.get(name) and stats[name].isup)
        if stats.get(name):
            iface.mtu = int(getattr(stats[name], "mtu", 0) or 0)
            iface.speed_mbps = int(getattr(stats[name], "speed", 0) or 0)
        for addr in info:
            if addr.family == socket.AF_INET:
                iface.ipv4 = iface.ipv4 or addr.address
                iface.netmask = iface.netmask or addr.netmask or ""
            elif addr.family == socket.AF_INET6:
                text_addr = addr.address.split("%")[0]
                if not text_addr.startswith("fe80") and not iface.ipv6:
                    iface.ipv6 = text_addr
            elif getattr(psutil, "AF_PACKET", object()) == addr.family:
                iface.mac = (addr.address or "").replace("-", ":").lower()
        out[name] = iface

    # gateway per interface via `ip route show default`
    if shutil.which("ip"):
        routes = _run(["ip", "-o", "route", "show", "default"])
        for line in routes.splitlines():
            match = re.search(r"default via (\S+) dev (\S+)", line)
            if match:
                gw, dev = match.group(1), match.group(2)
                if dev in out and not out[dev].gateway:
                    out[dev].gateway = gw
                    out[dev].is_default = True
        # DNS via resolvectl if present
        if shutil.which("resolvectl"):
            for name, iface in out.items():
                dns_text = _run(["resolvectl", "dns", name], timeout=3)
                for token in dns_text.split():
                    try:
                        ipaddress.ip_address(token)
                    except ValueError:
                        continue
                    if token not in iface.dns_servers:
                        iface.dns_servers.append(token)
    descriptions: dict[str, str] = {}
    if shutil.which("nmcli"):
        text = _run(["nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status"], timeout=5)
        for line in text.splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                descriptions[parts[0]] = parts[1]
    for name, iface in out.items():
        iface.description = descriptions.get(name, name)
        low = f"{name} {iface.description}".lower()
        iface.is_virtual = any(h in low for h in VIRTUAL_HINTS)
        if not iface.is_default and iface.gateway:
            iface.is_default = True
    return list(out.values())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class InterfaceService:
    """Reads the machine's interfaces.  Pure observation, no privileges."""

    def __init__(self) -> None:
        self._cache: list[NetworkInterface] = []
        self._last_refresh = 0.0
        self.privileges = self._detect_privileges()

    def _detect_privileges(self) -> dict:
        info = {
            "platform": sys.platform,
            "is_admin": False,
            "raw_capture": False,
            "npcap": False,
            "tshark": False,
            "note": "",
        }
        if sys.platform.startswith("win"):
            try:
                import ctypes

                info["is_admin"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:  # pragma: no cover - platform specific
                info["is_admin"] = False
            npcap_dll = None
            try:
                import scapy.config  # noqa: F401

                from scapy.arch.windows import get_windows_if_list  # noqa: F401

                npcap_dll = True
            except Exception:
                npcap_dll = False
            info["npcap"] = bool(npcap_dll)
        else:
            import os

            info["is_admin"] = hasattr(os, "geteuid") and os.geteuid() == 0
            info["npcap"] = True  # libpcap semantics on Linux
            if shutil.which("tcpdump"):
                info["note"] = "libpcap via tcpdump available"
        info["tshark"] = bool(shutil.which("tshark"))
        info["raw_capture"] = bool(info["npcap"] or info["tshark"])
        return info

    def discover(self) -> list[NetworkInterface]:
        try:
            if sys.platform.startswith("win"):
                interfaces = _windows_interfaces()
            else:
                interfaces = _linux_interfaces()
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("interface discovery failed: %s", exc)
            interfaces = []
        interfaces.sort(key=lambda i: (not i.is_up, i.is_virtual, i.name))
        self._cache = interfaces
        return interfaces

    @property
    def cached(self) -> list[NetworkInterface]:
        return self._cache

    def primary(self) -> NetworkInterface | None:
        if not self._cache:
            self.discover()
        candidates = [i for i in self._cache if i.ipv4 and i.is_up and not i.is_virtual]
        with_gw = [i for i in candidates if i.gateway]
        if with_gw:
            return with_gw[0]
        if candidates:
            return candidates[0]
        up = [i for i in self._cache if i.ipv4 and i.is_up]
        return up[0] if up else None

    def by_name(self, name: str) -> NetworkInterface | None:
        for iface in self._cache:
            if iface.name == name:
                return iface
        return None

    def select(self, name: str | None) -> NetworkInterface | None:
        if not self._cache:
            self.discover()
        if name:
            found = self.by_name(name)
            if found is not None:
                return found
        return self.primary()

    def local_ip(self) -> str | None:
        iface = self.primary()
        return iface.ipv4 if iface else None
