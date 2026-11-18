"""Network discovery: ARP/mDNS/SSDP/DHCP observation plus an optional ARP sweep.

Sources of truth, in order of reliability:

1. **Passive observation** (always on, no privileges): ARP replies, DHCP,
   mDNS and SSDP advertisements seen on the interface, the OS ARP/neighbour
   table, and the OS-level connection table.
2. **Active ARP sweep** (optional, low impact): one ARP request per host in the
   selected subnet, then the replies are read from the neighbour table.  This is
   a single round of ARP - never a port scan, never a probe of services.
3. **Agent reports**: devices that run the managed agent are matched by MAC.

Operating system and device type are only reported when there is evidence
(hostname pattern, mDNS service, DHCP fingerprint, vendor OUI).  Otherwise the
UI shows ``Unidentified``.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass, field

from networksentinel.core.logging import get_logger
from networksentinel.core.util import is_multicast, is_private_ip, now_ts
from networksentinel.services.oui import (
    OS_HINTS,
    VendorLookup,
    is_multicast_mac,
    is_randomized_mac,
    normalize_mac,
)

log = get_logger(__name__)

DEVICE_TYPES = [
    "Windows computer", "Linux computer", "macOS computer", "Android device",
    "iPhone / iPad", "Smart TV", "Printer", "Network equipment", "Server",
    "Gaming console", "IoT device", "Virtual machine", "Unknown",
]

CONFIDENCE = ["Observed", "Inferred", "Unidentified"]

# mDNS service types -> device category (RFC 6762 / bonjour service names)
MDNS_SERVICES = {
    "_ipp._tcp": "Printer", "_ipps._tcp": "Printer", "_printer._tcp": "Printer",
    "_pdl-datastream._tcp": "Printer", "_scanner._tcp": "Printer",
    "_airplay._tcp": "Smart TV", "_raop._tcp": "Smart TV", "_googlecast._tcp": "Smart TV",
    "_spotify-connect._tcp": "Smart TV", "_samsungtv._tcp": "Smart TV",
    "_workstation._tcp": "Computer", "_smb._tcp": "Computer", "_rfb._tcp": "Computer",
    "_ssh._tcp": "Computer", "_sftp-ssh._tcp": "Computer", "_companion-link._tcp": "Apple device",
    "_apple-mobdev2._tcp": "Apple device", "_device-info._tcp": "Apple device",
    "_afpovertcp._tcp": "macOS computer", "_homekit._tcp": "IoT device",
    "_hap._tcp": "IoT device", "_matter._tcp": "IoT device", "_esphomelib._tcp": "IoT device",
    "_http._tcp": "Web device", "_https._tcp": "Web device",
    "_androidtvremote2._tcp": "Smart TV", "_amzn-wplay._tcp": "Amazon device",
    "_sleep-proxy._udp": "Apple device", "_nfs._tcp": "Server",
}

VENDOR_TYPE_HINTS = {
    "Apple": "Apple device", "Samsung": "Samsung device", "Xiaomi": "Xiaomi device",
    "Huawei": "Huawei device", "Google": "Google device", "Amazon Technologies": "Amazon device",
    "Roku": "Roku", "Sonos": "Sonos speaker", "Philips Hue": "Smart light",
    "Espressif (ESP32)": "IoT device", "Espressif (ESP8266)": "IoT device",
    "Raspberry Pi Foundation": "Single-board computer", "Nintendo": "Gaming console",
    "Sony Interactive (PlayStation)": "Gaming console", "VMware": "Virtual machine",
    "VirtualBox": "Virtual machine", "Microsoft Hyper-V": "Virtual machine",
    "QEMU / KVM": "Virtual machine", "Docker": "Virtual machine",
    "TP-Link": "Network equipment", "D-Link": "Network equipment", "NETGEAR": "Network equipment",
    "Cisco": "Network equipment", "MikroTik": "Network equipment", "Ubiquiti": "Network equipment",
    "ASUSTek": "Network equipment", "Hangzhou H3C": "Network equipment", "Belkin": "Network equipment",
    "Seiko Epson": "Printer", "Brother Industries": "Printer", "Canon": "Printer",
    "Ricoh": "Printer", "Xerox": "Printer", "Lexmark": "Printer",
    "HP": "Computer", "Dell": "Computer", "Lenovo": "Computer", "Intel": "Computer",
    "ASUS": "Computer",
}


@dataclass
class ObservedDevice:
    mac: str
    ip: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    os_guess: str | None = None
    os_confidence: str = "Unidentified"
    device_type: str = "Unknown"
    source: str = "arp table"
    evidence: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    is_self: bool = False
    is_gateway: bool = False
    first_seen: float | None = None
    last_seen: float | None = None
    online: bool = True

    def merge(self, other: "ObservedDevice") -> None:
        if other.ip and not self.ip:
            self.ip = other.ip
        if other.hostname and not self.hostname:
            self.hostname = other.hostname
        if other.vendor and not self.vendor:
            self.vendor = other.vendor
        for item in other.evidence:
            if item not in self.evidence:
                self.evidence.append(item)
        for item in other.services:
            if item not in self.services:
                self.services.append(item)
        if other.os_guess and not self.os_guess:
            self.os_guess = other.os_guess
            self.os_confidence = other.os_confidence
        if other.device_type not in ("Unknown", "") and self.device_type in ("Unknown", ""):
            self.device_type = other.device_type
        self.is_gateway = self.is_gateway or other.is_gateway
        self.is_self = self.is_self or other.is_self
        self.last_seen = max(self.last_seen or 0, other.last_seen or 0) or None


def classify_from_evidence(hostname: str | None, vendor: str | None,
                           services: list[str]) -> tuple[str, str, str]:
    """Return (device_type, os_guess, confidence) from real evidence only."""
    os_guess, confidence = None, "Unidentified"
    device_type = "Unknown"

    for service in services:
        base = service.split(".")[0] + "." + service.split(".")[1] if service.count(".") >= 1 else service
        mapped = MDNS_SERVICES.get(service) or MDNS_SERVICES.get(base)
        if mapped:
            device_type = mapped
            confidence = "Observed"
            break

    if hostname:
        lowered = hostname.lower()
        for pattern, guess, _kind in OS_HINTS:
            if re.search(pattern, lowered):
                os_guess = guess
                confidence = "Inferred"
                if device_type == "Unknown":
                    device_type = guess
                elif guess in ("Windows", "Linux", "macOS"):
                    device_type = f"{guess} computer"
                break
        if device_type in ("Unknown", "Computer") and lowered:
            if re.match(r"^(desktop|laptop|win)-?[a-z0-9]{4,}", lowered):
                device_type, os_guess, confidence = "Windows computer", "Windows", "Inferred"

    if device_type in ("Unknown", "Computer") and vendor:
        hinted = VENDOR_TYPE_HINTS.get(vendor)
        if hinted:
            device_type = hinted
            if confidence == "Unidentified":
                confidence = "Inferred"

    if device_type == "Computer":
        device_type = "Unknown"

    if device_type in ("Windows computer",) and not os_guess:
        os_guess = "Windows"
    if device_type in ("Linux computer",) and not os_guess:
        os_guess = "Linux"
    if device_type in ("macOS computer",) and not os_guess:
        os_guess = "macOS"
    if device_type in ("Android device",) and not os_guess:
        os_guess = "Android"
    if device_type in ("iPhone / iPad",) and not os_guess:
        os_guess = "iOS / iPadOS"

    return device_type, (os_guess or "Unidentified"), confidence


class NetworkDiscoveryService:
    """Discovers devices on the selected interface."""

    def __init__(self, settings, dns_monitor, interfaces) -> None:
        self.settings = settings
        self.dns = dns_monitor
        self.interfaces = interfaces
        self.vendors = VendorLookup()
        self.known: dict[str, ObservedDevice] = {}
        self._lock = threading.Lock()
        self.last_scan: float = 0.0
        self.last_sweep: float = 0.0
        self.last_error: str | None = None
        self.sweep_results = 0
        self.passive_observations = 0

    # -- passive observation --------------------------------------------
    def observe_arp(self, src_ip: str, src_mac: str, iface_ip: str | None,
                    gateway: str | None) -> None:
        mac = normalize_mac(src_mac)
        if not mac or is_multicast_mac(mac) or mac == "FF:FF:FF:FF:FF:FF":
            return
        with self._lock:
            device = self.known.get(mac) or ObservedDevice(mac=mac, first_seen=now_ts())
            device.ip = src_ip or device.ip
            device.source = "ARP observation"
            device.last_seen = now_ts()
            device.online = True
            if src_ip and gateway and src_ip == gateway:
                device.is_gateway = True
            if iface_ip and src_ip == iface_ip:
                device.is_self = True
            self.known[mac] = device
            self.passive_observations += 1

    def observe_mdns(self, hostname: str | None, address: str | None,
                     services: list[str], src_mac: str | None = None) -> None:
        if not address and not hostname:
            return
        mac = normalize_mac(src_mac) if src_mac else ""
        with self._lock:
            device = None
            if mac:
                device = self.known.get(mac)
            if device is None and address:
                for candidate in self.known.values():
                    if candidate.ip == address:
                        device = candidate
                        break
            if device is None:
                if not mac:
                    return  # cannot inventory a device without a hardware address
                device = ObservedDevice(mac=mac, first_seen=now_ts())
            device.ip = address or device.ip
            device.hostname = device.hostname or (hostname.rstrip(".") if hostname else None)
            device.source = "mDNS observation"
            device.last_seen = now_ts()
            device.online = True
            for service in services:
                if service not in device.services:
                    device.services.append(service)
            if "mDNS service advertisement" not in device.evidence:
                device.evidence.append("mDNS service advertisement")
            self.known[mac] = device
            self.passive_observations += 1

    def observe_dhcp(self, hostname: str | None, client_ip: str | None,
                     client_mac: str | None) -> None:
        mac = normalize_mac(client_mac)
        if not mac:
            return
        with self._lock:
            device = self.known.get(mac) or ObservedDevice(mac=mac, first_seen=now_ts())
            device.ip = client_ip or device.ip
            if hostname:
                device.hostname = hostname
                if "DHCP hostname option" not in device.evidence:
                    device.evidence.append("DHCP hostname option")
            device.source = "DHCP observation"
            device.last_seen = now_ts()
            device.online = True
            self.known[mac] = device
            self.passive_observations += 1

    # -- active discovery ------------------------------------------------
    def _arp_table(self) -> list[tuple[str, str]]:
        """(ip, mac) pairs from the OS neighbour table."""
        pairs: list[tuple[str, str]] = []
        if sys.platform.startswith("win"):
            import subprocess

            try:
                out = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=8,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                ).stdout
            except (OSError, subprocess.SubprocessError):
                return pairs
            for line in out.splitlines():
                match = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)", line)
                if match and match.group(3).lower() == "dynamic":
                    pairs.append((match.group(1), normalize_mac(match.group(2))))
        else:
            try:
                out = open("/proc/net/arp", encoding="utf-8").read().splitlines()[1:]
            except OSError:
                return pairs
            for line in out:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    pairs.append((parts[0], normalize_mac(parts[3])))
        return pairs

    def arp_sweep(self, interface_name: str, cidr: str, local_ip: str,
                  gateway: str | None = None, timeout: float = 2.0,
                  max_hosts: int = 512) -> int:
        """Send one ARP request per host. Returns number of replies seen.

        Uses scapy when raw capture is available; otherwise it does a cheap
        'touch the neighbour cache' pass with a non-blocking TCP connect to the
        ARP-relevant address family.  Both are single round trips, not scans.
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return 0
        hosts = [str(h) for h in network.hosts() if str(h) != local_ip]
        if len(hosts) > max_hosts:
            hosts = hosts[:max_hosts]
        before = {ip for ip, _ in self._arp_table()}
        sent = 0
        try:
            from scapy.all import ARP, Ether, conf, srp  # noqa: F401

            conf.verb = 0
            packets = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host) for host in hosts]
            for packet in packets:
                try:
                    answered, _ = srp(packet, timeout=0.05, retry=0, verbose=0,
                                      iface=interface_name)
                    sent += len(answered)
                except Exception:
                    break
        except Exception:
            # No raw sockets: ask the OS to populate its neighbour table instead.
            for host in hosts:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(0.05)
                        sock.connect_ex((host, 1))
                except OSError:
                    pass
        time.sleep(min(timeout, 1.0))
        after = {ip for ip, _ in self._arp_table()}
        self.last_sweep = now_ts()
        self.sweep_results = len(after - before) + sent
        return self.sweep_results

    def scan(self, interface_name: str | None = None) -> list[ObservedDevice]:
        """Merge the OS neighbour table, reverse DNS and local sockets."""
        iface = self.interfaces.select(interface_name or self.settings.get("interface"))
        local_ip = iface.ipv4 if iface else None
        gateway = iface.gateway if iface else None
        found: dict[str, ObservedDevice] = {}

        for ip, mac in self._arp_table():
            if not mac or is_multicast_mac(mac) or not is_private_ip(ip):
                continue
            device = ObservedDevice(mac=mac, ip=ip, source="ARP / neighbour table",
                                    first_seen=now_ts(), last_seen=now_ts())
            if gateway and ip == gateway:
                device.is_gateway = True
                device.evidence.append("Default gateway address")
            if local_ip and ip == local_ip:
                device.is_self = True
                device.evidence.append("This computer")
            found[mac] = device

        # This computer always exists, even if the ARP table has no entry.
        if iface and iface.mac:
            mac = normalize_mac(iface.mac)
            device = found.get(mac) or ObservedDevice(mac=mac, first_seen=now_ts())
            device.ip = iface.ipv4 or device.ip
            device.is_self = True
            device.hostname = device.hostname or socket.gethostname()
            device.source = "local interface"
            device.last_seen = now_ts()
            device.evidence.append("Local interface of this computer")
            found[mac] = device

        with self._lock:
            for mac, device in found.items():
                existing = self.known.get(mac)
                if existing:
                    existing.merge(device)
                    existing.last_seen = now_ts()
                    existing.online = True
                    found[mac] = existing
                else:
                    self.known[mac] = device
            merged = list(found.values())

        self._enrich_all(merged)
        self.last_scan = now_ts()
        return merged

    def _enrich_all(self, devices: list[ObservedDevice]) -> None:
        """Reverse DNS for many devices at once, so one slow answer blocks nothing."""
        pending = []
        for device in devices:
            if not device.vendor and device.mac:
                vendor = self.vendors.lookup(device.mac)
                if vendor:
                    device.vendor = vendor
                    device.evidence.append(f"MAC OUI vendor: {vendor}")
                elif is_randomized_mac(device.mac):
                    device.evidence.append("Locally administered (randomised) MAC address")
            if not device.hostname and device.ip and self.settings.get("store_hostnames", True):
                pending.append(device)
        if pending:
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=16) as pool:
                names = list(pool.map(lambda d: self.dns.resolver.reverse(d.ip, ttl=3600, timeout=2.0), pending))
            for device, name in zip(pending, names):
                if name and not re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
                    device.hostname = name
                    device.evidence.append("Reverse DNS (PTR) answer")
        for device in devices:
            device_type, os_guess, confidence = classify_from_evidence(
                device.hostname, device.vendor, device.services
            )
            if device_type != "Unknown":
                device.device_type = device_type
            if os_guess != "Unidentified":
                device.os_guess = os_guess
                device.os_confidence = confidence
            elif not device.os_guess:
                device.os_confidence = "Unidentified"

    def _enrich(self, device: ObservedDevice) -> None:
        if not device.vendor and device.mac:
            vendor = self.vendors.lookup(device.mac)
            if vendor:
                device.vendor = vendor
                device.evidence.append(f"MAC OUI vendor: {vendor}")
            elif is_randomized_mac(device.mac):
                device.evidence.append("Locally administered (randomised) MAC address")
        if not device.hostname and device.ip and self.settings.get("store_hostnames", True):
            name = self.dns.resolver.reverse(device.ip)
            if name and not re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
                device.hostname = name
                device.evidence.append("Reverse DNS (PTR) answer")
        device_type, os_guess, confidence = classify_from_evidence(
            device.hostname, device.vendor, device.services
        )
        if device_type != "Unknown":
            device.device_type = device_type
        if os_guess != "Unidentified":
            device.os_guess = os_guess
            device.os_confidence = confidence
        elif not device.os_guess:
            device.os_confidence = "Unidentified"

    # -- accessors -------------------------------------------------------
    def snapshot(self) -> list[ObservedDevice]:
        with self._lock:
            return list(self.known.values())

    def stats(self) -> dict:
        return {
            "known": len(self.known),
            "last_scan": self.last_scan,
            "last_sweep": self.last_sweep,
            "sweep_results": self.sweep_results,
            "passive_observations": self.passive_observations,
            "vendor_table": self.vendors.size,
            "error": self.last_error,
        }
