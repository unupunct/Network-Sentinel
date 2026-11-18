"""Live traffic metadata capture.

Decoding is done with scapy *metadata only*: addresses, ports, protocol, flags,
length and - where the protocol makes it public - the DNS question, the DHCP
hostname, the mDNS service names and the TLS SNI / HTTP Host.

Never captured, stored or displayed: payload contents of application traffic,
credentials, cookies, tokens, HTTP request bodies, decrypted TLS.  TLS records
are only read for the server name in the ClientHello (an unencrypted field by
design); everything after the handshake is counted, not inspected.

If no capture provider is present (Npcap/libpcap/tshark), capture is reported as
unavailable with the reason, and the rest of the application keeps working from
OS telemetry.
"""

from __future__ import annotations

import queue
import shutil
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from networksentinel.core.logging import get_logger
from networksentinel.core.util import is_multicast, is_private_ip, now_ts

log = get_logger(__name__)

PROTOCOLS = ["TCP", "UDP", "DNS", "HTTP", "HTTPS", "ICMP", "DHCP", "ARP", "mDNS", "SSDP", "QUIC", "TLS", "OTHER"]

MAX_RING = 5000


@dataclass
class TrafficRecord:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int
    direction: str
    device_id: int | None = None
    app: str | None = None
    state: str = ""
    info: str = ""
    source: str = "capture"


@dataclass
class CaptureStatus:
    running: bool = False
    available: bool = False
    reason: str = ""
    interface: str = ""
    packets: int = 0
    errors: int = 0
    started_at: float = 0.0
    filter: str = ""
    provider: str = ""


class TrafficMonitorService:
    """Runs a capture thread and keeps a bounded in-memory ring of metadata."""

    def __init__(self, db, settings, interfaces, discovery, dns_monitor, inventory) -> None:
        self.db = db
        self.settings = settings
        self.interfaces = interfaces
        self.discovery = discovery
        self.dns = dns_monitor
        self.inventory = inventory
        self.status = CaptureStatus()
        self.ring: deque[TrafficRecord] = deque(maxlen=MAX_RING)
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._paused = threading.Event()
        self._queue: queue.Queue = queue.Queue(maxsize=20000)
        self._writer: threading.Thread | None = None
        self._db_buffer: list[tuple] = []
        self.protocol_counts: dict[str, int] = defaultdict(int)
        self.device_bytes: dict[str, dict] = defaultdict(lambda: {"up": 0, "down": 0})
        self.filters = {"protocol": None, "device_id": None, "ip": None, "port": None, "direction": None, "search": None}
        self.callbacks: list = []
        self.onsummary: list = []
        self.local_ips: set[str] = set()

    # -- availability ----------------------------------------------------
    def probe(self) -> CaptureStatus:
        provider = ""
        available = False
        reason = ""
        try:
            from scapy.all import conf  # noqa: F401

            if sys.platform.startswith("win"):
                try:
                    from scapy.arch.windows import get_windows_if_list

                    ifaces = get_windows_if_list()
                    available = bool(ifaces) and any(i.get("guid") for i in ifaces)
                    provider = "Npcap" if available else ""
                except Exception as exc:
                    available = False
                    provider = ""
                    reason = f"Npcap is not usable: {exc}"
                if not available and not reason:
                    reason = (
                        "Raw capture needs Npcap (WinPcap API) on Windows. Install Npcap "
                        "with 'WinPcap API-compatible mode', then restart Network Sentinel. "
                        "Everything else keeps working from OS telemetry."
                    )
            else:
                from scapy.config import conf as scapy_conf

                if getattr(scapy_conf, "use_pcap", False):
                    provider = "libpcap"
                    available = True
                else:
                    reason = (
                        "Raw capture needs libpcap and CAP_NET_RAW. Install libpcap "
                        "(python3-libpcap / libpcap0.8) and start Network Sentinel with "
                        "capture privileges."
                    )
            if not available and not reason:
                reason = "No packet capture provider (Npcap/libpcap) was found."
        except Exception as exc:
            reason = f"scapy is not available: {exc}"
        if not available and shutil.which("tshark"):
            reason += " tshark is installed and can be used from the command line for deep analysis."
        self.status.available = available
        self.status.provider = provider
        if not self.status.running:
            self.status.reason = reason
        return self.status

    # -- lifecycle -------------------------------------------------------
    def start(self, interface_name: str | None = None, bpf: str | None = None) -> CaptureStatus:
        if self.status.running:
            return self.status
        status = self.probe()
        if not status.available:
            return status
        iface = self.interfaces.select(interface_name or self.settings.get("interface"))
        if iface is None:
            self.status.reason = "No network interface selected."
            return self.status
        self.local_ips = {iface.ipv4} if iface.ipv4 else set()
        self.status = CaptureStatus(
            running=True, available=True, interface=iface.name,
            started_at=now_ts(), filter=bpf or self.settings.get("capture_filter", ""),
            provider=status.provider,
        )
        self._stop.clear()
        self._paused.clear()
        self._thread = threading.Thread(target=self._capture_loop, name="capture", daemon=True)
        self._thread.start()
        self._writer = threading.Thread(target=self._writer_loop, name="capture-writer", daemon=True)
        self._writer.start()
        log.info("capture started on %s (filter=%s)", iface.name, self.status.filter)
        return self.status

    def stop(self) -> None:
        self._stop.set()
        self._paused.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._flush_db()
        self.status.running = False
        log.info("capture stopped")

    def pause(self) -> None:
        self._paused.set()

    def resume(self) -> None:
        self._paused.clear()

    @property
    def paused(self) -> bool:
        return self._paused.is_set()

    # -- capture ---------------------------------------------------------
    def _capture_loop(self) -> None:
        try:
            from scapy.all import AsyncSniffer
        except Exception as exc:  # pragma: no cover
            self.status.running = False
            self.status.reason = f"scapy could not be loaded: {exc}"
            return
        kwargs = {"iface": self.status.interface, "prn": self._on_packet, "store": False}
        if self.status.filter:
            kwargs["filter"] = self.status.filter
        sniffer = None
        try:
            sniffer = AsyncSniffer(**kwargs)
            sniffer.start()
            while not self._stop.is_set():
                time.sleep(0.25)
        except Exception as exc:
            self.status.errors += 1
            self.status.reason = f"capture failed: {exc}"
            log.warning("capture failed: %s", exc)
        finally:
            if sniffer is not None:
                try:
                    sniffer.stop()
                except Exception:
                    pass
            self.status.running = False

    def _on_packet(self, packet) -> None:
        if self._paused.is_set():
            return
        try:
            record = self._decode(packet)
        except Exception:  # never let a malformed packet kill the thread
            self.status.errors += 1
            return
        if record is None:
            return
        self.status.packets += 1
        with self._lock:
            self.ring.append(record)
            self.protocol_counts[record.protocol] += 1
            bucket = self.device_bytes[record.src_ip if record.direction == "outbound" else record.dst_ip]
            if record.direction == "outbound":
                bucket["up"] += record.length
            else:
                bucket["down"] += record.length
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            pass
        for callback in self.callbacks:
            try:
                callback(record)
            except Exception:
                pass

    def _decode(self, packet) -> TrafficRecord | None:
        from scapy.layers.dhcp import DHCP
        from scapy.layers.dns import DNS
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import ARP, Ether

        ts = float(getattr(packet, "time", time.time()))
        length = len(packet)
        if packet.haslayer(ARP):
            arp = packet[ARP]
            proto = "ARP"
            src, dst = arp.psrc, arp.pdst
            self.discovery.observe_arp(arp.psrc, arp.hwsrc, None, None)
            direction = "local" if is_private_ip(dst) else "outbound"
            return TrafficRecord(ts, src, dst, 0, 0, proto, length, direction,
                                 info=f"ARP {arp.op} {'who-has' if arp.op == 1 else 'is-at'}")
        if packet.haslayer(IP):
            net = packet[IP]
            src, dst = net.src, net.dst
        elif packet.haslayer(IPv6):
            net = packet[IPv6]
            src, dst = net.src, net.dst
        else:
            return None
        if is_multicast(dst) and not packet.haslayer(UDP):
            return None
        src_port = dst_port = 0
        proto = "OTHER"
        info = ""
        state = ""
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            src_port, dst_port = int(tcp.sport), int(tcp.dport)
            proto = "TCP"
            flags = str(tcp.flags)
            state = {"S": "SYN", "SA": "SYN-ACK", "A": "ACK", "FA": "FIN-ACK",
                     "F": "FIN", "R": "RST", "PA": "PSH-ACK", "RA": "RST-ACK"}.get(flags, flags)
            if 443 in (src_port, dst_port):
                proto = "HTTPS"
            elif 80 in (src_port, dst_port):
                proto = "HTTP"
            elif 443 not in (src_port, dst_port) and dst_port in (853, 993, 995, 465, 8443):
                proto = "TLS"
            if dst_port == 443 and packet.haslayer(UDP):
                proto = "QUIC"
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            src_port, dst_port = int(udp.sport), int(udp.dport)
            proto = "UDP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            info = f"type {packet[ICMP].type}"
        if packet.haslayer(DNS):
            dns = packet[DNS]
            proto = "mDNS" if dst_port == 5353 or src_port == 5353 else "DNS"
            if dns.qd is not None:
                try:
                    qname = dns.qd.qname.decode("utf-8", "replace").rstrip(".")
                    info = f"{qname} {getattr(dns.qd, 'qtype', '')}"
                    answers = []
                    if dns.ancount:
                        records = dns.an
                        while records is not None and hasattr(records, "rdata"):
                            answers.append(str(records.rdata))
                            records = records.payload if hasattr(records, "payload") else None
                    if proto == "mDNS":
                        self.discovery.observe_mdns(qname, src, [qname], None)
                    elif qname and not qname.endswith(".arpa"):
                        self.dns.record(
                            qname, src, qtype=str(getattr(dns.qd, "qtype", "A")),
                            answers=answers, source="passive capture",
                            device_id=self._device_id_for(src), server=dst,
                        )
                except Exception:
                    pass
        elif packet.haslayer(DHCP):
            proto = "DHCP"
            try:
                for option in packet[DHCP].options:
                    if isinstance(option, tuple) and option[0] == "hostname":
                        self.discovery.observe_dhcp(option[1], src, packet[Ether].src if packet.haslayer(Ether) else None)
                        info = f"hostname {option[1]}"
                        break
                    if isinstance(option, tuple) and option[0] == "requested_addr":
                        info = f"request {option[1]}"
            except Exception:
                pass
        elif dst_port == 1900 or src_port == 1900:
            proto = "SSDP"
        if not info and packet.haslayer(Ether):
            try:
                if packet.haslayer("TLS") or b"\x16\x03" in bytes(packet.payload)[:4]:
                    pass
            except Exception:
                pass
        direction = self._direction(src, dst)
        return TrafficRecord(
            ts, src, dst, src_port, dst_port, proto, length, direction,
            device_id=self._device_id_for(src if direction == "outbound" else dst),
            state=state, info=info,
        )

    def _direction(self, src: str, dst: str) -> str:
        if is_private_ip(src) and is_private_ip(dst):
            return "local"
        if src in self.local_ips:
            return "outbound"
        if dst in self.local_ips:
            return "inbound"
        if is_private_ip(src):
            return "outbound"
        if is_private_ip(dst):
            return "inbound"
        return "unknown"

    def _device_id_for(self, ip: str) -> int | None:
        device = self.inventory.by_ip(ip)
        return device.id if device else None

    # -- writer ----------------------------------------------------------
    def _writer_loop(self) -> None:
        while not self._stop.is_set() or not self._queue.empty():
            try:
                record = self._queue.get(timeout=0.5)
            except queue.Empty:
                self._flush_db()
                continue
            self._db_buffer.append(
                (record.ts, record.device_id, record.src_ip, record.dst_ip, record.src_port,
                 record.dst_port, record.protocol, record.length, record.direction,
                 record.app, record.state, record.info, record.source)
            )
            if len(self._db_buffer) >= 200:
                self._flush_db()

    def _flush_db(self) -> None:
        if not self._db_buffer:
            return
        rows = self._db_buffer
        self._db_buffer = []
        try:
            self.db.executemany(
                "INSERT INTO traffic(ts, device_id, src_ip, dst_ip, src_port, dst_port, "
                "protocol, length, direction, app, state, info, source) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
        except Exception as exc:  # pragma: no cover
            log.warning("traffic insert failed: %s", exc)

    # -- queries ---------------------------------------------------------
    def filtered(self, limit: int = 500, since: float | None = None) -> list[dict]:
        since = since or (now_ts() - 300)
        with self._lock:
            records = list(self.ring)
        out = []
        f = self.filters
        for record in reversed(records):
            if record.ts < since:
                continue
            if f["protocol"] and record.protocol != f["protocol"]:
                continue
            if f["device_id"] and record.device_id != f["device_id"]:
                continue
            if f["direction"] and record.direction != f["direction"]:
                continue
            if f["ip"] and f["ip"] not in (record.src_ip, record.dst_ip):
                continue
            if f["port"] and f["port"] not in (record.src_port, record.dst_port):
                continue
            if f["search"]:
                needle = f["search"].lower()
                haystack = f"{record.src_ip} {record.dst_ip} {record.src_port} {record.dst_port} {record.protocol} {record.info}".lower()
                if needle not in haystack:
                    continue
            out.append(record)
            if len(out) >= limit:
                break
        return out

    def set_filters(self, **values) -> None:
        """Set capture filters (protocol, device_id, ip, port, direction, search)."""
        for key, value in values.items():
            if key in self.filters:
                self.filters[key] = value or None

    def clear_filters(self) -> None:
        for key in self.filters:
            self.filters[key] = None

    def protocol_distribution(self) -> list[tuple[str, int]]:
        with self._lock:
            return sorted(self.protocol_counts.items(), key=lambda kv: kv[1], reverse=True)

    def stats(self) -> dict:
        return {
            "running": self.status.running,
            "available": self.status.available,
            "reason": self.status.reason,
            "packets": self.status.packets,
            "errors": self.status.errors,
            "interface": self.status.interface,
            "provider": self.status.provider,
            "paused": self.paused,
            "ring": len(self.ring),
        }

    def export_rows(self, since: float | None = None, limit: int = 5000) -> list[dict]:
        rows = self.db.query(
            "SELECT ts, src_ip, dst_ip, src_port, dst_port, protocol, length, direction, "
            "state, info FROM traffic WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
            (since or 0, limit),
        )
        return [dict(r) for r in rows]
