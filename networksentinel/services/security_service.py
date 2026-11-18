"""Security detection engine.

Every rule reports *evidence*, not a verdict.  A destination is never called
malicious because it is unfamiliar: threat-intelligence hits are reported as
"listed in <feed>", behavioural rules as "unusual for this network", and the
severity is chosen from the evidence available.

Rules
-----
* ``unknown_device``        - online device that is not marked trusted
* ``new_device``            - device first seen in the last hour
* ``unexpected_service``    - a listening service on this computer that is not
                              expected for the host (RDP, VNC, Telnet, SMB...)
* ``unusual_outbound``      - connection to a rare/never-seen-before public
                              destination, or to a non-standard port
* ``threat_intel``          - destination present in the bundled threat feed
                              or in a user-supplied feed file
* ``dns_volume``            - burst of DNS queries from one client
* ``connection_failures``   - repeated failed connection attempts (RST)
* ``traffic_spike``         - bandwidth far above the rolling average
* ``port_scan``             - one host touching many ports of one target
* ``local_comm``            - unusual local-to-local communication
* ``unencrypted``           - plaintext protocols observed on the wire
* ``agent_offline``         - managed agent stopped reporting
"""

from __future__ import annotations

import ipaddress
import json
import statistics
import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path

from networksentinel.core.logging import get_logger
from networksentinel.core.util import fmt_bytes, is_private_ip, is_public_ip, now_ts

log = get_logger(__name__)

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

RISKY_PORTS = {
    23: ("Telnet", "plaintext remote shell"),
    21: ("FTP", "plaintext file transfer"),
    69: ("TFTP", "plaintext file transfer"),
    512: ("rexec", "plaintext remote execution"),
    513: ("rlogin", "plaintext remote login"),
    514: ("rsh", "plaintext remote shell"),
    445: ("SMB", "file sharing, often abused for lateral movement"),
    139: ("NetBIOS", "legacy file sharing"),
    3389: ("RDP", "remote desktop exposed"),
    5900: ("VNC", "remote desktop exposed"),
    5938: ("TeamViewer", "third-party remote control"),
    4444: ("Metasploit default", "common reverse-shell port"),
    1337: ("common backdoor port", "frequently used by malware"),
    31337: ("Back Orifice", "historically used by backdoors"),
    9050: ("Tor SOCKS", "anonymising proxy"),
    9001: ("Tor relay", "anonymising proxy"),
}

#: Bundled, deliberately small threat-intelligence seed list.  It contains
#: documentation/test ranges and a few well-known sinkhole/telemetry domains
#: used by malware families, so the rule can be demonstrated and tested without
#: pretending to be a live commercial feed.  The full, current feeds are not
#: redistributed here; the user can import one (Settings -> Threat intelligence).
BUNDLED_INDICATORS = {
    "domains": {
        "malware.testing.google.test": "Google Safe Browsing test domain (not malicious - demonstration)",
        "example-phishing.test": "reserved test domain",
        "sinkhole.example": "reserved test domain",
        "doubleclick.net": "advertising and tracking network",
        "telemetry.malware-analytics.example": "reserved test domain",
    },
    "ips": {
        "192.0.2.66": "TEST-NET-1 documentation range",
        "198.51.100.23": "TEST-NET-2 documentation range",
        "203.0.113.45": "TEST-NET-3 documentation range",
    },
}

EXPECTED_LISTENERS = {135, 139, 445, 5353, 5355, 631, 1900, 5040, 7680, 5000, 5001, 2869}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    evidence: str
    explanation: str
    impact: str
    recommendation: str
    device_id: int | None = None
    dedupe_key: str = ""
    source: str = "behavioural analysis"


class SecurityDetectionService:
    def __init__(self, db, settings, inventory, explorer, traffic, dns_monitor,
                 bandwidth, alerts, agents=None) -> None:
        self.db = db
        self.settings = settings
        self.inventory = inventory
        self.explorer = explorer
        self.traffic = traffic
        self.dns = dns_monitor
        self.bandwidth = bandwidth
        self.alerts = alerts
        self.agents = agents
        self._lock = threading.Lock()
        self._dns_window: dict[str, deque] = defaultdict(lambda: deque(maxlen=400))
        self._failure_window: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._port_window: dict[tuple[str, str], set] = defaultdict(set)
        self._seen_destinations: set[str] = set()
        self._bw_history: deque = deque(maxlen=60)
        self.threat_domains: dict[str, str] = dict(BUNDLED_INDICATORS["domains"])
        self.threat_ips: dict[str, str] = dict(BUNDLED_INDICATORS["ips"])
        self.threat_source = "bundled seed list"
        self.last_run: float = 0.0
        self.findings_created = 0
        self._bootstrap_destinations()

    def _bootstrap_destinations(self) -> None:
        rows = self.db.query(
            "SELECT DISTINCT remote_ip FROM connections WHERE remote_ip IS NOT NULL LIMIT 20000"
        )
        self._seen_destinations = {row[0] for row in rows if row[0]}

    # -- threat intelligence --------------------------------------------
    def load_threat_feed(self, path: Path | str, kind: str = "auto") -> dict:
        """Import a plain-text or JSON feed of indicators.

        Plain text: one indicator per line (``domain`` or ``ip``, optional
        ``,comment``).  JSON: ``{"domains": {...}, "ips": {...}}``.
        """
        path = Path(path)
        text = path.read_text(encoding="utf-8", errors="replace")
        added = 0
        if path.suffix.lower() == ".json":
            data = json.loads(text)
            for key, store in (("domains", self.threat_domains), ("ips", self.threat_ips)):
                for indicator, reason in (data.get(key) or {}).items():
                    store[indicator.strip().lower()] = str(reason)
                    added += 1
        else:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                indicator, _, comment = line.partition(",")
                indicator = indicator.strip().lower()
                try:
                    ipaddress.ip_address(indicator)
                    self.threat_ips[indicator] = comment.strip() or "user-supplied feed"
                except ValueError:
                    self.threat_domains[indicator.lstrip(".")] = comment.strip() or "user-supplied feed"
                added += 1
        self.threat_source = f"bundled seed list + {path.name} ({added} indicators)"
        self.settings.set("threat_intel_last_update", now_ts())
        self.db.audit("user", "threat_feed.import", str(path), f"{added} indicators")
        return {"added": added, "domains": len(self.threat_domains), "ips": len(self.threat_ips)}

    def threat_match(self, ip: str | None, domain: str | None) -> tuple[str, str] | None:
        if not self.settings.get("threat_intel_enabled", True):
            return None
        if ip and ip in self.threat_ips:
            return ip, self.threat_ips[ip]
        if domain:
            name = domain.lower().rstrip(".")
            if name in self.threat_domains:
                return name, self.threat_domains[name]
            parts = name.split(".")
            for index in range(1, len(parts) - 1):
                suffix = ".".join(parts[index:])
                if suffix in self.threat_domains:
                    return suffix, self.threat_domains[suffix]
        return None

    # -- finding storage -------------------------------------------------
    def _record(self, finding: Finding, cooldown: float = 3600.0) -> int | None:
        key = finding.dedupe_key or f"{finding.rule}:{finding.device_id}:{finding.title}"
        existing = self.db.query_one(
            "SELECT id, ts FROM findings WHERE dedupe_key = ? ORDER BY ts DESC LIMIT 1", (key,)
        )
        if existing and now_ts() - (existing["ts"] or 0) < cooldown:
            return None
        cur = self.db.execute(
            "INSERT INTO findings(ts, rule, severity, device_id, title, evidence, explanation, "
            "impact, recommendation, dedupe_key, source) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                now_ts(), finding.rule, finding.severity, finding.device_id, finding.title,
                finding.evidence, finding.explanation, finding.impact, finding.recommendation,
                key, finding.source,
            ),
        )
        self.findings_created += 1
        if finding.severity in ("Critical", "High") and self.alerts:
            self.alerts.emit(
                "security", finding.severity, finding.title, finding.evidence,
                finding.device_id, cooldown=cooldown,
            )
        return int(cur.lastrowid)

    # -- analysis --------------------------------------------------------
    def run(self) -> dict:
        if not self.settings.get("security_enabled", True):
            return {"skipped": True}
        created = 0
        created += self._check_devices()
        created += self._check_destinations()
        created += self._check_ports()
        created += self._check_dns()
        created += self._check_failures()
        created += self._check_bandwidth()
        created += self._check_listeners()
        created += self._check_local_traffic()
        created += self._check_agents()
        self.last_run = now_ts()
        return {"created": created, "total": self.db.scalar("SELECT COUNT(*) FROM findings")}

    def _check_devices(self) -> int:
        created = 0
        now = now_ts()
        for device in self.inventory.all_devices(include_offline=False):
            if device.is_self or device.is_gateway:
                continue
            if not device.trusted:
                age = now - (device.first_seen or now)
                if age < 3600:
                    severity = "Medium"
                    title = f"New untrusted device: {device.name}"
                else:
                    severity = "Low"
                    title = f"Untrusted device online: {device.name}"
                finding = Finding(
                    rule="unknown_device",
                    severity=severity,
                    title=title,
                    evidence=(
                        f"MAC {device.mac}; address {device.ip or 'unknown'}; "
                        f"manufacturer {device.vendor or 'unknown'}; "
                        f"type {device.device_type}; first seen {int(age // 60)} min ago."
                    ),
                    explanation=(
                        "The device is present on the local network and has not been marked "
                        "as trusted. Untrusted is not the same as malicious."
                    ),
                    impact=(
                        "An unrecognised device can use the network and may be reachable "
                        "from other hosts on it."
                    ),
                    recommendation=(
                        "Identify the device (check its MAC vendor and hostname), then mark it "
                        "trusted or investigate it on the router."
                    ),
                    device_id=device.id,
                    dedupe_key=f"unknown_device:{device.id}",
                )
                if self._record(finding, cooldown=6 * 3600):
                    created += 1
        return created

    def _check_destinations(self) -> int:
        created = 0
        since = now_ts() - 600
        rows = self.db.query(
            "SELECT remote_ip, domain, application, device_id, MAX(last_seen) AS ts "
            "FROM connections WHERE last_seen >= ? AND remote_ip IS NOT NULL "
            "GROUP BY remote_ip, application, device_id",
            (since,),
        )
        labels = self.inventory.label_map()
        for row in rows:
            ip, domain = row["remote_ip"], row["domain"]
            if not is_public_ip(ip):
                continue
            match = self.threat_match(ip, domain)
            if match:
                indicator, reason = match
                finding = Finding(
                    rule="threat_intel",
                    severity="High",
                    title=f"Destination listed in threat intelligence: {domain or ip}",
                    evidence=(
                        f"Indicator {indicator} ({reason}); remote {ip}:{row['application'] or 'unattributed'}; "
                        f"device {labels.get(row['device_id'], 'unknown')}."
                    ),
                    explanation=(
                        "The destination appears in the threat-intelligence list that is loaded "
                        "into Network Sentinel. Listings can be stale or over-broad."
                    ),
                    impact="Traffic to a listed destination can indicate malware, C2 or tracking.",
                    recommendation=(
                        "Correlate with the process that opened the connection, block the "
                        "destination on the router if it is not expected, and scan the host."
                    ),
                    device_id=row["device_id"],
                    dedupe_key=f"threat:{indicator}:{row['device_id']}",
                    source=f"threat intelligence ({self.threat_source})",
                )
                if self._record(finding, cooldown=12 * 3600):
                    created += 1
                    if self.alerts:
                        self.alerts.suspicious_destination(
                            labels.get(row["device_id"], "a device"), ip, domain, reason,
                            row["device_id"],
                        )
                continue

            first_time = ip not in self._seen_destinations
            risky = None
            port = self.db.scalar(
                "SELECT remote_port FROM connections WHERE remote_ip = ? ORDER BY last_seen DESC LIMIT 1",
                (ip,), default=0,
            )
            if port in RISKY_PORTS:
                risky = RISKY_PORTS[port]
            if first_time and (risky or not domain):
                severity = "Medium" if risky else "Low"
                title = (
                    f"New external destination: {domain or ip}"
                    if not risky else f"New connection to {risky[0]} port {port}"
                )
                evidence = (
                    f"{ip}:{port} from {row['application'] or 'an unattributed process'} on "
                    f"{labels.get(row['device_id'], 'this computer')}"
                    + (f"; domain {domain}" if domain else "; no domain name observed")
                )
                explanation = (
                    "This destination has not been observed on this network before. Novelty "
                    "alone does not make a destination malicious."
                    + (f" The port is associated with {risky[1]}." if risky else "")
                )
                impact = "A new outbound destination deserves a quick look, nothing more."
                recommendation = (
                    "Check the application that opened the connection. If it is expected, no "
                    "action is needed; if not, close the application and investigate."
                )
                finding = Finding(
                    rule="unusual_outbound", severity=severity, title=title, evidence=evidence,
                    explanation=explanation, impact=impact, recommendation=recommendation,
                    device_id=row["device_id"], dedupe_key=f"newdest:{ip}:{row['device_id']}",
                )
                if self._record(finding, cooldown=24 * 3600):
                    created += 1
        self._seen_destinations.update(row["remote_ip"] for row in rows if row["remote_ip"])
        return created

    def _check_ports(self) -> int:
        created = 0
        since = now_ts() - 300
        rows = self.db.query(
            "SELECT src_ip, dst_ip, COUNT(DISTINCT dst_port) AS ports, COUNT(*) AS packets "
            "FROM traffic WHERE ts >= ? AND protocol = 'TCP' GROUP BY src_ip, dst_ip "
            "HAVING ports >= ?",
            (since, int(self.settings.get("port_scan_threshold", 12))),
        )
        for row in rows:
            finding = Finding(
                rule="port_scan",
                severity="High",
                title=f"Possible port scan: {row['src_ip']} → {row['dst_ip']}",
                evidence=f"{row['ports']} distinct destination ports in 5 minutes ({row['packets']} packets).",
                explanation=(
                    "One host contacted many ports of a single target in a short time, which is "
                    "the signature of a port scan. Some applications and monitoring tools do this."
                ),
                impact="A scan is reconnaissance: it maps open services before an attack.",
                recommendation=(
                    "Identify the scanning host and the software responsible. If it is not a "
                    "known tool, isolate the host and review its logs."
                ),
                device_id=self.inventory.by_ip(row["src_ip"]).id if self.inventory.by_ip(row["src_ip"]) else None,
                dedupe_key=f"portscan:{row['src_ip']}:{row['dst_ip']}",
                source="packet metadata",
            )
            if self._record(finding, cooldown=1800):
                created += 1
        return created

    def _check_dns(self) -> int:
        created = 0
        rows = self.dns.recent(limit=400)
        counts: dict[str, int] = defaultdict(int)
        for row in rows:
            counts[row.get("client_ip") or "unknown"] += 1
        for client, count in counts.items():
            if count < 150:
                continue
            finding = Finding(
                rule="dns_volume",
                severity="Low",
                title=f"High DNS query volume from {client}",
                evidence=f"{count} queries in the last {len(rows)} observed records.",
                explanation=(
                    "Sustained query bursts can be normal (browsers, telemetry) or can indicate "
                    "DNS tunnelling or a misbehaving application."
                ),
                impact="DNS tunnelling can carry data out of the network disguised as queries.",
                recommendation="Compare the queried domains with the applications in use.",
                device_id=self.inventory.by_ip(client).id if self.inventory.by_ip(client) else None,
                dedupe_key=f"dnsvolume:{client}",
                source="DNS observation",
            )
            if self._record(finding, cooldown=3600):
                created += 1
        return created

    def _check_failures(self) -> int:
        created = 0
        since = now_ts() - 300
        rows = self.db.query(
            "SELECT dst_ip, COUNT(*) AS resets FROM traffic WHERE ts >= ? AND state LIKE '%RST%' "
            "GROUP BY dst_ip HAVING resets >= ?",
            (since, int(self.settings.get("connection_failure_threshold", 8))),
        )
        for row in rows:
            finding = Finding(
                rule="connection_failures",
                severity="Low",
                title=f"Repeated connection failures to {row['dst_ip']}",
                evidence=f"{row['resets']} reset connections in 5 minutes.",
                explanation=(
                    "Repeated resets can mean the remote service is down, a firewall is blocking "
                    "the traffic, or software is retrying aggressively."
                ),
                impact="Usually harmless; occasionally indicates blocked malware traffic.",
                recommendation="Check whether the destination is expected for the applications in use.",
                dedupe_key=f"failures:{row['dst_ip']}",
                source="packet metadata",
            )
            if self._record(finding, cooldown=1800):
                created += 1
        return created

    def _check_bandwidth(self) -> int:
        created = 0
        current = self.bandwidth.current
        if current is None:
            return 0
        total = current.download_bps + current.upload_bps
        if len(self._bw_history) >= 10:
            mean = statistics.fmean(self._bw_history) or 1.0
            if total > max(mean * 8, 25 * 1024 * 1024):
                finding = Finding(
                    rule="traffic_spike",
                    severity="Medium",
                    title="Unexpected traffic spike",
                    evidence=(
                        f"{fmt_bytes(total)}/s now against a recent average of {fmt_bytes(mean)}/s."
                    ),
                    explanation="Throughput rose sharply compared with the recent baseline.",
                    impact="A spike can be a legitimate download or an unexpected data transfer.",
                    recommendation="Open Bandwidth and check which device or application is responsible.",
                    dedupe_key="traffic_spike",
                    source="interface counters",
                )
                if self._record(finding, cooldown=900):
                    created += 1
        self._bw_history.append(total)
        return created

    def _check_listeners(self) -> int:
        created = 0
        services = getattr(self.explorer, "listen_snapshot", []) or []
        self_device = self.inventory.by_mac(self.inventory.discovery.interfaces.primary().mac) \
            if hasattr(self.inventory, "discovery") and self.inventory.discovery.interfaces.primary() else None
        for service in services:
            port = int(service.get("local_port") or 0)
            if not port or port in EXPECTED_LISTENERS:
                continue
            if not (is_private_ip(service.get("local_ip")) or service.get("local_ip") in ("0.0.0.0", "::")):
                continue
            risky = RISKY_PORTS.get(port)
            if risky is None and port < 1024:
                continue
            severity = "Medium" if risky else "Low"
            finding = Finding(
                rule="unexpected_service",
                severity=severity,
                title=f"Listening service on port {port}"
                      + (f" ({risky[0]})" if risky else ""),
                evidence=(
                    f"{service.get('protocol')} {service.get('local_ip')}:{port} "
                    f"by {service.get('process') or 'unknown process'}"
                    + (f"; {risky[1]}" if risky else "")
                ),
                explanation=(
                    "A process on this computer accepts inbound connections on a port that is "
                    "not part of the usual Windows/mDNS set."
                ),
                impact="Exposed services widen the attack surface of the host.",
                recommendation=(
                    "Confirm the process needs to listen. If not, stop it or block the port in "
                    "the firewall."
                ),
                device_id=self_device.id if self_device else None,
                dedupe_key=f"listen:{port}",
                source="OS socket table",
            )
            if self._record(finding, cooldown=6 * 3600):
                created += 1
        return created

    def _check_local_traffic(self) -> int:
        created = 0
        since = now_ts() - 600
        rows = self.db.query(
            "SELECT src_ip, dst_ip, COUNT(*) AS packets, SUM(length) AS bytes FROM traffic "
            "WHERE ts >= ? AND direction = 'local' GROUP BY src_ip, dst_ip "
            "HAVING bytes > 50000000 ORDER BY bytes DESC LIMIT 5",
            (since,),
        )
        for row in rows:
            finding = Finding(
                rule="local_comm",
                severity="Low",
                title=f"Unusual local traffic: {row['src_ip']} → {row['dst_ip']}",
                evidence=f"{fmt_bytes(row['bytes'])} in {row['packets']} packets within 10 minutes.",
                explanation=(
                    "Two hosts on the local network exchanged an unusual amount of data. Backups "
                    "and media streaming look like this too."
                ),
                impact="Large internal transfers can indicate data collection across hosts.",
                recommendation="Confirm both hosts are yours and the transfer is expected.",
                dedupe_key=f"local:{row['src_ip']}:{row['dst_ip']}",
                source="packet metadata",
            )
            if self._record(finding, cooldown=3600):
                created += 1
        return created

    def _check_agents(self) -> int:
        created = 0
        if self.agents is None:
            return 0
        for agent in self.agents.list_agents():
            if agent.get("status") == "offline":
                finding = Finding(
                    rule="agent_offline",
                    severity="Medium",
                    title=f"Monitoring agent offline: {agent.get('name')}",
                    evidence=(
                        f"Last report {int((now_ts() - (agent.get('last_seen') or 0)) // 60)} "
                        "minutes ago."
                    ),
                    explanation="The managed agent stopped sending telemetry.",
                    impact="Application attribution and per-process bandwidth for that computer are unavailable.",
                    recommendation="Check that the computer is on and the agent service is running.",
                    device_id=agent.get("device_id"),
                    dedupe_key=f"agent_offline:{agent.get('agent_id')}",
                    source="agent",
                )
                if self._record(finding, cooldown=3600):
                    created += 1
        return created

    # -- reporting -------------------------------------------------------
    def findings(self, limit: int = 300, severity: str | None = None,
                 since: float = 0.0) -> list[dict]:
        sql = "SELECT * FROM findings WHERE ts >= ?"
        params: list = [since]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.db.query(sql, params)]

    def counts(self) -> dict[str, int]:
        rows = self.db.query("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
        counts = {row[0]: row[1] for row in rows}
        return {sev: counts.get(sev, 0) for sev in SEVERITY_ORDER}

    def open_count(self) -> int:
        return int(self.db.scalar(
            "SELECT COUNT(*) FROM findings WHERE acknowledged = 0 AND severity IN ('Critical','High','Medium')"
        ))

    def acknowledge(self, finding_id: int) -> None:
        self.db.execute("UPDATE findings SET acknowledged = 1 WHERE id = ?", (finding_id,))
        self.db.audit("user", "finding.ack", str(finding_id))

    def stats(self) -> dict:
        return {
            "findings": self.db.scalar("SELECT COUNT(*) FROM findings"),
            "open": self.open_count(),
            "last_run": self.last_run,
            "threat_indicators": len(self.threat_domains) + len(self.threat_ips),
            "threat_source": self.threat_source,
            "created_last_run": self.findings_created,
        }
