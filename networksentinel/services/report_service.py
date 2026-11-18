"""Reports: PDF, HTML and JSON.

Every report is generated from stored telemetry only.  Credentials, cookies,
tokens and message contents are never stored in the first place; on top of that
every string passes through :func:`redact` before it is written.
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path

from networksentinel import APP_NAME, APP_VERSION
from networksentinel.core.logging import get_logger
from networksentinel.core.paths import reports_dir
from networksentinel.core.redaction import redact, redact_mapping
from networksentinel.core.util import fmt_bytes, fmt_ts, now_ts

log = get_logger(__name__)

PERIODS = {
    "Last hour": 3600,
    "Last 24 hours": 86400,
    "Last 7 days": 7 * 86400,
    "Last 30 days": 30 * 86400,
}


class ReportService:
    def __init__(self, db, inventory, explorer, dns_monitor, bandwidth, security,
                 alerts, timeline, settings, interfaces) -> None:
        self.db = db
        self.inventory = inventory
        self.explorer = explorer
        self.dns = dns_monitor
        self.bandwidth = bandwidth
        self.security = security
        self.alerts = alerts
        self.timeline = timeline
        self.settings = settings
        self.interfaces = interfaces
        self.last_report: Path | None = None
        self.history: list[dict] = []

    # -- data assembly ---------------------------------------------------
    def collect(self, seconds: int = 86400, sections: list[str] | None = None) -> dict:
        since = now_ts() - seconds
        sections = sections or [
            "summary", "devices", "domains", "applications", "bandwidth",
            "security", "alerts", "configuration",
        ]
        iface = self.interfaces.select(self.settings.get("interface"))
        data: dict = {
            "meta": {
                "application": APP_NAME,
                "version": APP_VERSION,
                "generated": fmt_ts(now_ts()),
                "period_seconds": seconds,
                "period_label": next(
                    (name for name, secs in PERIODS.items() if secs == seconds),
                    f"{seconds // 3600} hours",
                ),
                "interface": iface.name if iface else "none",
                "interface_cidr": iface.cidr if iface else "",
                "gateway": iface.gateway if iface else "",
                "monitoring_scope": (
                    "Local network observations (ARP/DNS/connection metadata) plus telemetry "
                    "from explicitly enrolled managed agents."
                ),
            },
            "sections": sections,
        }
        if "summary" in sections:
            data["summary"] = {
                "devices_total": self.inventory.summary()["total"],
                "devices_online": self.inventory.summary()["online"],
                "connections": self.db.scalar(
                    "SELECT COUNT(*) FROM connections WHERE first_seen >= ?", (since,)
                ),
                "dns_queries": self.db.scalar(
                    "SELECT COUNT(*) FROM dns_queries WHERE ts >= ?", (since,)
                ),
                "domains": self.db.scalar(
                    "SELECT COUNT(DISTINCT domain) FROM dns_queries WHERE ts >= ?", (since,)
                ),
                "findings": self.db.scalar(
                    "SELECT COUNT(*) FROM findings WHERE ts >= ?", (since,)
                ),
                "alerts": self.db.scalar("SELECT COUNT(*) FROM alerts WHERE ts >= ?", (since,)),
                "download_bytes": int(self.db.scalar(
                    "SELECT SUM(download_bytes) FROM bandwidth_samples WHERE ts >= ? AND scope='interface'",
                    (since,),
                ) or 0),
                "upload_bytes": int(self.db.scalar(
                    "SELECT SUM(upload_bytes) FROM bandwidth_samples WHERE ts >= ? AND scope='interface'",
                    (since,),
                ) or 0),
            }
        if "devices" in sections:
            data["devices"] = [
                {
                    "name": d.name,
                    "mac": d.mac,
                    "ip": d.ip,
                    "vendor": d.vendor or "Unknown manufacturer",
                    "type": d.category,
                    "os": d.os_label,
                    "status": d.status,
                    "trusted": d.trusted,
                    "first_seen": fmt_ts(d.first_seen),
                    "last_seen": fmt_ts(d.last_seen),
                    "description": d.description or "",
                }
                for d in self.inventory.all_devices()
            ]
        if "domains" in sections:
            data["domains"] = self.dns.domains(since=since, limit=60)
            data["domain_categories"] = [
                {"category": cat, "queries": count}
                for cat, count in self.dns.counts_by_category(since)
            ]
        if "applications" in sections:
            data["applications"] = self.explorer.applications(since=since)
        if "bandwidth" in sections:
            data["bandwidth"] = {
                "devices": self.bandwidth.device_usage()[:40],
                "processes": self.bandwidth.process_usage(limit=30),
                "summary": self.bandwidth.summary(),
            }
        if "security" in sections:
            data["security"] = self.security.findings(since=since, limit=200)
            data["security_counts"] = self.security.counts()
        if "alerts" in sections:
            data["alerts"] = self.alerts.list(limit=200)
        if "configuration" in sections:
            settings = self.settings.as_dict()
            data["configuration"] = {
                key: settings[key]
                for key in (
                    "monitoring_enabled", "capture_enabled", "active_scan_interval",
                    "sample_interval", "retention_days", "security_enabled",
                    "threat_intel_enabled", "agent_server_enabled", "agent_server_port",
                    "agent_interval", "alerts_enabled",
                )
                if key in settings
            }
            data["configuration"]["threat_intel_source"] = self.security.threat_source
        return redact_mapping(data)

    # -- writers ---------------------------------------------------------
    def _path(self, fmt: str, period_label: str) -> Path:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        slug = period_label.lower().replace(" ", "-")
        return reports_dir() / f"network-sentinel-{slug}-{stamp}.{fmt}"

    def generate(self, fmt: str = "pdf", seconds: int = 86400,
                 sections: list[str] | None = None,
                 target: Path | None = None) -> Path:
        data = self.collect(seconds, sections)
        period_label = data["meta"]["period_label"]
        if fmt == "json":
            path = target or self._path("json", period_label)
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        elif fmt == "html":
            path = target or self._path("html", period_label)
            path.write_text(self._render_html(data), encoding="utf-8")
        else:
            path = target or self._path("pdf", period_label)
            self._render_pdf(data, path)
        self.last_report = path
        self.history.append({"path": str(path), "fmt": fmt, "ts": now_ts(), "label": period_label})
        self.db.audit("user", f"report.{fmt}", str(path), period_label)
        return path

    # -- HTML ------------------------------------------------------------
    def _render_html(self, data: dict) -> str:
        meta = data["meta"]
        e = html.escape

        def table(headers: list[str], rows: list[list[str]]) -> str:
            head = "".join(f"<th>{e(h)}</th>" for h in headers)
            body = "".join(
                "<tr>" + "".join(f"<td>{e(str(cell))}</td>" for cell in row) + "</tr>"
                for row in rows
            ) or f'<tr><td colspan="{len(headers)}">No data for this period.</td></tr>'
            return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

        parts = [f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{e(APP_NAME)} report</title>
<style>
 body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif; background:#101820; color:#EDF6F7; margin:0; padding:32px; }}
 h1 {{ font-size:26px; margin:0 0 4px; }} h2 {{ font-size:17px; margin:28px 0 10px; color:#00D4C7; }}
 .meta {{ color:#94AAB3; font-size:13px; }} .grid {{ display:flex; flex-wrap:wrap; gap:12px; margin:18px 0; }}
 .card {{ background:#1D303B; border:1px solid #2B4453; border-radius:12px; padding:14px 18px; min-width:150px; }}
 .card b {{ display:block; font-size:22px; color:#00D4C7; }} .card span {{ color:#94AAB3; font-size:12px; }}
 table {{ width:100%; border-collapse:collapse; font-size:12.5px; background:#172630; border-radius:10px; overflow:hidden; }}
 th {{ text-align:left; background:#1D303B; color:#94AAB3; font-weight:600; padding:8px; }}
 td {{ padding:7px 8px; border-top:1px solid #223844; }}
 .note {{ background:#172630; border-left:3px solid #00A8E8; padding:10px 14px; border-radius:8px; color:#94AAB3; font-size:12.5px; }}
 .sev-Critical {{ color:#EF5350; }} .sev-High {{ color:#F5B942; }} .sev-Medium {{ color:#00A8E8; }}
 .sev-Low {{ color:#00D4C7; }} .sev-Informational {{ color:#94AAB3; }}
 footer {{ margin-top:36px; color:#6E828B; font-size:11.5px; }}
</style></head><body>
<h1>{e(APP_NAME)} — network activity report</h1>
<div class="meta">Generated {e(meta['generated'])} · period {e(meta['period_label'])} ·
interface {e(meta['interface'])} {e(meta['interface_cidr'])} · version {e(meta['version'])}</div>
<div class="note">{e(meta['monitoring_scope'])} Encrypted DNS, VPNs and proxies hide DNS
observations; per-device traffic outside this computer needs packet capture or an agent.</div>
"""]
        summary = data.get("summary")
        if summary:
            cards = [
                ("Devices online", f"{summary['devices_online']} / {summary['devices_total']}"),
                ("Connections", summary["connections"]),
                ("DNS queries", summary["dns_queries"]),
                ("Distinct domains", summary["domains"]),
                ("Security findings", summary["findings"]),
                ("Alerts", summary["alerts"]),
                ("Downloaded", fmt_bytes(summary["download_bytes"])),
                ("Uploaded", fmt_bytes(summary["upload_bytes"])),
            ]
            parts.append('<div class="grid">' + "".join(
                f'<div class="card"><b>{e(str(value))}</b><span>{e(label)}</span></div>'
                for label, value in cards
            ) + "</div>")
        if data.get("devices"):
            parts.append("<h2>Device inventory</h2>")
            parts.append(table(
                ["Name", "Address", "MAC", "Manufacturer", "Type", "OS estimate", "Status",
                 "Trusted", "First seen", "Last seen"],
                [[d["name"], d["ip"] or "—", d["mac"], d["vendor"], d["type"], d["os"],
                  d["status"], "yes" if d["trusted"] else "no", d["first_seen"], d["last_seen"]]
                 for d in data["devices"]],
            ))
        if data.get("domains"):
            parts.append("<h2>Domain activity</h2>")
            parts.append(table(
                ["Domain", "Category", "Queries", "First seen", "Last seen"],
                [[d["domain"], d.get("category", ""), d.get("queries", 0),
                  fmt_ts(d.get("first_seen")), fmt_ts(d.get("last_seen"))]
                 for d in data["domains"]],
            ))
        if data.get("domain_categories"):
            parts.append("<h2>Destinations by category</h2>")
            parts.append(table(
                ["Category", "Queries"],
                [[c["category"], c["queries"]] for c in data["domain_categories"]],
            ))
        if data.get("applications"):
            parts.append("<h2>Application connections</h2>")
            parts.append(table(
                ["Application", "Category", "Connections", "Upload", "Download", "Last seen"],
                [[a["application"], a.get("category", ""), a["connections"],
                  fmt_bytes(a["upload"] or 0), fmt_bytes(a["download"] or 0),
                  fmt_ts(a["last_seen"])]
                 for a in data["applications"]],
            ))
        bandwidth = data.get("bandwidth")
        if bandwidth:
            parts.append("<h2>Bandwidth</h2>")
            summary_bw = bandwidth.get("summary") or {}
            parts.append(table(
                ["Metric", "Value"],
                [
                    ["Current download", f"{fmt_bytes(summary_bw.get('download_bps') or 0)}/s"],
                    ["Current upload", f"{fmt_bytes(summary_bw.get('upload_bps') or 0)}/s"],
                    ["Transferred today (down)", fmt_bytes(summary_bw.get("today_download") or 0)],
                    ["Transferred today (up)", fmt_bytes(summary_bw.get("today_upload") or 0)],
                    ["Peak download", f"{fmt_bytes(summary_bw.get('peak_download') or 0)}/s"],
                    ["Peak upload", f"{fmt_bytes(summary_bw.get('peak_upload') or 0)}/s"],
                ],
            ))
            if bandwidth.get("processes"):
                parts.append("<h3>Per application (process counters)</h3>")
                parts.append(table(
                    ["Application", "PID", "Downloaded", "Uploaded", "Source"],
                    [[p["name"], p["pid"], fmt_bytes(p["download_bytes"]),
                      fmt_bytes(p["upload_bytes"]), p.get("source", "")]
                     for p in bandwidth["processes"]],
                ))
        if data.get("security"):
            parts.append("<h2>Security findings</h2>")
            parts.append(table(
                ["Severity", "Rule", "Device", "Title", "Evidence", "Recommendation"],
                [[f["severity"], f["rule"], str(f.get("device_id") or "—"),
                  f["title"], f["evidence"], f["recommendation"]]
                 for f in data["security"]],
            ))
        if data.get("alerts"):
            parts.append("<h2>Alert history</h2>")
            parts.append(table(
                ["Time", "Severity", "Kind", "Title", "Detail"],
                [[fmt_ts(a["ts"]), a["severity"], a["kind"], a["title"], a["body"]]
                 for a in data["alerts"]],
            ))
        if data.get("configuration"):
            parts.append("<h2>Monitoring configuration</h2>")
            parts.append(table(
                ["Setting", "Value"],
                [[k, str(v)] for k, v in data["configuration"].items()],
            ))
        parts.append(
            f"<footer>Generated by {e(APP_NAME)} {e(APP_VERSION)}. No credentials, cookies, "
            "tokens or message contents are stored or reported.</footer></body></html>"
        )
        return "\n".join(parts)

    # -- PDF -------------------------------------------------------------
    def _render_pdf(self, data: dict, path: Path) -> None:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )

        accent = colors.HexColor("#00A8A0")
        dark = colors.HexColor("#15232B")
        muted = colors.HexColor("#5A6B75")
        styles = getSampleStyleSheet()
        title = ParagraphStyle("T", parent=styles["Title"], fontSize=20, textColor=dark,
                               alignment=TA_LEFT, spaceAfter=4)
        subtitle = ParagraphStyle("S", parent=styles["Normal"], fontSize=9, textColor=muted,
                                  spaceAfter=12)
        heading = ParagraphStyle("H", parent=styles["Heading2"], fontSize=13,
                                 textColor=accent, spaceBefore=14, spaceAfter=6)
        body = ParagraphStyle("B", parent=styles["Normal"], fontSize=8.5, textColor=dark,
                              leading=11)
        cell = ParagraphStyle("C", parent=styles["Normal"], fontSize=7.5, textColor=dark,
                              leading=9)

        doc = SimpleDocTemplate(
            str(path), pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
            topMargin=16 * mm, bottomMargin=16 * mm,
            title=f"{APP_NAME} report", author=APP_NAME,
        )
        story: list = []
        meta = data["meta"]
        story.append(Paragraph(f"{APP_NAME} — network activity report", title))
        story.append(Paragraph(
            f"Generated {meta['generated']} · period {meta['period_label']} · "
            f"interface {meta['interface']} {meta['interface_cidr']} · version {meta['version']}",
            subtitle,
        ))
        story.append(Paragraph(
            "Scope: " + meta["monitoring_scope"] + " Encrypted DNS, VPNs and proxies hide DNS "
            "observations; per-device traffic other than this computer requires packet capture "
            "or an enrolled agent.", body,
        ))

        def make_table(headers: list[str], rows: list[list[str]], widths: list[float] | None = None):
            data_rows = [[Paragraph(f"<b>{html.escape(str(h))}</b>", cell) for h in headers]]
            for row in rows:
                data_rows.append([Paragraph(html.escape(str(c))[:400], cell) for c in row])
            table = Table(data_rows, colWidths=widths, repeatRows=1)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E3EEF1")),
                ("TEXTCOLOR", (0, 0), (-1, 0), dark),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#C9D6DB")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F6FAFB")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ]))
            return table

        summary = data.get("summary")
        if summary:
            story.append(Paragraph("Summary", heading))
            rows = [
                ["Devices online", f"{summary['devices_online']} of {summary['devices_total']}"],
                ["Connections observed", str(summary["connections"])],
                ["DNS queries observed", str(summary["dns_queries"])],
                ["Distinct domains", str(summary["domains"])],
                ["Security findings", str(summary["findings"])],
                ["Alerts", str(summary["alerts"])],
                ["Downloaded", fmt_bytes(summary["download_bytes"])],
                ["Uploaded", fmt_bytes(summary["upload_bytes"])],
            ]
            story.append(make_table(["Metric", "Value"], rows, [70 * mm, 90 * mm]))

        if data.get("devices"):
            story.append(Paragraph("Device inventory", heading))
            rows = [
                [d["name"], d["ip"] or "-", d["mac"], d["vendor"], d["type"], d["os"],
                 d["status"], "yes" if d["trusted"] else "no"]
                for d in data["devices"]
            ]
            story.append(make_table(
                ["Name", "Address", "MAC", "Manufacturer", "Type", "OS estimate", "Status", "Trusted"],
                rows, [26 * mm, 22 * mm, 26 * mm, 26 * mm, 22 * mm, 22 * mm, 14 * mm, 12 * mm],
            ))

        if data.get("domains"):
            story.append(Paragraph("Domain activity", heading))
            rows = [
                [d["domain"], d.get("category", ""), str(d.get("queries", 0)),
                 fmt_ts(d.get("first_seen")), fmt_ts(d.get("last_seen"))]
                for d in data["domains"][:80]
            ]
            story.append(make_table(
                ["Domain", "Category", "Queries", "First seen", "Last seen"],
                rows, [56 * mm, 34 * mm, 16 * mm, 30 * mm, 30 * mm],
            ))

        if data.get("applications"):
            story.append(Paragraph("Application connections", heading))
            rows = [
                [a["application"], a.get("category", ""), str(a["connections"]),
                 fmt_bytes(a["upload"] or 0), fmt_bytes(a["download"] or 0), fmt_ts(a["last_seen"])]
                for a in data["applications"][:80]
            ]
            story.append(make_table(
                ["Application", "Category", "Connections", "Upload", "Download", "Last seen"],
                rows, [44 * mm, 30 * mm, 20 * mm, 22 * mm, 22 * mm, 28 * mm],
            ))

        if data.get("security"):
            story.append(PageBreak())
            story.append(Paragraph("Security findings", heading))
            rows = [
                [f["severity"], f["rule"], f["title"], f["evidence"], f["recommendation"]]
                for f in data["security"][:80]
            ]
            story.append(make_table(
                ["Severity", "Rule", "Finding", "Evidence", "Recommendation"],
                rows, [16 * mm, 22 * mm, 42 * mm, 52 * mm, 34 * mm],
            ))

        if data.get("alerts"):
            story.append(Paragraph("Alert history", heading))
            rows = [
                [fmt_ts(a["ts"]), a["severity"], a["title"], a["body"][:160]]
                for a in data["alerts"][:80]
            ]
            story.append(make_table(
                ["Time", "Severity", "Alert", "Detail"],
                rows, [30 * mm, 18 * mm, 56 * mm, 62 * mm],
            ))

        if data.get("configuration"):
            story.append(Paragraph("Monitoring configuration", heading))
            rows = [[k, str(v)] for k, v in data["configuration"].items()]
            story.append(make_table(["Setting", "Value"], rows, [70 * mm, 90 * mm]))

        story.append(Spacer(1, 8))
        story.append(Paragraph(
            f"Generated by {APP_NAME} {APP_VERSION}. No credentials, cookies, tokens or message "
            "contents are stored or reported.", subtitle,
        ))
        doc.build(story)
