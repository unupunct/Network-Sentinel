"""Dashboard: live overview of the whole network."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QGridLayout, QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget,
)

from networksentinel.app.context import AppContext
from networksentinel.core.util import fmt_ago, fmt_bytes, fmt_rate, fmt_time, now_ts
from networksentinel.ui.theme import CHART_COLORS, PALETTE, device_color, severity_color
from networksentinel.widgets.common import (
    BarChart, Card, Chart, DataTable, Pill, StatCard, availability, button, dim,
    heading, make_icon, muted,
)


class DashboardPage(QWidget):
    navigate = Signal(str)

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        self._ticks: list[float] = []
        self._down: list[float] = []
        self._up: list[float] = []

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(14)

        # header
        self.status_pill = Pill("Starting", PALETTE.accent)
        self.refresh_button = button("Refresh", "secondary", "refresh", self.refresh)
        header_trailing = QWidget()
        ht = QHBoxLayout(header_trailing)
        ht.setContentsMargins(0, 0, 0, 0)
        ht.setSpacing(8)
        ht.addWidget(self.status_pill)
        ht.addWidget(self.refresh_button)
        layout.addWidget(heading(
            "Network overview",
            "Live view of the devices, destinations and traffic observed on this network.",
            header_trailing,
        ))

        # stat cards
        grid = QGridLayout()
        grid.setSpacing(12)
        self.card_devices = StatCard("Connected devices", "—", "0 active", PALETTE.accent2, "devices")
        self.card_active = StatCard("Active devices", "—", "transferring now", PALETTE.success, "eye")
        self.card_down = StatCard("Download", "—", "current rate", PALETTE.accent, "download")
        self.card_up = StatCard("Upload", "—", "current rate", PALETTE.violet, "upload")
        self.card_today = StatCard("Data today", "—", "down / up", PALETTE.warning, "traffic")
        self.card_suspicious = StatCard("Suspicious", "—", "open findings", PALETTE.critical, "shield")
        self.card_connections = StatCard("Connections", "—", "active sockets", PALETTE.accent2, "link")
        self.card_agents = StatCard("Agents", "—", "enrolled computers", PALETTE.success, "agent")
        for index, card in enumerate((
            self.card_devices, self.card_active, self.card_down, self.card_up,
            self.card_today, self.card_suspicious, self.card_connections, self.card_agents,
        )):
            grid.addWidget(card, index // 4, index % 4)
        layout.addLayout(grid)

        # charts row 1
        charts = QHBoxLayout()
        charts.setSpacing(12)
        self.throughput = Chart("Network throughput", "bytes/s")
        self.throughput.add_curve("download", "Download", PALETTE.accent)
        self.throughput.add_curve("upload", "Upload", PALETTE.violet)
        charts.addWidget(self.throughput, 3)
        self.protocol_chart = BarChart("Traffic by protocol")
        charts.addWidget(self.protocol_chart, 2)
        layout.addLayout(charts, 2)

        # charts row 2
        row2 = QHBoxLayout()
        row2.setSpacing(12)
        self.domains_card = BarChart("Top domains (24 h)")
        row2.addWidget(self.domains_card, 1)
        self.apps_card = BarChart("Most active applications")
        row2.addWidget(self.apps_card, 1)
        self.devices_card = BarChart("Busiest devices")
        row2.addWidget(self.devices_card, 1)
        layout.addLayout(row2, 2)

        # bottom row
        bottom = QHBoxLayout()
        bottom.setSpacing(12)
        events_card = Card("Recent network events")
        self.events = DataTable(["Time", "Device", "Event", "Source"])
        self.events.column_widths([80, 130, 320, 130])
        self.events.setMinimumHeight(210)
        self.events.cellDoubleClicked.connect(lambda r, _c: self._open_event(r))
        events_card.body.addWidget(self.events)
        bottom.addWidget(events_card, 3)

        alerts_card = Card("Recent alerts")
        self.alerts = DataTable(["Time", "Severity", "Title"])
        self.alerts.column_widths([70, 80, 220])
        self.alerts.setMinimumHeight(210)
        alerts_card.body.addWidget(self.alerts)
        bottom.addWidget(alerts_card, 2)
        layout.addLayout(bottom, 2)

        self.note = dim("")
        layout.addWidget(self.note)
        layout.addStretch(1)

        self._device_rows: list[int] = []

    # -- data ------------------------------------------------------------
    def refresh(self) -> None:
        data = self.context.dashboard()
        self.card_devices.set_value(str(data["devices_total"]), f"{data['devices_online']} online · {data['devices_offline']} offline")
        self.card_active.set_value(str(data["devices_transferring"]), f"{data['connections_active']} active connections")
        self.card_down.set_value(fmt_rate(data["download_bps"]), f"peak {fmt_rate(data['peak_download'])}")
        self.card_up.set_value(fmt_rate(data["upload_bps"]), f"peak {fmt_rate(data['peak_upload'])}")
        self.card_today.set_value(fmt_bytes(data["today_download"]), f"upload {fmt_bytes(data['today_upload'])}")
        self.card_suspicious.set_value(str(data["suspicious"]), self._severity_hint(data["findings_by_severity"]))
        self.card_connections.set_value(str(data["connections_active"]), f"{data['dns_today'] or 0} DNS queries today")
        self.card_agents.set_value(str(data["agents_online"]), "enrolled computers reporting")

        self.status_pill.set_status(
            "Monitoring" if data["monitoring"] else "Paused",
            PALETTE.success if data["monitoring"] else PALETTE.warning,
        )

        # throughput history
        self._ticks.append(now_ts())
        self._down.append(float(data["download_bps"] or 0))
        self._up.append(float(data["upload_bps"] or 0))
        if len(self._ticks) > 120:
            self._ticks = self._ticks[-120:]
            self._down = self._down[-120:]
            self._up = self._up[-120:]
        xs = list(range(-len(self._ticks) + 1, 1))
        self.throughput.set_data("download", xs, self._down)
        self.throughput.set_data("upload", xs, self._up)

        protocols = self.context.traffic.protocol_distribution()
        total = sum(count for _p, count in protocols) or 1
        self.protocol_chart.set_items(
            [(name, f"{count:,} · {count * 100 // total}%", count) for name, count in protocols[:7]]
        )
        if not protocols:
            self.protocol_chart.set_items([])

        self.domains_card.set_items([
            (d["domain"], f"{d['queries']} queries", d["queries"]) for d in data["top_domains"]
        ])
        self.apps_card.set_items([
            (a["application"] or "Unattributed", f"{a['connections']} conns", a["connections"])
            for a in data["top_apps"]
        ])
        device_usage = self.context.bandwidth.device_usage()
        if device_usage:
            self.devices_card.set_items([
                (u["name"], fmt_bytes(u["download_bytes"] + u["upload_bytes"]),
                 u["download_bytes"] + u["upload_bytes"])
                for u in device_usage[:6]
            ])
            self.devices_card.set_title("Busiest devices")
        else:
            self.devices_card.set_items([])
            self.devices_card.set_title("Busiest devices (needs capture or agent)")

        # events + alerts
        events = self.context.timeline.events(limit=40)
        labels = self.context.inventory.label_map()
        rows, colors = [], {}
        for index, event in enumerate(events):
            rows.append([
                fmt_time(event["ts"]),
                labels.get(event["device_id"], "—") if event.get("device_id") else "Network",
                event["title"],
                event.get("source") or "",
            ])
            if event.get("certainty") == "inferred":
                colors[index] = PALETTE.warning
        self.events.set_rows(rows, colors)
        self._event_rows = events

        alerts = data["recent_alerts"]
        rows, colors = [], {}
        for index, alert in enumerate(alerts):
            rows.append([fmt_time(alert["ts"]), alert["severity"], alert["title"]])
            colors[index] = severity_color(alert["severity"])
        self.alerts.set_rows(rows, colors)

        capture = data["capture"]
        notes = []
        if not capture.get("running"):
            notes.append(
                f"Packet capture is not running: {capture.get('reason') or 'disabled in Settings'}. "
                "Device, connection, DNS and bandwidth data still come from the operating system."
            )
        if not data["per_device_available"]:
            notes.append(data["per_device_note"])
        self.note.setText("  ".join(notes))

    def _severity_hint(self, counts: dict) -> str:
        parts = [f"{k} {v}" for k, v in counts.items() if v]
        return " · ".join(parts) if parts else "no findings"

    def _open_event(self, row: int) -> None:
        if 0 <= row < len(getattr(self, "_event_rows", [])):
            device_id = self._event_rows[row].get("device_id")
            if device_id:
                self.navigate.emit("devices")
