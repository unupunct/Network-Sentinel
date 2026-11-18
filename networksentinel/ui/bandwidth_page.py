"""Bandwidth page: throughput history, per-application and per-device usage."""

from __future__ import annotations

from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from networksentinel.app.context import AppContext
from networksentinel.core.util import fmt_bytes, fmt_rate, fmt_ts, now_ts
from networksentinel.ui.theme import PALETTE
from networksentinel.widgets.common import (
    BarChart, Card, Chart, DataTable, Pill, StatCard, dim, heading, muted,
)


class BandwidthPage(QWidget):
    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        layout.addWidget(heading(
            "Bandwidth",
            "Measured throughput of the monitored interface, plus per-process and per-device "
            "usage where the operating system or an agent actually reports it.",
        ))

        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.card_down = StatCard("Download now", "—", "", PALETTE.accent, "download")
        self.card_up = StatCard("Upload now", "—", "", PALETTE.violet, "upload")
        self.card_today = StatCard("Today", "—", "", PALETTE.accent2, "traffic")
        self.card_peak = StatCard("Peak", "—", "", PALETTE.warning, "bandwidth")
        for card in (self.card_down, self.card_up, self.card_today, self.card_peak):
            cards.addWidget(card)
        layout.addLayout(cards)

        controls = QHBoxLayout()
        self.period = QComboBox()
        for label, value in (("Last 15 minutes", 15), ("Last hour", 60), ("Last 6 hours", 360),
                             ("Last 24 hours", 1440)):
            self.period.addItem(label, value)
        self.period.setCurrentIndex(1)
        self.period.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.period)
        controls.addStretch(1)
        self.pill = Pill("—", PALETTE.text_muted)
        controls.addWidget(self.pill)
        layout.addLayout(controls)

        self.chart = Chart("Throughput over time", "bytes/s")
        self.chart.add_curve("download", "Download", PALETTE.accent)
        self.chart.add_curve("upload", "Upload", PALETTE.violet)
        self.chart.setMinimumHeight(230)
        layout.addWidget(self.chart, 2)

        tables = QHBoxLayout()
        tables.setSpacing(12)
        apps_card = Card("Per-application usage (this computer)")
        self.apps = DataTable(["Application", "PID", "Download", "Upload", "Rate"])
        self.apps.column_widths([180, 70, 100, 100, 100])
        apps_card.body.addWidget(self.apps)
        tables.addWidget(apps_card, 1)
        devices_card = Card("Per-device usage")
        self.devices = DataTable(["Device", "Download", "Upload", "Rate", "Source"])
        self.devices.column_widths([160, 100, 100, 100, 120])
        devices_card.body.addWidget(self.devices)
        tables.addWidget(devices_card, 1)
        layout.addLayout(tables, 2)

        self.note = dim("")
        layout.addWidget(self.note)

    def refresh(self) -> None:
        summary = self.context.bandwidth.summary()
        self.card_down.set_value(fmt_rate(summary["download_bps"]), f"interface {summary['interface'] or '—'}")
        self.card_up.set_value(fmt_rate(summary["upload_bps"]), "measured by the OS counters")
        self.card_today.set_value(fmt_bytes(summary["today_download"]),
                                  f"up {fmt_bytes(summary['today_upload'])}")
        self.card_peak.set_value(fmt_rate(summary["peak_download"]),
                                 f"peak up {fmt_rate(summary['peak_upload'])}")

        minutes = self.period.currentData() or 60
        points = self.context.bandwidth.stored_series(minutes=minutes)
        if not points:
            points = self.context.bandwidth.series(minutes=minutes)
        xs = [p["ts"] for p in points]
        if points:
            base = xs[0]
            xs = [(x - base) / 60.0 for x in xs]
        self.chart.set_data("download", xs, [p["download_bps"] for p in points])
        self.chart.set_data("upload", xs, [p["upload_bps"] for p in points])
        self.chart.plot.getAxis("bottom").setLabel("minutes ago", color=PALETTE.text_dim, size="9pt")

        procs = self.context.bandwidth.process_usage(limit=30)
        self.apps.set_rows([
            [p["name"], p["pid"], fmt_bytes(p["download_bytes"]), fmt_bytes(p["upload_bytes"]),
             fmt_rate(p["download_bps"] + p["upload_bps"])]
            for p in procs
        ])
        devices = self.context.bandwidth.device_usage()
        self.devices.set_rows([
            [d["name"], fmt_bytes(d["download_bytes"]), fmt_bytes(d["upload_bytes"]),
             fmt_rate(d["download_bps"] + d["upload_bps"]), d["source"]]
            for d in devices
        ])
        if devices:
            self.pill.set_status(f"{len(devices)} devices with measured traffic", PALETTE.success)
        else:
            self.pill.set_status("per-device traffic unavailable", PALETTE.warning)
        self.note.setText(
            "Interface totals are measured by the operating system. Per-application numbers come "
            "from per-process counters and are therefore this computer only. Per-device numbers "
            "require packet capture or an enrolled agent; without them the table stays empty "
            "instead of showing estimates."
        )
