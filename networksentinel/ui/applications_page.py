"""Applications page: which programs connect to the internet."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLineEdit, QVBoxLayout, QWidget

from networksentinel.app.context import AppContext
from networksentinel.core.util import fmt_ago, fmt_bytes, fmt_ts, now_ts
from networksentinel.ui.theme import PALETTE
from networksentinel.widgets.common import (
    BarChart, Card, DataTable, Pill, button, dim, heading, muted,
)


class ApplicationsPage(QWidget):
    device_opened = Signal(int)

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        layout.addWidget(heading(
            "Applications",
            "Programs on managed computers and their internet connections. Application names "
            "come from the operating system's socket table, so they are observed, not inferred.",
        ))

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search application…")
        self.search.textChanged.connect(self.refresh)
        controls.addWidget(self.search, 2)
        self.period = QComboBox()
        for label, value in (("Last hour", 3600), ("Last 24 hours", 86400), ("Last 7 days", 604800)):
            self.period.addItem(label, value)
        self.period.setCurrentIndex(1)
        self.period.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.period)
        self.refresh_button = button("Refresh", "secondary", "refresh", self.refresh)
        controls.addWidget(self.refresh_button)
        layout.addLayout(controls)

        self.status_pill = Pill("—", PALETTE.accent)
        self.note = muted("")
        row = QHBoxLayout()
        row.addWidget(self.status_pill)
        row.addWidget(self.note, 1)
        layout.addLayout(row)

        body = QHBoxLayout()
        body.setSpacing(12)
        table_card = Card("Applications seen connecting")
        self.table = DataTable([
            "Application", "Category", "Connections", "Remote hosts", "Download", "Upload", "Last seen",
        ])
        self.table.column_widths([190, 120, 100, 100, 90, 90, 100])
        self.table.itemSelectionChanged.connect(self._show_connections)
        table_card.body.addWidget(self.table)
        body.addWidget(table_card, 3)

        side = QVBoxLayout()
        side.setSpacing(12)
        self.chart = BarChart("Connections per application")
        side.addWidget(self.chart, 1)
        self.detail_card = Card("Connections of the selected application")
        self.detail = DataTable(["Destination", "Port", "Proto", "State", "Last seen"])
        self.detail.column_widths([190, 60, 60, 90, 90])
        self.detail_card.body.addWidget(self.detail)
        side.addWidget(self.detail_card, 1)
        body.addLayout(side, 2)
        layout.addLayout(body, 1)

        self.footer = dim("")
        layout.addWidget(self.footer)
        self._rows: list[dict] = []

    def refresh(self) -> None:
        seconds = self.period.currentData() or 86400
        since = now_ts() - seconds
        rows = self.context.explorer.applications(since=since, search=self.search.text().strip() or None)
        self._rows = rows
        self.table.set_rows([
            [
                r["application"], r.get("category") or "", f"{r['connections']:,}",
                r.get("remotes") or 0, fmt_bytes(r.get("download")), fmt_bytes(r.get("upload")),
                fmt_ago(r.get("last_seen")),
            ]
            for r in rows
        ])
        self.chart.set_items([
            (r["application"], f"{r['connections']}", r["connections"]) for r in rows[:8]
        ])
        stats = self.context.explorer.stats()
        self.status_pill.set_status(f"{len(rows)} applications · {stats['active']} active sockets",
                                    PALETTE.accent)
        if stats.get("error"):
            self.note.setText(f"Socket table error: {stats['error']}")
        else:
            self.note.setText(
                "Data covers this computer. Remote computers appear here only when a Network "
                "Sentinel agent is installed on them (see Agents)."
            )
        self.footer.setText(
            "Download and upload columns show bytes attributed by the operating system's "
            "per-process counters where available; otherwise 0 B is shown rather than an estimate."
        )

    def _show_connections(self) -> None:
        row = self.table.currentRow()
        if not (0 <= row < len(self._rows)):
            return
        name = self._rows[row]["application"]
        conns = self.context.explorer.query(application=name, limit=120)
        self.detail.set_rows([
            [
                c.get("domain") or c.get("remote_ip"), c.get("remote_port"), c.get("protocol"),
                c.get("state"), fmt_ago(c.get("last_seen")),
            ]
            for c in conns
        ])
        self.detail_card.set_title(f"Connections of {name}")
