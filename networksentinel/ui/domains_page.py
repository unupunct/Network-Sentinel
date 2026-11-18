"""Domains page: DNS observations and destination activity."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QLabel, QLineEdit, QVBoxLayout, QWidget,
)

from networksentinel.app.context import AppContext
from networksentinel.core.util import fmt_ago, fmt_ts, now_ts
from networksentinel.ui.theme import PALETTE
from networksentinel.widgets.common import (
    BarChart, Card, DataTable, Pill, availability, button, dim, heading, muted,
)


class DomainsPage(QWidget):
    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        layout.addWidget(heading(
            "Domains & websites",
            "Domains observed through DNS answers and TLS server names. Sites contacted over "
            "encrypted connections without an observed name are listed as Encrypted, never guessed.",
        ))

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search domain…")
        self.search.textChanged.connect(self.refresh)
        controls.addWidget(self.search, 2)
        self.period = QComboBox()
        for label, value in (("Last hour", 3600), ("Last 24 hours", 86400), ("Last 7 days", 604800),
                             ("Last 30 days", 2592000)):
            self.period.addItem(label, value)
        self.period.setCurrentIndex(1)
        self.period.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.period)
        self.category = QComboBox()
        self.category.addItem("All categories", "")
        self.category.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.category)
        layout.addLayout(controls)

        self.status_pill = Pill("—", PALETTE.accent2)
        self.explain = muted("")
        row = QHBoxLayout()
        row.addWidget(self.status_pill)
        row.addWidget(self.explain, 1)
        layout.addLayout(row)

        content = QHBoxLayout()
        content.setSpacing(12)
        table_card = Card("Observed domains")
        self.table = DataTable(["Domain", "Category", "Queries", "Devices", "Last seen", "Clients"])
        self.table.column_widths([250, 140, 80, 70, 150, 190])
        self.table.itemSelectionChanged.connect(self._show_detail)
        table_card.body.addWidget(self.table)
        content.addWidget(table_card, 3)

        side = QVBoxLayout()
        side.setSpacing(12)
        self.top_chart = BarChart("Top domains")
        side.addWidget(self.top_chart, 1)
        self.recent_card = Card("Latest DNS observations")
        self.recent = DataTable(["Time", "Domain", "Type", "Client"])
        self.recent.column_widths([80, 190, 55, 110])
        self.recent_card.body.addWidget(self.recent)
        side.addWidget(self.recent_card, 1)
        content.addLayout(side, 2)
        layout.addLayout(content, 1)

        self.detail = dim("Select a domain to see its observation details.")
        layout.addWidget(self.detail)
        self._rows: list[dict] = []
        self._categories_loaded = False

    def refresh(self) -> None:
        seconds = self.period.currentData() or 86400
        since = now_ts() - seconds
        category = self.category.currentData() or None
        rows = self.context.dns.domains(
            since=since, category=category, search=self.search.text().strip() or None, limit=800
        )
        self._rows = rows
        self.table.set_rows([
            [
                r["domain"], r.get("category") or "", f"{r['queries']:,}", r["devices"],
                fmt_ts(r["last_seen"]), (r.get("clients") or "").replace(",", ", ")[:60],
            ]
            for r in rows
        ])
        self.top_chart.set_items([(r["domain"], f"{r['queries']}", r["queries"]) for r in rows[:7]])
        recent = self.context.dns.recent(60)
        self.recent.set_rows([
            [fmt_ts(r["ts"], "%H:%M:%S"), r["domain"], r["qtype"], r.get("client_ip") or "—"]
            for r in recent
        ])
        stats = self.context.dns.stats()
        self.status_pill.set_status(f"{stats['today']:,} queries today", PALETTE.accent2)
        capture = self.context.traffic.stats()
        self.explain.setText(
            "DNS observations come from passive capture."
            if capture.get("running") else
            "Passive DNS capture is not running; only reverse-DNS names and TLS server names "
            "from active connections are recorded."
        )
        if not self._categories_loaded:
            for name, count in self.context.dns.counts_by_category(since):
                self.category.addItem(f"{name} ({count})", name)
            self._categories_loaded = True

    def _show_detail(self) -> None:
        row = self.table.currentRow()
        if not (0 <= row < len(self._rows)):
            return
        item = self._rows[row]
        self.detail.setText(
            f"{item['domain']} · category {item.get('category') or 'Unknown destination'} · "
            f"{item['queries']} queries between {fmt_ts(item['first_seen'])} and "
            f"{fmt_ts(item['last_seen'])} · clients {item.get('clients') or 'not recorded'}"
        )
