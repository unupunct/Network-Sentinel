"""Security page: findings from behavioural analysis and threat-intel matching."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QTextEdit, QVBoxLayout, QWidget,
)

from networksentinel.app.context import AppContext
from networksentinel.core.util import fmt_ts, now_ts
from networksentinel.ui.theme import PALETTE, severity_color
from networksentinel.widgets.common import (
    Card, DataTable, Pill, StatCard, button, dim, heading, kv_row, muted,
)


class SecurityPage(QWidget):
    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        layout.addWidget(heading(
            "Security findings",
            "Behavioural checks over what this network actually observed. Each finding carries the "
            "evidence it was derived from; nothing is reported without evidence.",
        ))

        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.card_critical = StatCard("Critical", "0", "", PALETTE.critical, "warning")
        self.card_high = StatCard("High", "0", "", PALETTE.warning, "warning")
        self.card_medium = StatCard("Medium", "0", "", PALETTE.accent2, "shield")
        self.card_open = StatCard("Open", "0", "", PALETTE.accent, "eye")
        self.card_intel = StatCard("Threat indicators", "0", "", PALETTE.violet, "lock")
        for card in (self.card_critical, self.card_high, self.card_medium, self.card_open, self.card_intel):
            cards.addWidget(card)
        layout.addLayout(cards)

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.severity = QComboBox()
        self.severity.addItem("All severities", "")
        for name in ("Critical", "High", "Medium", "Low", "Informational"):
            self.severity.addItem(name, name)
        self.severity.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.severity)
        self.period = QComboBox()
        for label, value in (("Last 24 hours", 86400), ("Last 7 days", 604800), ("Last 30 days", 2592000)):
            self.period.addItem(label, value)
        self.period.setCurrentIndex(1)
        self.period.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.period)
        self.run_button = button("Run analysis", "primary", "shield", self._run)
        controls.addWidget(self.run_button)
        self.ack_button = button("Acknowledge", "secondary", "check", self._acknowledge)
        controls.addWidget(self.ack_button)
        self.feed_button = button("Import threat feed", "secondary", "download", self._import_feed)
        controls.addWidget(self.feed_button)
        controls.addStretch(1)
        layout.addLayout(controls)

        body = QHBoxLayout()
        body.setSpacing(12)
        table_card = Card("Findings")
        self.table = DataTable(["Time", "Severity", "Title", "Device", "Confidence", "Source"])
        self.table.column_widths([120, 85, 280, 130, 90, 130])
        self.table.itemSelectionChanged.connect(self._show_detail)
        table_card.body.addWidget(self.table)
        body.addWidget(table_card, 3)

        detail_card = Card("Evidence")
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("Select a finding to read its evidence.")
        detail_card.body.addWidget(self.detail)
        body.addWidget(detail_card, 2)
        layout.addLayout(body, 1)

        self.note = dim("")
        layout.addWidget(self.note)
        self._rows: list[dict] = []

    def refresh(self) -> None:
        counts = self.context.security.counts()
        self.card_critical.set_value(str(counts.get("Critical", 0)), "require attention")
        self.card_high.set_value(str(counts.get("High", 0)), "review soon")
        self.card_medium.set_value(str(counts.get("Medium", 0)), "worth checking")
        self.card_open.set_value(str(self.context.security.open_count()), "unacknowledged")
        stats = self.context.security.stats()
        self.card_intel.set_value(str(stats["threat_indicators"]), stats["threat_source"] or "bundled list")
        seconds = self.period.currentData() or 604800
        rows = self.context.security.findings(
            limit=400, severity=self.severity.currentData() or None, since=now_ts() - seconds
        )
        self._rows = rows
        labels = self.context.inventory.label_map()
        colors = {}
        table_rows = []
        for index, row in enumerate(rows):
            table_rows.append([
                fmt_ts(row["ts"]), row["severity"], row["title"],
                labels.get(row.get("device_id") or 0, "Network"),
                (row.get("confidence") or "Medium"),
                row.get("source") or "analysis",
            ])
            colors[index] = severity_color(row["severity"])
        self.table.set_rows(table_rows, colors)
        self.note.setText(
            f"Last analysis run: {fmt_ts(stats['last_run'])} · {stats['findings']:,} findings stored · "
            f"{stats['created_last_run']} created in the last run. Thresholds are configurable in Settings."
        )

    def _show_detail(self) -> None:
        row = self.table.currentRow()
        if not (0 <= row < len(self._rows)):
            return
        item = self._rows[row]
        parts = [
            f"<b style='color:{severity_color(item['severity'])}'>{item['severity']}</b> — {item['title']}",
            f"<span style='color:{PALETTE.text_muted}'>{fmt_ts(item['ts'])} · "
            f"confidence {item.get('confidence') or 'Medium'} · source {item.get('source') or 'analysis'}</span>",
            "",
            "<b>Evidence</b>",
            (item.get("evidence") or "No evidence text recorded.").replace("\n", "<br>"),
        ]
        if item.get("recommendation"):
            parts += ["", "<b>Recommended action</b>", item["recommendation"]]
        for key, label in (("explanation", "Why this was reported"),
                           ("impact", "Possible impact")):
            if item.get(key):
                parts += ["", f"<b>{label}</b>", str(item[key])]
        self.detail.setHtml("<br>".join(parts))

    def _run(self) -> None:
        result = self.context.security.run()
        self.refresh()
        QMessageBox.information(
            self, "Analysis complete",
            f"{result.get('created', 0)} new findings from {result.get('checks', 0)} checks.",
        )

    def _acknowledge(self) -> None:
        row = self.table.currentRow()
        if 0 <= row < len(self._rows):
            self.context.security.acknowledge(self._rows[row]["id"])
            self.refresh()

    def _import_feed(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(
            self, "Import threat feed", "", "Text or JSON (*.txt *.csv *.json);;All files (*)"
        )
        if not path:
            return
        result = self.context.security.load_threat_feed(path)
        self.refresh()
        QMessageBox.information(
            self, "Threat feed",
            f"{result.get('added', 0)} indicators imported from {result.get('kind', 'file')}.",
        )
