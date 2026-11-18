"""Connections page: socket-level detail for every observed connection."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QLineEdit, QTextEdit, QVBoxLayout, QWidget,
)

from networksentinel.app.context import AppContext
from networksentinel.core.util import fmt_ago, fmt_bytes, fmt_ts, now_ts
from networksentinel.ui.theme import PALETTE
from networksentinel.widgets.common import (
    Card, DataTable, Pill, button, dim, heading, kv_row, muted,
)


class ConnectionsPage(QWidget):
    device_opened = Signal(int)

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        layout.addWidget(heading(
            "Connections",
            "Every socket Network Sentinel observed, with its process, destination and state. "
            "Encrypted destinations without an observed name stay unlabelled.",
        ))

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search IP, domain or application…")
        self.search.textChanged.connect(self.refresh)
        controls.addWidget(self.search, 2)
        self.protocol = QComboBox()
        self.protocol.addItem("All protocols", "")
        for name in ("TCP", "UDP"):
            self.protocol.addItem(name, name)
        self.protocol.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.protocol)
        self.order = QComboBox()
        for label, value in (("Newest first", "last_seen"), ("Most traffic", "traffic"),
                             ("Remote address", "remote_ip")):
            self.order.addItem(label, value)
        self.order.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.order)
        self.public_only = QComboBox()
        self.public_only.addItem("All destinations", False)
        self.public_only.addItem("Internet only", True)
        self.public_only.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.public_only)
        self.export_button = button("Export CSV", "secondary", "download", self._export)
        controls.addWidget(self.export_button)
        layout.addLayout(controls)

        self.pill = Pill("—", PALETTE.accent2)
        self.note = muted("")
        row = QHBoxLayout()
        row.addWidget(self.pill)
        row.addWidget(self.note, 1)
        layout.addLayout(row)

        body = QHBoxLayout()
        body.setSpacing(12)
        card = Card("Observed connections")
        self.table = DataTable([
            "Last seen", "Application", "Device", "Local", "Remote", "Port", "Proto", "State", "Source",
        ])
        self.table.column_widths([90, 150, 120, 130, 150, 55, 55, 100, 110])
        self.table.itemSelectionChanged.connect(self._show_detail)
        card.body.addWidget(self.table)
        body.addWidget(card, 3)
        detail_card = Card("Connection detail")
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("Select a connection.")
        detail_card.body.addWidget(self.detail)
        body.addWidget(detail_card, 2)
        layout.addLayout(body, 1)

        self.footer = dim("")
        layout.addWidget(self.footer)
        self._rows: list[dict] = []

    def refresh(self) -> None:
        rows = self.context.explorer.query(
            since=0,
            search=self.search.text().strip() or None,
            protocol=self.protocol.currentData() or None,
            public_only=bool(self.public_only.currentData()),
            order=self.order.currentData() or "last_seen",
            limit=800,
        )
        self._rows = rows
        labels = self.context.inventory.label_map()
        self.table.set_rows([
            [
                fmt_ago(r.get("last_seen")),
                r.get("application") or "Unattributed",
                labels.get(r.get("device_id") or 0, "—"),
                f"{r.get('local_ip') or ''}:{r.get('local_port') or ''}",
                r.get("domain") or r.get("remote_ip") or "—",
                r.get("remote_port") or "",
                r.get("protocol") or "",
                r.get("state") or "",
                r.get("source") or "",
            ]
            for r in rows
        ])
        stats = self.context.explorer.stats()
        self.pill.set_status(f"{len(rows)} shown · {stats['active']} active", PALETTE.accent2)
        self.note.setText(
            f"{stats['total']:,} connections stored · {stats['new_connections']:,} new since start"
        )
        self.footer.setText(
            "Local sockets (loopback and LAN) are shown as observed. Remote addresses without a "
            "recorded name appear as the address itself; the application never guesses a website."
        )

    def _show_detail(self) -> None:
        row = self.table.currentRow()
        if not (0 <= row < len(self._rows)):
            return
        item = self._rows[row]
        lines = [
            f"<b>{item.get('application') or 'Unattributed'}</b>",
            f"Process: {item.get('process_path') or 'Unavailable'}",
            f"Local: {item.get('local_ip')}:{item.get('local_port')}",
            f"Remote: {item.get('remote_ip')}:{item.get('remote_port')}",
            f"Protocol / state: {item.get('protocol')} / {item.get('state') or '—'}",
            f"Domain: {item.get('domain') or 'Unavailable (not observed)'}",
            f"Category: {item.get('category') or 'Unknown'}",
            f"First seen: {fmt_ts(item.get('first_seen'))}",
            f"Last seen: {fmt_ts(item.get('last_seen'))}",
            f"Traffic: {fmt_bytes(item.get('download_bytes'))} down · "
            f"{fmt_bytes(item.get('upload_bytes'))} up",
            f"Source: {item.get('source') or 'OS socket table'}",
        ]
        self.detail.setHtml("<br>".join(lines))

    def _export(self) -> None:
        from PySide6.QtWidgets import QFileDialog, QMessageBox

        path, _f = QFileDialog.getSaveFileName(self, "Export connections", "connections.csv",
                                               "CSV (*.csv)")
        if not path:
            return
        import csv

        rows = self.context.explorer.export_rows(since=now_ts() - 7 * 86400)
        if not rows:
            QMessageBox.information(self, "Export", "There is nothing to export yet.")
            return
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        QMessageBox.information(self, "Export", f"{len(rows):,} rows written to {path}")
