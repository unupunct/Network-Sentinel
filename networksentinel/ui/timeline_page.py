"""Timeline page: chronological activity for a device or the whole network."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from networksentinel.app.context import AppContext
from networksentinel.core.util import fmt_ts, now_ts
from networksentinel.ui.theme import PALETTE
from networksentinel.widgets.common import (
    Card, DataTable, Pill, button, dim, heading, muted,
)

KIND_COLORS = {
    "connection": PALETTE.accent2,
    "dns": PALETTE.accent,
    "finding": PALETTE.critical,
    "device": PALETTE.violet,
    "agent": PALETTE.success,
}


class TimelinePage(QWidget):
    device_changed = Signal(int)

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        layout.addWidget(heading(
            "Activity timeline",
            "Everything observed for one device or the whole network, in order, with the "
            "source of each observation.",
        ))

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.device = QComboBox()
        self.device.addItem("Whole network", 0)
        self.device.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.device, 2)
        self.period = QComboBox()
        for label, value in (("Last hour", 3600), ("Last 24 hours", 86400), ("Last 7 days", 604800),
                             ("Last 30 days", 2592000)):
            self.period.addItem(label, value)
        self.period.setCurrentIndex(1)
        self.period.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.period)
        self.kind = QComboBox()
        for label, value in (("All events", ""), ("Connections", "connection"), ("DNS", "dns"),
                             ("Findings", "finding"), ("Device events", "device")):
            self.kind.addItem(label, value)
        self.kind.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.kind)
        self.refresh_button = button("Refresh", "secondary", "refresh", self.refresh)
        controls.addWidget(self.refresh_button)
        layout.addLayout(controls)

        self.pill = Pill("—", PALETTE.accent2)
        self.note = muted("")
        row = QHBoxLayout()
        row.addWidget(self.pill)
        row.addWidget(self.note, 1)
        layout.addLayout(row)

        card = Card("Events")
        self.table = DataTable(["Time", "Kind", "Device", "Event", "Detail", "Certainty", "Source"])
        self.table.column_widths([140, 90, 130, 300, 320, 80, 140])
        self.table.cellDoubleClicked.connect(self._open_device)
        card.body.addWidget(self.table)
        layout.addWidget(card, 1)

        layout.addWidget(dim(
            "Observed = read directly from the operating system or a packet. Inferred = a "
            "conclusion drawn by the security analysis from those observations."
        ))
        self._rows: list[dict] = []
        self._devices_loaded = False

    def refresh(self) -> None:
        if not self._devices_loaded:
            for device in self.context.inventory.all_devices():
                self.device.addItem(f"{device.name} ({device.ip or device.mac})", device.id)
            self._devices_loaded = True
        seconds = self.period.currentData() or 86400
        device_id = self.device.currentData() or 0
        kind = self.kind.currentData() or None
        labels = self.context.inventory.label_map()
        if device_id:
            items = self.context.timeline.merged_timeline(device_id, seconds=seconds, limit=600)
            if kind:
                items = [i for i in items if i["kind"] == kind]
        else:
            since = now_ts() - seconds
            items = []
            for row in self.context.db.query(
                "SELECT * FROM events WHERE ts >= ? ORDER BY ts DESC LIMIT 600", (since,)
            ):
                items.append({
                    "ts": row["ts"], "kind": row["kind"], "title": row["title"],
                    "detail": row["detail"], "certainty": row["certainty"],
                    "source": row["source"], "device_id": row["device_id"],
                })
            for row in self.context.db.query(
                "SELECT * FROM findings WHERE ts >= ? ORDER BY ts DESC LIMIT 100", (since,)
            ):
                items.append({
                    "ts": row["ts"], "kind": "finding", "title": f"{row['severity']}: {row['title']}",
                    "detail": row["evidence"], "certainty": "inferred",
                    "source": row["source"], "device_id": row["device_id"],
                })
            if kind:
                items = [i for i in items if i["kind"] == kind]
            items.sort(key=lambda i: i["ts"] or 0, reverse=True)
        self._rows = items
        rows, colors = [], {}
        for index, item in enumerate(items):
            rows.append([
                fmt_ts(item["ts"]),
                item["kind"].title(),
                labels.get(item.get("device_id") or 0, "Network"),
                item.get("title") or "",
                (item.get("detail") or "")[:200],
                (item.get("certainty") or "observed").title(),
                item.get("source") or "",
            ])
            colors[index] = KIND_COLORS.get(item["kind"], PALETTE.text_muted)
        self.table.set_rows(rows, colors)
        self.pill.set_status(f"{len(items)} events", PALETTE.accent2)
        stats = self.context.timeline.stats()
        self.note.setText(f"{stats['events']:,} events stored · {stats['today']:,} in the last 24 hours")

    def _open_device(self, row: int, _column: int) -> None:
        if 0 <= row < len(self._rows):
            device_id = self._rows[row].get("device_id")
            if device_id:
                self.device_changed.emit(int(device_id))
