"""Alerts page: notifications raised by the monitoring rules."""

from __future__ import annotations

from PySide6.QtWidgets import QComboBox, QHBoxLayout, QVBoxLayout, QWidget

from networksentinel.app.context import AppContext
from networksentinel.core.util import fmt_ts
from networksentinel.ui.theme import PALETTE, severity_color
from networksentinel.widgets.common import Card, DataTable, Pill, button, dim, heading, muted


class AlertsPage(QWidget):
    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        layout.addWidget(heading(
            "Alerts",
            "Notifications raised by the monitoring rules: new devices, security findings, "
            "bandwidth thresholds and agent state.",
        ))

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.severity = QComboBox()
        self.severity.addItem("All severities", "")
        for name in ("Critical", "High", "Medium", "Low", "Informational"):
            self.severity.addItem(name, name)
        self.severity.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.severity)
        self.unread = QComboBox()
        self.unread.addItem("All alerts", False)
        self.unread.addItem("Unread only", True)
        self.unread.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.unread)
        self.read_button = button("Mark all read", "secondary", "check", self._mark_read)
        controls.addWidget(self.read_button)
        self.clear_button = button("Clear alerts", "danger", "", self._clear)
        controls.addWidget(self.clear_button)
        controls.addStretch(1)
        self.pill = Pill("—", PALETTE.accent2)
        controls.addWidget(self.pill)
        layout.addLayout(controls)

        card = Card("Alert history")
        self.table = DataTable(["Time", "Severity", "Kind", "Title", "Detail"])
        self.table.column_widths([140, 85, 130, 320, 420])
        card.body.addWidget(self.table)
        layout.addWidget(card, 1)
        layout.addWidget(dim(
            "Desktop notifications are sent for Critical and High alerts when enabled in Settings. "
            "Every alert is also kept here."
        ))

    def refresh(self) -> None:
        alerts = self.context.alerts.list(
            limit=500,
            severity=self.severity.currentData() or None,
            unread_only=bool(self.unread.currentData()),
        )
        colors = {}
        rows = []
        for index, alert in enumerate(alerts):
            rows.append([
                fmt_ts(alert["ts"]), alert["severity"], alert.get("kind") or "",
                alert["title"], (alert.get("body") or "")[:220],
            ])
            colors[index] = severity_color(alert["severity"])
        self.table.set_rows(rows, colors)
        unread = self.context.alerts.unread_count()
        self.pill.set_status(f"{len(alerts)} alerts · {unread} unread", PALETTE.accent2)

    def _mark_read(self) -> None:
        self.context.alerts.mark_read()
        self.refresh()

    def _clear(self) -> None:
        from PySide6.QtWidgets import QMessageBox

        if QMessageBox.question(self, "Clear alerts", "Delete the whole alert history?") == QMessageBox.Yes:
            self.context.alerts.clear()
            self.refresh()
