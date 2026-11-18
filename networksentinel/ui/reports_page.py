"""Reports page: generate PDF, HTML and JSON reports from stored telemetry."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QVBoxLayout, QWidget,
)

from networksentinel.app.context import AppContext
from networksentinel.core.paths import reports_dir
from networksentinel.core.util import fmt_ts, now_ts
from networksentinel.ui.theme import PALETTE
from networksentinel.widgets.common import Card, DataTable, Pill, button, dim, heading, muted


class ReportsPage(QWidget):
    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        layout.addWidget(heading(
            "Reports",
            "Self-contained reports built from the telemetry in the local database. Choose a "
            "period and a format; nothing leaves this computer.",
        ))

        options = Card("Generate a report")
        row = QHBoxLayout()
        row.setSpacing(8)
        self.period = QComboBox()
        for label, value in (("Last hour", 3600), ("Last 24 hours", 86400), ("Last 7 days", 604800),
                             ("Last 30 days", 2592000)):
            self.period.addItem(label, value)
        self.period.setCurrentIndex(1)
        row.addWidget(QLabel("Period"))
        row.addWidget(self.period)
        self.format = QComboBox()
        for label, value in (("PDF", "pdf"), ("HTML", "html"), ("JSON", "json")):
            self.format.addItem(label, value)
        row.addWidget(QLabel("Format"))
        row.addWidget(self.format)
        self.generate_button = button("Generate", "primary", "report", self._generate)
        row.addWidget(self.generate_button)
        self.open_folder_button = button("Open reports folder", "secondary", "", self._open_folder)
        row.addWidget(self.open_folder_button)
        row.addStretch(1)
        options.body.addLayout(row)
        self.result = muted("")
        options.body.addWidget(self.result)
        layout.addWidget(options)

        card = Card("Generated in this session")
        self.table = DataTable(["Generated", "Period", "Format", "File"])
        self.table.column_widths([140, 140, 70, 520])
        self.table.cellDoubleClicked.connect(self._open_report)
        card.body.addWidget(self.table)
        layout.addWidget(card, 1)

        layout.addWidget(dim(
            "Reports contain device names, addresses, domains and findings from the database. "
            "Fields that look like credentials are redacted automatically."
        ))
        self.pill = Pill(f"Folder: {reports_dir()}", PALETTE.text_muted)
        layout.addWidget(self.pill)

    def refresh(self) -> None:
        history = self.context.reports.history
        self.table.set_rows([
            [fmt_ts(item["ts"]), item["label"], item["fmt"].upper(), item["path"]]
            for item in reversed(history[-50:])
        ])

    def _generate(self) -> None:
        fmt = self.format.currentData() or "pdf"
        seconds = self.period.currentData() or 86400
        self.generate_button.setEnabled(False)
        self.result.setText("Generating…")
        try:
            path = self.context.reports.generate(fmt, seconds)
            self.result.setText(f"Report written to {path}")
            self.refresh()
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
        except Exception as exc:
            self.result.setText(f"Report failed: {exc}")
            QMessageBox.warning(self, "Report", f"Could not generate the report:\n{exc}")
        finally:
            self.generate_button.setEnabled(True)

    def _open_report(self, row: int, _column: int) -> None:
        history = self.context.reports.history
        if 0 <= row < len(history):
            path = Path(history[len(history) - 1 - row]["path"])
            if path.exists():
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _open_folder(self) -> None:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(reports_dir())))
