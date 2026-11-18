"""Live traffic page: metadata capture table and protocol mix."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QLineEdit, QSpinBox, QVBoxLayout, QWidget,
)

from networksentinel.app.context import AppContext
from networksentinel.core.util import fmt_bytes, fmt_ts, now_ts
from networksentinel.ui.theme import PALETTE
from networksentinel.widgets.common import (
    BarChart, Card, DataTable, Pill, availability, button, dim, heading, muted,
)


class TrafficPage(QWidget):
    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        layout.addWidget(heading(
            "Live traffic",
            "Packet metadata only: addresses, ports, protocol, flags, size, DNS questions and "
            "TLS server names. Payloads, credentials and encrypted content are never captured.",
        ))

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by IP, port or protocol…")
        self.search.textChanged.connect(self._apply_filters)
        controls.addWidget(self.search, 2)
        self.protocol = QComboBox()
        self.protocol.addItem("All protocols", "")
        for name in ("TCP", "UDP", "DNS", "TLS", "HTTP", "HTTPS", "QUIC", "ICMP", "DHCP", "ARP", "mDNS", "SSDP"):
            self.protocol.addItem(name, name)
        self.protocol.currentIndexChanged.connect(self._apply_filters)
        controls.addWidget(self.protocol)
        self.direction = QComboBox()
        for label, value in (("Both directions", ""), ("Inbound", "in"), ("Outbound", "out"),
                             ("Local", "local")):
            self.direction.addItem(label, value)
        self.direction.currentIndexChanged.connect(self._apply_filters)
        controls.addWidget(self.direction)
        self.limit = QSpinBox()
        self.limit.setRange(50, 5000)
        self.limit.setSingleStep(100)
        self.limit.setValue(400)
        self.limit.setPrefix("rows ")
        controls.addWidget(self.limit)
        self.capture_button = button("Start capture", "primary", "play", self._toggle_capture)
        controls.addWidget(self.capture_button)
        self.pause_button = button("Pause", "secondary", "pause", self._toggle_pause)
        controls.addWidget(self.pause_button)
        layout.addLayout(controls)

        self.status_pill = Pill("—", PALETTE.text_muted)
        self.note = muted("")
        row = QHBoxLayout()
        row.addWidget(self.status_pill)
        row.addWidget(self.note, 1)
        layout.addLayout(row)

        body = QHBoxLayout()
        body.setSpacing(12)
        table_card = Card("Captured packets")
        self.table = DataTable([
            "Time", "Source", "Sport", "Destination", "Dport", "Proto", "Len", "Dir", "Info",
        ])
        self.table.column_widths([85, 135, 55, 135, 55, 60, 55, 55, 260])
        table_card.body.addWidget(self.table)
        body.addWidget(table_card, 4)

        side = QVBoxLayout()
        side.setSpacing(12)
        self.protocols = BarChart("Protocol distribution")
        side.addWidget(self.protocols, 1)
        self.summary = Card("Capture status")
        self.summary_text = muted("")
        self.summary.body.addWidget(self.summary_text)
        side.addWidget(self.summary, 1)
        body.addLayout(side, 2)
        layout.addLayout(body, 1)

        self.footer = dim(
            "If no capture provider (Npcap on Windows, libpcap on Linux) is installed, capture is "
            "unavailable and this page says so instead of inventing packets."
        )
        layout.addWidget(self.footer)
        self._sync_buttons()

    def _apply_filters(self) -> None:
        self.context.traffic.set_filters(
            protocol=self.protocol.currentData() or None,
            direction=self.direction.currentData() or None,
            search=self.search.text().strip() or None,
        )

    def _toggle_capture(self) -> None:
        status = self.context.traffic.stats()
        if status.get("running"):
            self.context.traffic.stop()
        else:
            iface = self.context.interface
            result = self.context.traffic.start(iface.name if iface else None)
            self.note.setText(str(result.get("reason") or ""))
        self._sync_buttons()

    def _toggle_pause(self) -> None:
        if self.context.traffic.paused:
            self.context.traffic.resume()
        else:
            self.context.traffic.pause()
        self._sync_buttons()

    def _sync_buttons(self) -> None:
        stats = self.context.traffic.stats()
        running = bool(stats.get("running"))
        self.capture_button.setText("Stop capture" if running else "Start capture")
        self.capture_button.setObjectName("Danger" if running else "Primary")
        self.capture_button.style().unpolish(self.capture_button)
        self.capture_button.style().polish(self.capture_button)
        self.pause_button.setText("Resume" if stats.get("paused") else "Pause")
        self.pause_button.setEnabled(running)

    def refresh(self) -> None:
        stats = self.context.traffic.stats()
        if stats.get("running"):
            self.status_pill.set_status(
                f"Capturing on {stats.get('interface') or 'interface'}", PALETTE.success
            )
            self.note.setText(
                f"{stats.get('packets', 0):,} packets · {stats.get('errors', 0)} errors · "
                f"provider {stats.get('provider') or 'scapy'} · {stats.get('ring', 0)} in buffer"
            )
        elif stats.get("available"):
            self.status_pill.set_status("Capture ready", PALETTE.accent2)
            self.note.setText("Capture provider found. Press Start capture to begin.")
        else:
            self.status_pill.set_status("Capture unavailable", PALETTE.warning)
            self.note.setText(stats.get("reason") or "No capture provider available.")

        rows = self.context.traffic.filtered(limit=self.limit.value())
        self.table.set_rows([
            [
                fmt_ts(r.ts, "%H:%M:%S"), r.src_ip, r.src_port, r.dst_ip, r.dst_port,
                r.protocol, r.length, r.direction, (r.info or "")[:120],
            ]
            for r in rows
        ])
        protocols = self.context.traffic.protocol_distribution()
        self.protocols.set_items([(name, f"{count:,}", count) for name, count in protocols[:9]])
        labels = self.context.inventory.label_map()
        self.summary_text.setText(
            f"Interface: {stats.get('interface') or '—'}\n"
            f"Provider: {stats.get('provider') or 'none'}\n"
            f"Packets: {stats.get('packets', 0):,}\n"
            f"Buffer: {stats.get('ring', 0):,} records\n"
            f"Errors: {stats.get('errors', 0)}\n"
            f"Paused: {'yes' if stats.get('paused') else 'no'}"
        )
        self._sync_buttons()
