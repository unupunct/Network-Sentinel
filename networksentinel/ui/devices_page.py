"""Devices page: inventory, filters and a per-device detail drawer."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox, QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton, QScrollArea,
    QSizePolicy, QSplitter, QTabWidget, QTextEdit, QVBoxLayout, QWidget,
)

from networksentinel.app.context import AppContext
from networksentinel.core.util import fmt_ago, fmt_bytes, fmt_mac, fmt_rate, fmt_ts
from networksentinel.services.inventory_service import Device
from networksentinel.ui.theme import PALETTE, device_color
from networksentinel.widgets.common import (
    Badge, Card, DataTable, Pill, availability, button, dim, heading, kv_row, mono, muted,
)

CATEGORIES = [
    "Windows computer", "Linux computer", "macOS computer", "Android device",
    "iPhone / iPad", "Smart TV", "Printer", "Network equipment", "Server",
    "Gaming console", "IoT device", "Virtual machine", "Unknown",
]


class DeviceDetail(QWidget):
    """Right-hand panel with everything known about one device."""

    changed = Signal()

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        self.device: Device | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        header = QHBoxLayout()
        self.title = QLabel("Select a device")
        self.title.setObjectName("PageTitle")
        self.title.setStyleSheet("font-size: 17px;")
        header.addWidget(self.title, 1)
        self.status = Pill("—", PALETTE.text_muted)
        header.addWidget(self.status)
        layout.addLayout(header)
        self.subtitle = muted("")
        layout.addWidget(self.subtitle)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)

        # overview tab
        overview = QWidget()
        ov = QVBoxLayout(overview)
        ov.setContentsMargins(12, 12, 12, 12)
        ov.setSpacing(6)
        self.facts_box = QVBoxLayout()
        self.facts_box.setSpacing(2)
        ov.addLayout(self.facts_box)
        self.evidence_title = QLabel("EVIDENCE")
        self.evidence_title.setObjectName("CardTitle")
        ov.addWidget(self.evidence_title)
        self.evidence = dim("")
        ov.addWidget(self.evidence)
        ov.addStretch(1)
        self.tabs.addTab(overview, "Overview")

        # edit tab
        edit = QWidget()
        ed = QVBoxLayout(edit)
        ed.setContentsMargins(12, 12, 12, 12)
        ed.setSpacing(7)
        ed.addWidget(QLabel("Display name"))
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Custom name for this device")
        ed.addWidget(self.name_edit)
        ed.addWidget(QLabel("Category"))
        self.category_combo = QComboBox()
        self.category_combo.addItem("(detected)", "")
        for category in CATEGORIES:
            self.category_combo.addItem(category, category)
        ed.addWidget(self.category_combo)
        ed.addWidget(QLabel("Description"))
        self.description_edit = QTextEdit()
        self.description_edit.setPlaceholderText("What is this device? Who owns it?")
        self.description_edit.setMaximumHeight(90)
        ed.addWidget(self.description_edit)
        buttons = QHBoxLayout()
        self.trust_button = button("Mark trusted", "secondary", "check")
        self.trust_button.clicked.connect(self._toggle_trust)
        buttons.addWidget(self.trust_button)
        self.save_button = button("Save", "primary", "check", self._save)
        buttons.addWidget(self.save_button)
        buttons.addStretch(1)
        ed.addLayout(buttons)
        ed.addWidget(dim("Only you can change these values; they are stored locally."))
        ed.addStretch(1)
        self.tabs.addTab(edit, "Edit")

        # connections tab
        self.connections_table = DataTable(["Application", "Destination", "Port", "Proto", "Last seen"])
        self.connections_table.column_widths([140, 170, 60, 55, 80])
        self.tabs.addTab(self.connections_table, "Connections")

        # timeline tab
        self.timeline_table = DataTable(["Time", "Event", "Detail", "Source"])
        self.timeline_table.column_widths([110, 200, 240, 100])
        self.tabs.addTab(self.timeline_table, "Timeline")

        # addresses tab
        self.ips_table = DataTable(["IP address", "First seen", "Last seen"])
        self.ips_table.column_widths([150, 140, 140])
        self.tabs.addTab(self.ips_table, "Addresses")

        footer = QHBoxLayout()
        self.forget_button = button("Forget device", "danger", "", self._forget)
        footer.addWidget(self.forget_button)
        footer.addStretch(1)
        layout.addLayout(footer)

    # -- public ----------------------------------------------------------
    def show_device(self, device_id: int | None) -> None:
        self.device = self.context.inventory.get(device_id) if device_id else None
        self.refresh()

    def refresh(self) -> None:
        device = self.device
        if device is None:
            self.title.setText("Select a device")
            self.subtitle.setText("Pick a device in the list to see its details.")
            self.status.set_status("—", PALETTE.text_muted)
            while self.facts_box.count():
                item = self.facts_box.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
            self.evidence.setText("")
            self.connections_table.set_rows([])
            self.timeline_table.set_rows([])
            self.ips_table.set_rows([])
            return

        # reload from the database so live values stay current
        fresh = self.context.inventory.get(device.id)
        if fresh:
            self.device = device = fresh

        self.title.setText(device.name)
        self.subtitle.setText(
            f"{device.ip or 'no address'} · {fmt_mac(device.mac)} · {device.category}"
        )
        self.status.set_status(
            "Online" if device.online else "Offline",
            PALETTE.success if device.online else PALETTE.text_dim,
        )
        while self.facts_box.count():
            item = self.facts_box.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        usage = next(
            (u for u in self.context.bandwidth.device_usage() if u["device_id"] == device.id), None
        )
        conn_count = self.context.db.scalar(
            "SELECT COUNT(*) FROM connections WHERE device_id = ? AND last_seen >= ?",
            (device.id, 0),
        )
        facts = [
            ("IP address", device.ip or "Unavailable"),
            ("MAC address", fmt_mac(device.mac) or "Unavailable"),
            ("Manufacturer", device.vendor or "Unknown manufacturer"),
            ("Operating system", device.os_label),
            ("Device type", device.category),
            ("Trusted", "Yes" if device.trusted else "No"),
            ("Agent installed", "Yes" if device.is_agent else "No"),
            ("Gateway", "Yes" if device.is_gateway else "No"),
            ("This computer", "Yes" if device.is_self else "No"),
            ("First seen", fmt_ts(device.first_seen)),
            ("Last seen", f"{fmt_ts(device.last_seen)} ({fmt_ago(device.last_seen)})"),
            ("Connections seen", f"{conn_count:,}"),
            (
                "Traffic (measured)",
                f"{fmt_bytes(usage['download_bytes'])} down · {fmt_bytes(usage['upload_bytes'])} up"
                if usage else "Unavailable without capture or agent",
            ),
            ("Discovery source", device.source or "ARP table"),
        ]
        for key, value in facts:
            self.facts_box.addWidget(kv_row(key, value, mono_value=key in ("MAC address", "IP address")))
        self.evidence.setText(
            "\n".join(f"• {item}" for item in device.evidence) or
            "No additional evidence was collected for this device."
        )

        self.name_edit.setText(device.custom_name or "")
        index = self.category_combo.findData(device.custom_category or "")
        self.category_combo.setCurrentIndex(index if index >= 0 else 0)
        self.description_edit.setPlainText(device.description or "")
        self.trust_button.setText("Unmark trusted" if device.trusted else "Mark trusted")

        conns = self.context.explorer.query(device_id=device.id, limit=200)
        self.connections_table.set_rows([
            [
                c.get("application") or "Unattributed",
                c.get("domain") or c.get("remote_ip"),
                c.get("remote_port"),
                c.get("protocol"),
                fmt_ago(c.get("last_seen")),
            ]
            for c in conns
        ])

        timeline = self.context.timeline.merged_timeline(device.id, seconds=7 * 86400, limit=150)
        self.timeline_table.set_rows([
            [fmt_ts(t["ts"]), t["title"], (t.get("detail") or "")[:160], t.get("source") or ""]
            for t in timeline
        ])
        self.ips_table.set_rows([
            [ip["ip"], fmt_ts(ip["first_seen"]), fmt_ts(ip["last_seen"])]
            for ip in self.context.inventory.ips(device.id)
        ])

    # -- actions ---------------------------------------------------------
    def _save(self) -> None:
        if not self.device:
            return
        self.context.inventory.rename(self.device.id, self.name_edit.text())
        self.context.inventory.set_category(self.device.id, self.category_combo.currentData())
        self.context.inventory.set_description(self.device.id, self.description_edit.toPlainText())
        self.changed.emit()
        self.refresh()

    def _toggle_trust(self) -> None:
        if not self.device:
            return
        self.context.inventory.set_trusted(self.device.id, not self.device.trusted)
        self.changed.emit()
        self.refresh()

    def _forget(self) -> None:
        if not self.device:
            return
        from PySide6.QtWidgets import QMessageBox

        answer = QMessageBox.question(
            self, "Forget device",
            f"Remove {self.device.name} and its recorded addresses from the inventory?\n"
            "Historical connection and traffic rows stay in the database.",
        )
        if answer == QMessageBox.Yes:
            self.context.inventory.forget(self.device.id)
            self.device = None
            self.changed.emit()
            self.refresh()


class DevicesPage(QWidget):
    device_opened = Signal(int)

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        layout.addWidget(heading(
            "Devices",
            "Every device seen on this network, with the evidence behind each identification.",
        ))

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search name, IP, MAC, vendor…")
        self.search.textChanged.connect(self.refresh)
        controls.addWidget(self.search, 2)
        self.category_filter = QComboBox()
        self.category_filter.addItem("All categories", "")
        for category in CATEGORIES:
            self.category_filter.addItem(category, category)
        self.category_filter.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.category_filter)
        self.status_filter = QComboBox()
        for label, value in (("All devices", ""), ("Online only", "online"),
                             ("Offline only", "offline"), ("Trusted", "trusted"),
                             ("Untrusted", "untrusted"), ("Agents", "agents")):
            self.status_filter.addItem(label, value)
        self.status_filter.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.status_filter)
        self.rescan_button = button("Rescan", "secondary", "refresh", self._rescan)
        controls.addWidget(self.rescan_button)
        layout.addLayout(controls)

        splitter = QSplitter(Qt.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)

        self.summary_pill = Pill("—", PALETTE.accent)
        summary_row = QHBoxLayout()
        summary_row.addWidget(self.summary_pill)
        self.summary_text = muted("")
        summary_row.addWidget(self.summary_text, 1)
        left_layout.addLayout(summary_row)

        self.table = DataTable([
            "Device", "Address", "MAC", "Manufacturer", "OS", "Type", "Status", "Last seen",
        ])
        self.table.column_widths([150, 120, 140, 130, 110, 130, 80, 90])
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.table.cellDoubleClicked.connect(
            lambda row, _col: self.device_opened.emit(self._devices[row].id)
            if 0 <= row < len(self._devices) else None
        )
        left_layout.addWidget(self.table, 1)
        splitter.addWidget(left)

        self.detail = DeviceDetail(context)
        self.detail.changed.connect(self.refresh)
        detail_scroll = QScrollArea()
        detail_scroll.setWidgetResizable(True)
        detail_scroll.setWidget(self.detail)
        detail_scroll.setMinimumWidth(430)
        splitter.addWidget(detail_scroll)
        splitter.setSizes([820, 480])
        layout.addWidget(splitter, 1)

        self._devices: list[Device] = []
        self._current_id: int | None = None

    # -- data ------------------------------------------------------------
    def _filtered(self) -> list[Device]:
        devices = self.context.inventory.all_devices()
        needle = self.search.text().strip().lower()
        category = self.category_filter.currentData()
        status = self.status_filter.currentData()
        out = []
        for device in devices:
            if needle and needle not in " ".join(filter(None, [
                device.name, device.ip, device.mac, device.vendor, device.hostname,
                device.category, device.os_guess,
            ])).lower():
                continue
            if category and device.category != category:
                continue
            if status == "online" and not device.online:
                continue
            if status == "offline" and device.online:
                continue
            if status == "trusted" and not device.trusted:
                continue
            if status == "untrusted" and device.trusted:
                continue
            if status == "agents" and not device.is_agent:
                continue
            out.append(device)
        out.sort(key=lambda d: (not d.online, d.name.lower()))
        return out

    def refresh(self) -> None:
        devices = self._filtered()
        self._devices = devices
        rows = []
        for device in devices:
            rows.append([
                device.name,
                device.ip or "—",
                device.mac,
                device.vendor or "Unknown",
                device.os_label,
                device.category,
                "Online" if device.online else "Offline",
                fmt_ago(device.last_seen),
            ])
        self.table.set_rows(rows)
        summary = self.context.inventory.summary()
        self.summary_pill.set_status(
            f"{summary['online']} online / {summary['total']} known", PALETTE.accent2
        )
        self.summary_text.setText(
            f"{summary['trusted']} trusted · {summary['untrusted_online']} untrusted online · "
            f"{summary['agents']} with agent"
        )
        # keep selection
        if self._current_id:
            for row, device in enumerate(devices):
                if device.id == self._current_id:
                    self.table.selectRow(row)
                    break
        self.detail.refresh()

    def _selection_changed(self) -> None:
        row = self.table.currentRow()
        if 0 <= row < len(self._devices):
            self._current_id = self._devices[row].id
            self.detail.show_device(self._current_id)

    def open_device(self, device_id: int) -> None:
        self._current_id = device_id
        self.refresh()
        for row, device in enumerate(self._devices):
            if device.id == device_id:
                self.table.selectRow(row)
                break

    def _rescan(self) -> None:
        self.rescan_button.setEnabled(False)
        self.rescan_button.setText("Scanning…")
        try:
            self.context.discovery.scan(self.context.settings.get("interface"))
            self.context.inventory.sync()
        finally:
            self.rescan_button.setEnabled(True)
            self.rescan_button.setText("Rescan")
            self.refresh()
