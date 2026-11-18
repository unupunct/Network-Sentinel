"""Main window: sidebar navigation, page stack, status bar, live refresh."""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QButtonGroup, QFrame, QHBoxLayout, QLabel, QMainWindow, QPushButton,
    QScrollArea, QStackedWidget, QStatusBar, QVBoxLayout, QWidget,
)

from networksentinel import APP_NAME, APP_VERSION
from networksentinel.app.context import AppContext
from networksentinel.core.util import fmt_ago, now_ts
from networksentinel.ui.theme import PALETTE
from networksentinel.widgets.common import Pill, app_icon, make_icon

NAV_ITEMS = [
    ("dashboard", "Dashboard", "dashboard"),
    ("devices", "Devices", "devices"),
    ("domains", "Domains", "globe"),
    ("applications", "Applications", "apps"),
    ("traffic", "Live Traffic", "traffic"),
    ("bandwidth", "Bandwidth", "bandwidth"),
    ("timeline", "Timeline", "timeline"),
    ("security", "Security", "shield"),
    ("connections", "Connections", "link"),
    ("topology", "Topology", "topology"),
    ("agents", "Agents", "agent"),
    ("alerts", "Alerts", "bell"),
    ("reports", "Reports", "report"),
    ("settings", "Settings", "settings"),
]


class NavButton(QPushButton):
    def __init__(self, key: str, label: str, icon: str, parent: QWidget | None = None) -> None:
        super().__init__(f"  {label}", parent)
        self.key = key
        self.setObjectName("NavButton")
        self.setCheckable(True)
        self.setIcon(make_icon(icon))
        self.setIconSize(QSize(17, 17))
        self.setCursor(Qt.PointingHandCursor)


class MainWindow(QMainWindow):
    navigate_to = Signal(str)

    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.context = context
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.setWindowIcon(app_icon())
        self.setMinimumSize(1180, 740)
        if context.settings.get("remember_window", True):
            self.resize(
                int(context.settings.get("window_width", 1560)),
                int(context.settings.get("window_height", 960)),
            )
        else:
            self.resize(1560, 960)

        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        root.addWidget(self.stack, 1)

        self.pages: dict[str, QWidget] = {}
        self._build_pages()
        self._build_statusbar()

        start = context.settings.get("last_section", "dashboard")
        self.navigate(start if start in self.pages else "dashboard")

        # Live refresh: pages pull from the services; nothing blocks the GUI.
        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(2000)
        self.refresh_timer.timeout.connect(self.refresh_current)
        self.refresh_timer.start()
        self.status_timer = QTimer(self)
        self.status_timer.setInterval(1000)
        self.status_timer.timeout.connect(self._update_status)
        self.status_timer.start()

    # -- construction ----------------------------------------------------
    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(214)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(12, 16, 12, 12)
        layout.setSpacing(2)

        brand = QHBoxLayout()
        brand.setSpacing(9)
        logo = QLabel()
        logo.setPixmap(app_icon().pixmap(30, 30))
        brand.addWidget(logo)
        text = QVBoxLayout()
        text.setSpacing(0)
        title = QLabel("Network <span style='color:#25D0C0'>Sentinel</span>")
        title.setObjectName("BrandTitle")
        title.setTextFormat(Qt.RichText)
        subtitle = QLabel("NETWORK INTELLIGENCE")
        subtitle.setObjectName("BrandSubtitle")
        text.addWidget(title)
        text.addWidget(subtitle)
        brand.addLayout(text)
        brand.addStretch(1)
        layout.addLayout(brand)
        layout.addSpacing(10)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_buttons: dict[str, NavButton] = {}
        for key, label, icon in NAV_ITEMS:
            button = NavButton(key, label, icon)
            button.clicked.connect(lambda _=False, k=key: self.navigate(k))
            self.nav_group.addButton(button)
            self.nav_buttons[key] = button
            layout.addWidget(button)
        layout.addStretch(1)

        self.alerts_badge = QLabel("")
        self.alerts_badge.setObjectName("SidebarFooter")
        layout.addWidget(self.alerts_badge)

        self.monitor_button = QPushButton("  Pause monitoring")
        self.monitor_button.setObjectName("Ghost")
        self.monitor_button.setIcon(make_icon("pause", PALETTE.text_muted))
        self.monitor_button.setCursor(Qt.PointingHandCursor)
        self.monitor_button.clicked.connect(self._toggle_monitoring)
        layout.addWidget(self.monitor_button)

        footer = QLabel("Local-first. No cloud.\nAuthorised networks only.")
        footer.setObjectName("SidebarFooter")
        layout.addWidget(footer)
        version = QLabel(f"v{APP_VERSION}")
        version.setObjectName("SidebarFooter")
        layout.addWidget(version)
        return sidebar

    def _build_pages(self) -> None:
        from networksentinel.ui.agents_page import AgentsPage
        from networksentinel.ui.alerts_page import AlertsPage
        from networksentinel.ui.applications_page import ApplicationsPage
        from networksentinel.ui.bandwidth_page import BandwidthPage
        from networksentinel.ui.connections_page import ConnectionsPage
        from networksentinel.ui.dashboard_page import DashboardPage
        from networksentinel.ui.devices_page import DevicesPage
        from networksentinel.ui.domains_page import DomainsPage
        from networksentinel.ui.reports_page import ReportsPage
        from networksentinel.ui.security_page import SecurityPage
        from networksentinel.ui.settings_page import SettingsPage
        from networksentinel.ui.timeline_page import TimelinePage
        from networksentinel.ui.topology_page import TopologyPage
        from networksentinel.ui.traffic_page import TrafficPage

        context = self.context
        self.dashboard = DashboardPage(context, self)
        self.devices = DevicesPage(context, self)
        self.domains = DomainsPage(context)
        self.applications = ApplicationsPage(context)
        self.traffic = TrafficPage(context)
        self.bandwidth = BandwidthPage(context)
        self.timeline = TimelinePage(context)
        self.security = SecurityPage(context)
        self.connections = ConnectionsPage(context)
        self.topology = TopologyPage(context)
        self.agents = AgentsPage(context)
        self.alerts = AlertsPage(context)
        self.reports = ReportsPage(context)
        self.settings_page = SettingsPage(context)

        for key, page in (
            ("dashboard", self.dashboard), ("devices", self.devices), ("domains", self.domains),
            ("applications", self.applications), ("traffic", self.traffic),
            ("bandwidth", self.bandwidth), ("timeline", self.timeline),
            ("security", self.security), ("connections", self.connections),
            ("topology", self.topology), ("agents", self.agents), ("alerts", self.alerts),
            ("reports", self.reports), ("settings", self.settings_page),
        ):
            self.pages[key] = page
            self.stack.addWidget(page)

        self.dashboard.navigate.connect(self.navigate)
        self.devices.device_opened.connect(self._open_device)
        self.topology.device_opened.connect(self._open_device)
        self.timeline.device_changed.connect(self._timeline_device_changed)
        self.applications.device_opened.connect(self._open_device)
        self.connections.device_opened.connect(self._open_device)
        self.settings_page.interface_changed.connect(self._on_interface_changed)
        self.settings_page.monitoring_toggled.connect(self._on_monitoring_toggled)

    def _build_statusbar(self) -> None:
        bar = QStatusBar()
        self.setStatusBar(bar)
        self.status_label = QLabel("Starting…")
        bar.addWidget(self.status_label, 1)
        self.capture_pill = Pill("Capture: probing", PALETTE.text_muted)
        bar.addPermanentWidget(self.capture_pill)
        self.agent_pill = Pill("Agents: 0", PALETTE.text_muted)
        bar.addPermanentWidget(self.agent_pill)
        self.iface_label = QLabel("no interface")
        self.iface_label.setObjectName("Muted")
        bar.addPermanentWidget(self.iface_label)
        self._update_status()

    # -- navigation ------------------------------------------------------
    def navigate(self, key: str) -> None:
        page = self.pages.get(key)
        if page is None:
            return
        self.stack.setCurrentWidget(page)
        for name, button in self.nav_buttons.items():
            button.setChecked(name == key)
        self.context.settings.set("last_section", key)
        label = dict((k, l) for k, l, _i in NAV_ITEMS).get(key, key.title())
        self.status_label.setText(label)
        refresh = getattr(page, "refresh", None)
        if callable(refresh):
            try:
                refresh()
            except Exception as exc:  # keep the UI alive whatever a page does
                self.status_label.setText(f"{label}: {exc}")

    def refresh_current(self) -> None:
        page = self.stack.currentWidget()
        refresh = getattr(page, "refresh", None)
        if callable(refresh):
            try:
                refresh()
            except Exception as exc:
                self.status_label.setText(f"Refresh problem: {exc}")
        unread = self.context.alerts.unread_count()
        self.alerts_badge.setText(f"{unread} unread alerts" if unread else "")
        self.alerts_badge.setStyleSheet(
            f"color: {PALETTE.warning if unread else PALETTE.text_dim}; font-size: 10.5px;"
        )

    # -- actions ---------------------------------------------------------
    def _toggle_monitoring(self) -> None:
        enabled = not self.context.monitoring
        self._on_monitoring_toggled(enabled)

    def _on_monitoring_toggled(self, enabled: bool) -> None:
        self.context.set_monitoring(enabled)
        self.monitor_button.setText("  Pause monitoring" if enabled else "  Resume monitoring")
        self.monitor_button.setIcon(make_icon("pause" if enabled else "play", PALETTE.text_muted))
        self.status_label.setText("Monitoring active" if enabled else "Monitoring paused")

    def _on_interface_changed(self, name: str) -> None:
        self.context.select_interface(name)
        self._update_status()
        for page in self.pages.values():
            refresh = getattr(page, "refresh", None)
            if callable(refresh):
                try:
                    refresh()
                except Exception:
                    pass

    def _open_device(self, device_id: int) -> None:
        self.navigate("devices")
        self.devices.open_device(device_id)

    def _timeline_device_changed(self, device_id: int) -> None:
        self.navigate("devices")
        self.devices.open_device(device_id)
        self.devices.tabs.setCurrentIndex(3)

    def _update_status(self) -> None:
        info = self.context.interface_info()
        health = self.context.health()
        if info.get("available"):
            self.iface_label.setText(f"{info['name']} · {info['ipv4']} · {info['cidr']}")
        else:
            self.iface_label.setText("no interface selected")
        capture = health.get("capture") or {}
        if capture.get("running"):
            self.capture_pill.set_status(f"Capture: {capture.get('packets', 0):,} packets", PALETTE.success)
        elif capture.get("available"):
            self.capture_pill.set_status("Capture: ready", PALETTE.accent2)
        else:
            self.capture_pill.set_status("Capture: unavailable", PALETTE.text_dim)
        agents = health.get("agents") or 0
        self.agent_pill.set_status(
            f"Agents: {agents}", PALETTE.success if agents else PALETTE.text_muted
        )
        if not self.context.monitoring:
            self.monitor_button.setText("  Resume monitoring")
            self.monitor_button.setIcon(make_icon("play", PALETTE.text_muted))
        else:
            self.monitor_button.setText("  Pause monitoring")
            self.monitor_button.setIcon(make_icon("pause", PALETTE.text_muted))

    # -- lifecycle -------------------------------------------------------
    def closeEvent(self, event):  # noqa: N802
        if self.context.settings.get("remember_window", True):
            self.context.settings.update(window_width=self.width(), window_height=self.height())
        self.refresh_timer.stop()
        self.status_timer.stop()
        super().closeEvent(event)
