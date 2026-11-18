"""Settings page: monitoring scope, capture, alerts, retention and privacy."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDoubleSpinBox, QFrame, QGridLayout, QHBoxLayout, QLabel,
    QLineEdit, QMessageBox, QScrollArea, QSpinBox, QVBoxLayout, QWidget,
)

from networksentinel.app.context import AppContext
from networksentinel.core.util import fmt_bytes, fmt_ts
from networksentinel.ui.theme import PALETTE
from networksentinel.widgets.common import (
    Card, Pill, button, dim, divider, heading, kv_row, muted,
)


def _section(title: str, description: str = "") -> tuple[Card, QVBoxLayout]:
    card = Card(title)
    if description:
        card.body.addWidget(muted(description))
    inner = QVBoxLayout()
    inner.setSpacing(6)
    card.body.addLayout(inner)
    return card, inner


class SettingsPage(QWidget):
    interface_changed = Signal(str)
    monitoring_toggled = Signal(bool)

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        header_actions = QWidget()
        ha = QHBoxLayout(header_actions)
        ha.setContentsMargins(0, 0, 0, 0)
        self.save_button = button("Save settings", "primary", "check", self._save)
        ha.addWidget(self.save_button)
        layout.addWidget(heading(
            "Settings",
            "Scope, capture, alerts and retention. Everything is stored on this computer.",
            header_actions,
        ))

        # monitoring scope
        scope, scope_inner = _section(
            "Monitoring scope",
            "Network Sentinel only observes the interface you select here.",
        )
        grid = QGridLayout()
        grid.setSpacing(8)
        grid.addWidget(QLabel("Interface"), 0, 0)
        self.interface_combo = QComboBox()
        for iface in self.context.interfaces.cached:
            label = f"{iface.name} — {iface.ipv4 or 'no address'}"
            if iface.gateway:
                label += f" (gateway {iface.gateway})"
            self.interface_combo.addItem(label, iface.name)
        current = self.context.settings.get("interface")
        index = self.interface_combo.findData(current)
        if index >= 0:
            self.interface_combo.setCurrentIndex(index)
        grid.addWidget(self.interface_combo, 0, 1)
        self.scope_info = muted("")
        grid.addWidget(self.scope_info, 1, 1)
        scope_inner.addLayout(grid)
        self.monitoring_check = QCheckBox("Monitoring active")
        scope_inner.addWidget(self.monitoring_check)
        self.capture_check = QCheckBox("Enable packet capture (metadata only; requires Npcap or libpcap)")
        scope_inner.addWidget(self.capture_check)
        capture_row = QHBoxLayout()
        capture_row.addWidget(QLabel("Capture filter (BPF)"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("e.g. not port 22")
        capture_row.addWidget(self.filter_edit, 1)
        scope_inner.addLayout(capture_row)
        self.capture_status = muted("")
        scope_inner.addWidget(self.capture_status)
        layout.addWidget(scope)

        # intervals
        timing, timing_inner = _section(
            "Polling and discovery",
            "Lower intervals give fresher data and use more CPU.",
        )
        tgrid = QGridLayout()
        tgrid.setSpacing(8)
        self.sample_spin = QSpinBox()
        self.sample_spin.setRange(1, 60)
        self.sample_spin.setSuffix(" s")
        tgrid.addWidget(QLabel("Bandwidth sample interval"), 0, 0)
        tgrid.addWidget(self.sample_spin, 0, 1)
        self.scan_spin = QSpinBox()
        self.scan_spin.setRange(5, 3600)
        self.scan_spin.setSuffix(" s")
        tgrid.addWidget(QLabel("Device rescan interval"), 1, 0)
        tgrid.addWidget(self.scan_spin, 1, 1)
        self.retention_spin = QSpinBox()
        self.retention_spin.setRange(1, 3650)
        self.retention_spin.setSuffix(" days")
        tgrid.addWidget(QLabel("Keep history for"), 2, 0)
        tgrid.addWidget(self.retention_spin, 2, 1)
        self.traffic_limit_spin = QSpinBox()
        self.traffic_limit_spin.setRange(10_000, 5_000_000)
        self.traffic_limit_spin.setSingleStep(10_000)
        tgrid.addWidget(QLabel("Maximum traffic rows"), 3, 0)
        tgrid.addWidget(self.traffic_limit_spin, 3, 1)
        timing_inner.addLayout(tgrid)
        self.purge_button = button("Purge old data now", "secondary", "", self._purge)
        timing_inner.addWidget(self.purge_button)
        layout.addWidget(timing)

        # alerts
        alerts, alerts_inner = _section(
            "Alerts",
            "Which events raise a notification. Thresholds of 0 disable that check.",
        )
        self.alerts_enabled = QCheckBox("Alerts enabled")
        self.desktop_check = QCheckBox("Show desktop notifications")
        self.new_device_check = QCheckBox("New device joined the network")
        self.unknown_device_check = QCheckBox("Unknown (untrusted) device is online")
        self.offline_check = QCheckBox("Device went offline")
        self.agent_offline_check = QCheckBox("Agent stopped reporting")
        self.suspicious_check = QCheckBox("Security finding of High or Critical severity")
        for widget in (self.alerts_enabled, self.desktop_check, self.new_device_check,
                       self.unknown_device_check, self.offline_check, self.agent_offline_check,
                       self.suspicious_check):
            alerts_inner.addWidget(widget)
        agrid = QGridLayout()
        agrid.setSpacing(8)
        self.upload_threshold = QSpinBox()
        self.upload_threshold.setRange(0, 100_000)
        self.upload_threshold.setSuffix(" MB / 10 min")
        agrid.addWidget(QLabel("Upload alert threshold"), 0, 0)
        agrid.addWidget(self.upload_threshold, 0, 1)
        self.download_threshold = QSpinBox()
        self.download_threshold.setRange(0, 1_000_000)
        self.download_threshold.setSuffix(" MB / 10 min")
        agrid.addWidget(QLabel("Download alert threshold"), 1, 0)
        agrid.addWidget(self.download_threshold, 1, 1)
        alerts_inner.addLayout(agrid)
        layout.addWidget(alerts)

        # security
        security, security_inner = _section(
            "Security analysis",
            "Behavioural rules over observed data. Threat intelligence can be extended with your "
            "own indicator list on the Security page.",
        )
        self.security_check = QCheckBox("Run behavioural analysis")
        security_inner.addWidget(self.security_check)
        self.intel_check = QCheckBox("Match destinations against threat intelligence")
        security_inner.addWidget(self.intel_check)
        sgrid = QGridLayout()
        self.port_scan_spin = QSpinBox()
        self.port_scan_spin.setRange(2, 500)
        sgrid.addWidget(QLabel("Distinct ports that count as a scan"), 0, 0)
        sgrid.addWidget(self.port_scan_spin, 0, 1)
        self.failure_spin = QSpinBox()
        self.failure_spin.setRange(2, 500)
        sgrid.addWidget(QLabel("Failed connections that count as a burst"), 1, 0)
        sgrid.addWidget(self.failure_spin, 1, 1)
        security_inner.addLayout(sgrid)
        layout.addWidget(security)

        # agent server
        agent, agent_inner = _section(
            "Agent server",
            "Receives reports from the optional agent on computers you administer.",
        )
        self.agent_check = QCheckBox("Agent server enabled")
        agent_inner.addWidget(self.agent_check)
        agrow = QHBoxLayout()
        agrow.addWidget(QLabel("Port"))
        self.agent_port = QSpinBox()
        self.agent_port.setRange(1024, 65535)
        agrow.addWidget(self.agent_port)
        agrow.addWidget(QLabel("Agent offline after"))
        self.agent_offline_spin = QSpinBox()
        self.agent_offline_spin.setRange(15, 3600)
        self.agent_offline_spin.setSuffix(" s")
        agrow.addWidget(self.agent_offline_spin)
        agrow.addStretch(1)
        agent_inner.addLayout(agrow)
        self.agent_status = muted("")
        agent_inner.addWidget(self.agent_status)
        layout.addWidget(agent)

        # privacy
        privacy, privacy_inner = _section("Privacy")
        self.hostname_check = QCheckBox("Resolve and store device host names (reverse DNS)")
        self.dns_check = QCheckBox("Store observed DNS questions")
        self.remember_check = QCheckBox("Remember window size and last page")
        for widget in (self.hostname_check, self.dns_check, self.remember_check):
            privacy_inner.addWidget(widget)
        privacy_inner.addWidget(dim(
            "Payloads, credentials, cookies, keystrokes and browser history are never collected. "
            "Encrypted traffic is counted, never decrypted."
        ))
        layout.addWidget(privacy)

        # about / data
        about, about_inner = _section("Data and diagnostics")
        self.data_info = muted("")
        about_inner.addWidget(self.data_info)
        row = QHBoxLayout()
        self.reveal_button = button("Open data folder", "secondary", "", self._open_data)
        row.addWidget(self.reveal_button)
        self.reset_button = button("Reset all settings", "danger", "", self._reset)
        row.addWidget(self.reset_button)
        row.addStretch(1)
        about_inner.addLayout(row)
        self.problems = dim("")
        about_inner.addWidget(self.problems)
        layout.addWidget(about)
        layout.addStretch(1)

        self._load()

    # -- data ------------------------------------------------------------
    def _load(self) -> None:
        s = self.context.settings
        self.monitoring_check.setChecked(bool(s.get("monitoring_enabled", True)))
        self.capture_check.setChecked(bool(s.get("capture_enabled", False)))
        self.filter_edit.setText(str(s.get("capture_filter", "") or ""))
        self.sample_spin.setValue(int(s.get("sample_interval", 5)))
        self.scan_spin.setValue(int(s.get("active_scan_interval", 60)))
        self.retention_spin.setValue(int(s.get("retention_days", 30)))
        self.traffic_limit_spin.setValue(int(s.get("traffic_row_limit", 200_000)))
        self.alerts_enabled.setChecked(bool(s.get("alerts_enabled", True)))
        self.desktop_check.setChecked(bool(s.get("desktop_notifications", True)))
        self.new_device_check.setChecked(bool(s.get("alert_new_device", True)))
        self.unknown_device_check.setChecked(bool(s.get("alert_unknown_device", True)))
        self.offline_check.setChecked(bool(s.get("alert_device_offline", False)))
        self.agent_offline_check.setChecked(bool(s.get("alert_agent_offline", True)))
        self.suspicious_check.setChecked(bool(s.get("alert_suspicious", True)))
        self.upload_threshold.setValue(int(s.get("alert_upload_threshold_mb", 500)))
        self.download_threshold.setValue(int(s.get("alert_download_threshold_mb", 2000)))
        self.security_check.setChecked(bool(s.get("security_enabled", True)))
        self.intel_check.setChecked(bool(s.get("threat_intel_enabled", True)))
        self.port_scan_spin.setValue(int(s.get("port_scan_threshold", 12)))
        self.failure_spin.setValue(int(s.get("connection_failure_threshold", 8)))
        self.agent_check.setChecked(bool(s.get("agent_server_enabled", True)))
        self.agent_port.setValue(int(s.get("agent_server_port", 8765)))
        self.agent_offline_spin.setValue(int(s.get("agent_offline_after", 90)))
        self.hostname_check.setChecked(bool(s.get("store_hostnames", True)))
        self.dns_check.setChecked(bool(s.get("store_dns", True)))
        self.remember_check.setChecked(bool(s.get("remember_window", True)))
        self.refresh()

    def refresh(self) -> None:
        info = self.context.interface_info()
        if info.get("available"):
            self.scope_info.setText(
                f"{info['description'] or info['name']} · {info['ipv4']} · {info['cidr']} · "
                f"gateway {info['gateway'] or 'unknown'} · {info['hosts']} usable addresses"
            )
        priv = info.get("privileges") or {}
        capture = info.get("capture") or {}
        self.capture_status.setText(
            f"Capture provider: {'available' if capture.get('available') else 'unavailable'} · "
            f"{capture.get('reason') or 'ready'} · administrator: "
            f"{'yes' if priv.get('is_admin') else 'no'}"
        )
        health = self.context.health()
        self.data_info.setText(
            f"Database: {health['database']} ({fmt_bytes(health['database_bytes'])}) · "
            f"cycles run: {health['cycles']} · last cycle {fmt_ts(health['last_cycle'])}"
        )
        status = self.context.agents.status()
        self.agent_status.setText(
            f"Server {'running' if status['running'] else 'stopped'} · {status['agents']} agents · "
            f"reachable at {', '.join(status['addresses']) or 'no address'}"
        )

    # -- actions ---------------------------------------------------------
    def _save(self) -> None:
        s = self.context.settings
        previous_interface = s.get("interface")
        values = {
            "interface": self.interface_combo.currentData() or "",
            "monitoring_enabled": self.monitoring_check.isChecked(),
            "capture_enabled": self.capture_check.isChecked(),
            "capture_filter": self.filter_edit.text().strip(),
            "sample_interval": self.sample_spin.value(),
            "active_scan_interval": self.scan_spin.value(),
            "retention_days": self.retention_spin.value(),
            "traffic_row_limit": self.traffic_limit_spin.value(),
            "alerts_enabled": self.alerts_enabled.isChecked(),
            "desktop_notifications": self.desktop_check.isChecked(),
            "alert_new_device": self.new_device_check.isChecked(),
            "alert_unknown_device": self.unknown_device_check.isChecked(),
            "alert_device_offline": self.offline_check.isChecked(),
            "alert_agent_offline": self.agent_offline_check.isChecked(),
            "alert_suspicious": self.suspicious_check.isChecked(),
            "alert_upload_threshold_mb": self.upload_threshold.value(),
            "alert_download_threshold_mb": self.download_threshold.value(),
            "security_enabled": self.security_check.isChecked(),
            "threat_intel_enabled": self.intel_check.isChecked(),
            "port_scan_threshold": self.port_scan_spin.value(),
            "connection_failure_threshold": self.failure_spin.value(),
            "agent_server_enabled": self.agent_check.isChecked(),
            "agent_server_port": self.agent_port.value(),
            "agent_offline_after": self.agent_offline_spin.value(),
            "store_hostnames": self.hostname_check.isChecked(),
            "store_dns": self.dns_check.isChecked(),
            "remember_window": self.remember_check.isChecked(),
        }
        s.update(**values)
        problems = s.validated()
        self.problems.setText(
            "Problems: " + ", ".join(f"{k} {v}" for k, v in problems.items()) if problems else "Settings saved."
        )
        if values["interface"] != previous_interface:
            self.interface_changed.emit(values["interface"])
        self.monitoring_toggled.emit(values["monitoring_enabled"])
        if values["capture_enabled"]:
            iface = self.context.interface
            self.context.traffic.start(iface.name if iface else None,
                                       values["capture_filter"] or None)
        else:
            self.context.traffic.stop()
        self.refresh()

    def _purge(self) -> None:
        removed = self.context.purge_old_data()
        total = sum(v for v in removed.values() if isinstance(v, int))
        QMessageBox.information(self, "Purge", f"{total:,} old rows removed.")

    def _open_data(self) -> None:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices

        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.context.db.path.parent)))

    def _reset(self) -> None:
        if QMessageBox.question(self, "Reset settings", "Restore every setting to its default?") == QMessageBox.Yes:
            self.context.settings.reset()
            self._load()
