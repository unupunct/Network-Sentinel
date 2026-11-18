"""Topology page: drawn network map of the router and its devices."""

from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget

from networksentinel.app.context import AppContext
from networksentinel.core.util import fmt_ago, fmt_bytes
from networksentinel.ui.theme import PALETTE, device_color
from networksentinel.widgets.common import Card, Pill, button, dim, heading, muted


class NetworkMap(QWidget):
    """Radial map: gateway in the centre, devices around it."""

    device_clicked = Signal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.devices: list = []
        self.online_ids: set[int] = set()
        self.gateway = None
        self._hot: int | None = None
        self.setMouseTracking(True)
        self.setMinimumHeight(420)

    def set_devices(self, devices: list, online_ids: set[int] | None = None) -> None:
        self.gateway = next((d for d in devices if d.is_gateway), None)
        self.devices = [d for d in devices if not d.is_gateway]
        self.online_ids = online_ids or {d.id for d in devices if d.online}
        self.update()

    def _online(self, device) -> bool:
        return device.id in self.online_ids or bool(device.online)

    def _positions(self) -> list[tuple[object, QPointF]]:
        width, height = self.width(), self.height()
        center = QPointF(width / 2, height / 2)
        others = self.devices
        radius_x = max(120.0, width / 2 - 110)
        radius_y = max(100.0, height / 2 - 90)
        positions = []
        count = max(1, len(others))
        for index, device in enumerate(others):
            angle = (2 * math.pi * index / count) - math.pi / 2
            # two rings so many devices stay readable
            ring = 1.0 if count <= 12 else (1.0 if index % 2 == 0 else 0.62)
            x = center.x() + math.cos(angle) * radius_x * ring
            y = center.y() + math.sin(angle) * radius_y * ring
            positions.append((device, QPointF(x, y)))
        return positions

    def paintEvent(self, event):  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor(PALETTE.secondary))
        center = QPointF(self.width() / 2, self.height() / 2)
        positions = self._positions()

        # links
        for device, point in positions:
            pen = QPen(QColor(PALETTE.border), 1.4)
            pen.setStyle(Qt.SolidLine if self._online(device) else Qt.DashLine)
            painter.setPen(pen)
            painter.drawLine(center, point)

        # gateway
        if self.gateway is not None:
            painter.setBrush(QBrush(QColor(PALETTE.panel_alt)))
            painter.setPen(QPen(QColor(PALETTE.accent2), 2))
            rect = QRectF(center.x() - 42, center.y() - 42, 84, 84)
            painter.drawEllipse(rect)
            painter.setPen(QPen(QColor(PALETTE.text)))
            font = QFont()
            font.setPointSize(9)
            font.setBold(True)
            painter.setFont(font)
            painter.drawText(QRectF(center.x() - 40, center.y() - 12, 80, 16),
                             Qt.AlignCenter, "ROUTER")
            painter.setPen(QPen(QColor(PALETTE.text_muted)))
            font.setBold(False)
            font.setPointSize(8)
            painter.setFont(font)
            painter.drawText(QRectF(center.x() - 40, center.y() + 2, 80, 16),
                             Qt.AlignCenter, self.gateway.ip or "gateway")
        else:
            painter.setPen(QPen(QColor(PALETTE.text_dim)))
            painter.drawText(self.rect(), Qt.AlignCenter,
                             "Gateway not identified yet")

        # devices
        for device, point in positions:
            color = QColor(device_color(device.category))
            online = self._online(device)
            if not online:
                color.setAlpha(110)
            radius = 15 if online else 12
            painter.setBrush(QBrush(color.darker(190)))
            painter.setPen(QPen(color, 2 if device.id == self._hot else 1.4))
            painter.drawEllipse(point, radius, radius)
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(point, 4, 4)
            painter.setPen(QPen(QColor(PALETTE.text if online else PALETTE.text_dim)))
            font = QFont()
            font.setPointSize(8)
            painter.setFont(font)
            label = device.name if len(device.name) <= 22 else device.name[:21] + "…"
            painter.drawText(QRectF(point.x() - 70, point.y() + radius + 2, 140, 14),
                             Qt.AlignCenter, label)
            painter.setPen(QPen(QColor(PALETTE.text_dim)))
            painter.drawText(QRectF(point.x() - 70, point.y() + radius + 15, 140, 12),
                             Qt.AlignCenter, device.ip or device.mac)
        painter.end()

    def mouseMoveEvent(self, event):  # noqa: N802
        pos = event.position()
        hot = None
        for device, point in self._positions():
            if (pos - point).manhattanLength() < 34:
                hot = device.id
                break
        if hot != self._hot:
            self._hot = hot
            self.setToolTip(self._tooltip_for(hot))
            self.update()

    def mousePressEvent(self, event):  # noqa: N802
        if self._hot:
            self.device_clicked.emit(self._hot)

    def _tooltip_for(self, device_id: int | None) -> str:
        for device, _p in self._positions():
            if device.id == device_id:
                return (f"{device.name}\n{device.ip or '—'} · {device.mac}\n"
                        f"{device.vendor or 'Unknown manufacturer'} · {device.category}\n"
                        f"Last seen {fmt_ago(device.last_seen)}")
        return ""


class TopologyPage(QWidget):
    device_opened = Signal(int)

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        layout.addWidget(heading(
            "Network topology",
            "The gateway and the devices observed behind it. Click a device to open its details.",
        ))

        self.pill = Pill("—", PALETTE.accent)
        self.note = muted("")
        row = QHBoxLayout()
        row.addWidget(self.pill)
        row.addWidget(self.note, 1)
        layout.addLayout(row)

        card = Card("")
        self.map = NetworkMap()
        self.map.device_clicked.connect(self.device_opened.emit)
        card.body.addWidget(self.map, 1)
        layout.addWidget(card, 1)

        legend = QHBoxLayout()
        legend.setSpacing(10)
        for label, color in (("Online", PALETTE.success), ("Offline", PALETTE.text_dim),
                             ("Router", PALETTE.accent2)):
            item = Pill(label, color)
            legend.addWidget(item)
        legend.addStretch(1)
        layout.addLayout(legend)
        layout.addWidget(dim(
            "Links are logical: every device is shown connected to the gateway because that is how "
            "the traffic is routed. Physical switch ports and Wi-Fi associations are not visible to "
            "an ordinary host and are therefore not drawn."
        ))

    def refresh(self) -> None:
        devices = self.context.inventory.all_devices()
        devices.sort(key=lambda d: (not d.online, d.name.lower()))
        self.map.set_devices(devices)
        online = sum(1 for d in devices if d.online)
        self.pill.set_status(f"{len(devices)} devices · {online} online", PALETTE.accent)
        gateway = next((d for d in devices if d.is_gateway), None)
        self.note.setText(
            f"Gateway {gateway.ip} ({gateway.mac})" if gateway else "Gateway not yet identified"
        )
