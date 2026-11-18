"""Reusable widgets: icons, cards, stat tiles, pills, charts, tables."""

from __future__ import annotations

from typing import Callable, Iterable

import pyqtgraph as pg
from PySide6.QtCore import QRectF, QSize, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QIcon, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView, QFrame, QHBoxLayout, QHeaderView, QLabel, QPushButton,
    QSizePolicy, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from networksentinel.ui.theme import CHART_COLORS, PALETTE, device_color

pg.setConfigOptions(antialias=True, background=None, foreground=PALETTE.text_muted)


# ---------------------------------------------------------------------------
# Icons drawn with QPainter (no image assets, crisp at any DPI)
# ---------------------------------------------------------------------------

def _icon_pixmap(name: str, size: int = 22, color: str | None = None) -> QPixmap:
    color = color or PALETTE.accent
    pix = QPixmap(size, size)
    pix.fill(Qt.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.Antialiasing)
    pen = QPen(QColor(color), max(1.3, size / 13))
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)
    s = size
    m = s * 0.18

    def line(x1, y1, x2, y2):
        painter.drawLine(int(x1), int(y1), int(x2), int(y2))

    if name == "dashboard":
        for x, y in ((m, m), (s * 0.54, m), (m, s * 0.54), (s * 0.54, s * 0.54)):
            painter.drawRoundedRect(QRectF(x, y, s * 0.28, s * 0.28), 2, 2)
    elif name == "devices":
        painter.drawRoundedRect(QRectF(m, s * 0.22, s * 0.42, s * 0.3), 2, 2)
        line(s * 0.12, s * 0.72, s * 0.52, s * 0.72)
        line(s * 0.32, s * 0.52, s * 0.32, s * 0.72)
        painter.drawRoundedRect(QRectF(s * 0.55, s * 0.45, s * 0.3, s * 0.4), 4, 4)
    elif name == "globe":
        painter.drawEllipse(QRectF(m, m, s - 2 * m, s - 2 * m))
        painter.drawEllipse(QRectF(s * 0.36, m, s * 0.28, s - 2 * m))
        line(m, s * 0.5, s - m, s * 0.5)
    elif name == "apps":
        painter.drawRoundedRect(QRectF(m, m, s * 0.3, s * 0.3), 3, 3)
        painter.drawRoundedRect(QRectF(s * 0.52, m, s * 0.3, s * 0.3), 3, 3)
        painter.drawRoundedRect(QRectF(m, s * 0.52, s * 0.3, s * 0.3), 3, 3)
        painter.setBrush(QColor(color))
        painter.drawEllipse(QRectF(s * 0.56, s * 0.56, s * 0.22, s * 0.22))
    elif name == "traffic":
        path = QPainterPath()
        path.moveTo(m, s * 0.7)
        path.lineTo(s * 0.35, s * 0.42)
        path.lineTo(s * 0.52, s * 0.58)
        path.lineTo(s - m, s * 0.24)
        painter.drawPath(path)
        painter.drawEllipse(QRectF(s * 0.72, s * 0.18, s * 0.16, s * 0.16))
    elif name == "bandwidth":
        painter.drawRoundedRect(QRectF(m, s * 0.55, s * 0.14, s * 0.3), 2, 2)
        painter.drawRoundedRect(QRectF(s * 0.33, s * 0.35, s * 0.14, s * 0.5), 2, 2)
        painter.drawRoundedRect(QRectF(s * 0.56, s * 0.2, s * 0.14, s * 0.65), 2, 2)
        painter.drawRoundedRect(QRectF(s * 0.79, s * 0.45, s * 0.14, s * 0.4), 2, 2)
    elif name == "timeline":
        line(s * 0.2, m, s * 0.2, s - m)
        for y in (0.28, 0.5, 0.72):
            painter.setBrush(QColor(color))
            painter.drawEllipse(QRectF(s * 0.14, s * y - s * 0.05, s * 0.12, s * 0.12))
            line(s * 0.32, s * y, s - m, s * y)
    elif name == "shield":
        path = QPainterPath()
        path.moveTo(s / 2, m * 0.7)
        path.lineTo(s - m, s * 0.3)
        path.lineTo(s - m, s * 0.55)
        path.cubicTo(s - m, s * 0.78, s * 0.7, s * 0.88, s / 2, s - m * 0.6)
        path.cubicTo(s * 0.3, s * 0.88, m, s * 0.78, m, s * 0.55)
        path.lineTo(m, s * 0.3)
        path.closeSubpath()
        painter.drawPath(path)
    elif name == "link":
        painter.drawArc(QRectF(m, s * 0.3, s * 0.42, s * 0.42), 45 * 16, 200 * 16)
        painter.drawArc(QRectF(s * 0.4, s * 0.3, s * 0.42, s * 0.42), 225 * 16, 200 * 16)
        line(s * 0.36, s * 0.5, s * 0.64, s * 0.5)
    elif name == "topology":
        painter.setBrush(QColor(color))
        painter.drawEllipse(QRectF(s * 0.4, s * 0.4, s * 0.2, s * 0.2))
        painter.setBrush(Qt.NoBrush)
        for x, y in ((0.12, 0.12), (0.72, 0.12), (0.12, 0.72), (0.72, 0.72)):
            painter.drawEllipse(QRectF(s * x, s * y, s * 0.16, s * 0.16))
            line(s * 0.5, s * 0.5, s * (x + 0.08), s * (y + 0.08))
    elif name == "bell":
        path = QPainterPath()
        path.moveTo(s * 0.26, s * 0.7)
        path.cubicTo(s * 0.3, s * 0.6, s * 0.28, s * 0.3, s * 0.5, s * 0.26)
        path.cubicTo(s * 0.72, s * 0.3, s * 0.7, s * 0.6, s * 0.74, s * 0.7)
        path.closeSubpath()
        painter.drawPath(path)
        line(s * 0.2, s * 0.7, s * 0.8, s * 0.7)
        painter.setBrush(QColor(color))
        painter.drawEllipse(QRectF(s * 0.44, s * 0.74, s * 0.12, s * 0.12))
    elif name == "report":
        painter.drawRoundedRect(QRectF(s * 0.22, m, s * 0.56, s - 2 * m), 2, 2)
        for y in (0.35, 0.5, 0.65):
            line(s * 0.32, s * y, s * 0.68, s * y)
    elif name == "settings":
        painter.drawEllipse(QRectF(s * 0.3, s * 0.3, s * 0.4, s * 0.4))
        for x1, y1, x2, y2 in ((0.5, 0.08, 0.5, 0.26), (0.5, 0.74, 0.5, 0.92),
                               (0.08, 0.5, 0.26, 0.5), (0.74, 0.5, 0.92, 0.5)):
            line(s * x1, s * y1, s * x2, s * y2)
    elif name == "refresh":
        painter.drawArc(QRectF(m, m, s - 2 * m, s - 2 * m), 40 * 16, 280 * 16)
        line(s * 0.78, s * 0.14, s * 0.78, s * 0.36)
        line(s * 0.78, s * 0.36, s * 0.56, s * 0.36)
    elif name == "play":
        path = QPainterPath()
        path.moveTo(s * 0.3, m)
        path.lineTo(s * 0.82, s / 2)
        path.lineTo(s * 0.3, s - m)
        path.closeSubpath()
        painter.setBrush(QColor(color))
        painter.drawPath(path)
    elif name == "stop":
        painter.setBrush(QColor(color))
        painter.drawRoundedRect(QRectF(s * 0.26, s * 0.26, s * 0.48, s * 0.48), 3, 3)
    elif name == "pause":
        painter.setBrush(QColor(color))
        painter.drawRoundedRect(QRectF(s * 0.28, s * 0.24, s * 0.16, s * 0.52), 2, 2)
        painter.drawRoundedRect(QRectF(s * 0.56, s * 0.24, s * 0.16, s * 0.52), 2, 2)
    elif name == "warning":
        path = QPainterPath()
        path.moveTo(s / 2, m)
        path.lineTo(s - m, s - m)
        path.lineTo(m, s - m)
        path.closeSubpath()
        painter.drawPath(path)
        line(s * 0.5, s * 0.4, s * 0.5, s * 0.62)
        painter.setBrush(QColor(color))
        painter.drawEllipse(QRectF(s * 0.46, s * 0.68, s * 0.08, s * 0.08))
    elif name == "check":
        line(s * 0.18, s * 0.55, s * 0.42, s * 0.78)
        line(s * 0.42, s * 0.78, s * 0.84, s * 0.24)
    elif name == "lock":
        painter.drawRoundedRect(QRectF(m, s * 0.45, s * 0.64, s * 0.4), 3, 3)
        painter.drawArc(QRectF(s * 0.3, m, s * 0.38, s * 0.5), 0, 180 * 16)
    elif name == "search":
        painter.drawEllipse(QRectF(m, m, s * 0.5, s * 0.5))
        line(s * 0.62, s * 0.62, s - m, s - m)
    elif name == "download":
        line(s * 0.5, m, s * 0.5, s * 0.62)
        line(s * 0.3, s * 0.44, s * 0.5, s * 0.64)
        line(s * 0.7, s * 0.44, s * 0.5, s * 0.64)
        line(m, s * 0.8, s - m, s * 0.8)
    elif name == "upload":
        line(s * 0.5, s - m, s * 0.5, s * 0.38)
        line(s * 0.3, s * 0.56, s * 0.5, s * 0.36)
        line(s * 0.7, s * 0.56, s * 0.5, s * 0.36)
        line(m, s * 0.2, s - m, s * 0.2)
    elif name == "eye":
        path = QPainterPath()
        path.moveTo(m, s * 0.5)
        path.cubicTo(s * 0.32, s * 0.2, s * 0.68, s * 0.2, s - m, s * 0.5)
        path.cubicTo(s * 0.68, s * 0.8, s * 0.32, s * 0.8, m, s * 0.5)
        painter.drawPath(path)
        painter.drawEllipse(QRectF(s * 0.4, s * 0.4, s * 0.2, s * 0.2))
    elif name == "agent":
        painter.drawRoundedRect(QRectF(m, s * 0.26, s - 2 * m, s * 0.42), 3, 3)
        line(s * 0.3, s * 0.74, s * 0.7, s * 0.74)
        line(s * 0.5, s * 0.68, s * 0.5, s * 0.74)
        painter.setBrush(QColor(color))
        painter.drawEllipse(QRectF(s * 0.34, s * 0.42, s * 0.1, s * 0.1))
        painter.drawEllipse(QRectF(s * 0.56, s * 0.42, s * 0.1, s * 0.1))
    else:
        painter.drawEllipse(QRectF(m, m, s - 2 * m, s - 2 * m))
    painter.end()
    return pix


def make_icon(name: str, color: str | None = None) -> QIcon:
    icon = QIcon()
    for size in (16, 22, 32, 64):
        icon.addPixmap(_icon_pixmap(name, size, color))
    return icon


def app_icon() -> QIcon:
    """Application icon: a radar shield, drawn with QPainter."""
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pix = QPixmap(size, size)
        pix.fill(Qt.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.Antialiasing)
        s = size
        path = QPainterPath()
        path.moveTo(s * 0.5, s * 0.05)
        path.lineTo(s * 0.92, s * 0.2)
        path.lineTo(s * 0.92, s * 0.52)
        path.cubicTo(s * 0.92, s * 0.76, s * 0.72, s * 0.92, s * 0.5, s * 0.97)
        path.cubicTo(s * 0.28, s * 0.92, s * 0.08, s * 0.76, s * 0.08, s * 0.52)
        path.lineTo(s * 0.08, s * 0.2)
        path.closeSubpath()
        gradient = QLinearGradient(0, 0, s, s)
        gradient.setColorAt(0, QColor(PALETTE.accent))
        gradient.setColorAt(1, QColor(PALETTE.accent2))
        p.setPen(QPen(QBrush(gradient), max(1.0, s * 0.03)))
        p.setBrush(QColor(11, 17, 23, 240))
        p.drawPath(path)
        p.setPen(QPen(QColor(PALETTE.accent), max(1.0, s * 0.028)))
        for i, frac in enumerate((0.30, 0.48, 0.66)):
            rect = QRectF(s * (0.5 - frac / 2), s * (0.30 - frac / 2 + 0.04), s * frac, s * frac)
            p.drawArc(rect, 30 * 16, 120 * 16)
        p.setBrush(QColor(PALETTE.accent))
        p.setPen(Qt.NoPen)
        p.drawEllipse(QRectF(s * 0.45, s * 0.5, s * 0.1, s * 0.1))
        p.end()
        icon.addPixmap(pix)
    return icon


# ---------------------------------------------------------------------------
# Small building blocks
# ---------------------------------------------------------------------------

class Pill(QLabel):
    """Rounded status chip."""

    def __init__(self, text: str = "", color: str | None = None, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("Pill")
        self.setAlignment(Qt.AlignCenter)
        self.set_status(text, color or PALETTE.text_muted)

    def set_status(self, text: str, color: str | None = None) -> None:
        color = color or PALETTE.text_muted
        self.setText(text)
        self.setStyleSheet(
            f"background: rgba(255,255,255,0.05); color: {color}; border: 1px solid {color};"
            "border-radius: 8px; padding: 2px 9px; font-size: 10.5px; font-weight: 600;"
        )


class StatCard(QFrame):
    """Dashboard metric tile."""

    def __init__(self, label: str, value: str = "—", hint: str = "",
                 color: str | None = None, icon: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("StatCard")
        self._color = color or PALETTE.accent
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 11, 14, 11)
        layout.setSpacing(3)
        top = QHBoxLayout()
        top.setSpacing(6)
        self.label = QLabel(label.upper())
        self.label.setObjectName("StatLabel")
        top.addWidget(self.label)
        top.addStretch(1)
        if icon:
            icon_label = QLabel()
            icon_label.setPixmap(_icon_pixmap(icon, 16, self._color))
            top.addWidget(icon_label)
        layout.addLayout(top)
        self.value = QLabel(value)
        self.value.setObjectName("StatValue")
        self.value.setStyleSheet(f"color: {self._color};")
        layout.addWidget(self.value)
        self.hint = QLabel(hint)
        self.hint.setObjectName("StatHint")
        layout.addWidget(self.hint)
        self.setMinimumHeight(88)

    def set_value(self, value: str, hint: str | None = None) -> None:
        self.value.setText(value)
        if hint is not None:
            self.hint.setText(hint)


class Card(QFrame):
    """Panel with an optional title row."""

    def __init__(self, title: str = "", parent: QWidget | None = None,
                 margins: tuple[int, int, int, int] = (14, 12, 14, 12)) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(*margins)
        self.body.setSpacing(8)
        self.header = QHBoxLayout()
        self.header.setSpacing(8)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("SectionTitle")
        if title:
            self.header.addWidget(self.title_label)
            self.header.addStretch(1)
            self.body.addLayout(self.header)

    def add_action(self, widget: QWidget) -> None:
        self.header.addWidget(widget)

    def set_title(self, text: str) -> None:
        self.title_label.setText(text)


class Chart(QFrame):
    """pyqtgraph plot styled for the dashboard."""

    def __init__(self, title: str = "", y_label: str = "", parent: QWidget | None = None,
                 fill: bool = True) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 8)
        layout.setSpacing(4)
        self.title = QLabel(title)
        self.title.setObjectName("CardTitle")
        layout.addWidget(self.title)
        self.plot = pg.PlotWidget()
        self.plot.setBackground(None)
        self.plot.showGrid(x=False, y=True, alpha=0.15)
        self.plot.setMouseEnabled(x=False, y=False)
        self.plot.hideButtons()
        self.plot.setMenuEnabled(False)
        axis_pen = pg.mkPen(PALETTE.border)
        for name in ("left", "bottom"):
            axis = self.plot.getAxis(name)
            axis.setPen(axis_pen)
            axis.setTextPen(pg.mkPen(PALETTE.text_dim))
            axis.setStyle(tickFont=None)
        if y_label:
            self.plot.setLabel("left", y_label, color=PALETTE.text_dim, size="9pt")
        self.fill = fill
        self.curves: dict[str, tuple] = {}
        self.legend = None
        layout.addWidget(self.plot, 1)
        self.setMinimumHeight(160)

    def add_curve(self, key: str, name: str, color: str | None = None, width: float = 2.0) -> None:
        color = color or CHART_COLORS[len(self.curves) % len(CHART_COLORS)]
        curve = self.plot.plot([], [], pen=pg.mkPen(color, width=width), name=name)
        brush = None
        if self.fill:
            c = QColor(color)
            c.setAlpha(40)
            brush = pg.mkBrush(c)
            curve.setFillLevel(0)
            curve.setBrush(brush)
        self.curves[key] = (curve, color, name)
        if len(self.curves) > 1:
            if self.legend is None:
                self.legend = self.plot.addLegend(offset=(6, 4), labelTextColor=PALETTE.text_muted)
            self.legend.addItem(curve, name)

    def set_data(self, key: str, xs: Iterable[float], ys: Iterable[float]) -> None:
        if key not in self.curves:
            return
        curve = self.curves[key][0]
        curve.setData(list(xs), list(ys))

    def clear_data(self) -> None:
        for curve, _c, _n in self.curves.values():
            curve.setData([], [])

    def set_title(self, text: str) -> None:
        self.title.setText(text.upper())


class BarChart(QFrame):
    """Horizontal bar list: label, value, share bar.  No plot library needed."""

    def __init__(self, title: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(14, 10, 14, 10)
        self._layout.setSpacing(6)
        self.title = QLabel(title)
        self.title.setObjectName("CardTitle")
        self._layout.addWidget(self.title)
        self._rows: QVBoxLayout = QVBoxLayout()
        self._rows.setSpacing(5)
        self._layout.addLayout(self._rows)
        self._layout.addStretch(1)
        self._empty = QLabel("No data yet")
        self._empty.setObjectName("Dim")
        self._rows.addWidget(self._empty)

    def set_items(self, items: list[tuple[str, str, float]], color: str | None = None) -> None:
        while self._rows.count():
            item = self._rows.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        if not items:
            empty = QLabel("No data yet")
            empty.setObjectName("Dim")
            self._rows.addWidget(empty)
            return
        peak = float(max((i[2] for i in items), default=1.0) or 1.0)
        for index, (label, value_text, value) in enumerate(items):
            row = QWidget()
            row.setStyleSheet("background: transparent;")
            layout = QVBoxLayout(row)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(2)
            head = QHBoxLayout()
            head.setSpacing(6)
            name = QLabel(label)
            name.setStyleSheet("background: transparent; font-size: 12px;")
            amount = QLabel(value_text)
            amount.setStyleSheet(
                f"color: {PALETTE.text_muted}; font-size: 11px; background: transparent;"
            )
            head.addWidget(name, 1)
            head.addWidget(amount)
            layout.addLayout(head)
            bar = QFrame()
            bar.setFixedHeight(5)
            bar.setStyleSheet(f"background: {PALETTE.secondary}; border-radius: 3px;")
            bar_layout = QHBoxLayout(bar)
            bar_layout.setContentsMargins(0, 0, 0, 0)
            bar_layout.setSpacing(0)
            inner = QFrame()
            c = color or CHART_COLORS[index % len(CHART_COLORS)]
            inner.setStyleSheet(f"background: {c}; border-radius: 3px;")
            filled = max(0.02, float(value) / peak)
            bar_layout.addWidget(inner, max(1, int(filled * 1000)))
            bar_layout.addStretch(max(1, int((1.0 - filled) * 1000)))
            layout.addWidget(bar)
            self._rows.addWidget(row)

    def set_title(self, text: str) -> None:
        self.title.setText(text.upper())


class BarChart(QFrame):
    """Horizontal bar list: label, value, share bar.  No plot library needed."""

    def __init__(self, title: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(14, 10, 14, 10)
        self._layout.setSpacing(6)
        self.title = QLabel(title)
        self.title.setObjectName("CardTitle")
        self._layout.addWidget(self.title)
        self._rows: QVBoxLayout = QVBoxLayout()
        self._rows.setSpacing(5)
        self._layout.addLayout(self._rows)
        self._layout.addStretch(1)
        self._empty = QLabel("No data yet")
        self._empty.setObjectName("Dim")
        self._rows.addWidget(self._empty)

    def set_items(self, items: list[tuple[str, str, float]], color: str | None = None) -> None:
        while self._rows.count():
            item = self._rows.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        if not items:
            empty = QLabel("No data yet")
            empty.setObjectName("Dim")
            self._rows.addWidget(empty)
            return
        peak = max((i[2] for i in items), default=1.0) or 1.0
        for index, (label, value_text, value) in enumerate(items):
            row = QWidget()
            row.setStyleSheet("background: transparent;")
            layout = QVBoxLayout(row)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(2)
            head = QHBoxLayout()
            head.setSpacing(6)
            name = QLabel(label)
            name.setStyleSheet("background: transparent; font-size: 12px;")
            amount = QLabel(value_text)
            amount.setStyleSheet(
                f"color: {PALETTE.text_muted}; font-size: 11px; background: transparent;"
            )
            head.addWidget(name, 1)
            head.addWidget(amount)
            layout.addLayout(head)
            bar = QFrame()
            bar.setFixedHeight(5)
            bar.setStyleSheet(f"background: {PALETTE.secondary}; border-radius: 3px;")
            bar_layout = QHBoxLayout(bar)
            bar_layout.setContentsMargins(0, 0, 0, 0)
            bar_layout.setSpacing(0)
            inner = QFrame()
            bar_layout.addWidget(inner, max(1, int((value / peak) * 1000)))
            bar_layout.addStretch(max(1, int((1 - value / peak) * 1000)))
            c = color or CHART_COLORS[index % len(CHART_COLORS)]
            inner.setStyleSheet(f"background: {c}; border-radius: 3px;")
            layout.addWidget(bar)
            self._rows.addWidget(row)

    def set_title(self, text: str) -> None:
        self.title.setText(text.upper())


class BarChart(QFrame):
    """Horizontal bar list: label, value, share bar.  No plot library needed."""

    def __init__(self, title: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(14, 10, 14, 10)
        self._layout.setSpacing(6)
        self.title = QLabel(title)
        self.title.setObjectName("CardTitle")
        self._layout.addWidget(self.title)
        self._rows: QVBoxLayout = QVBoxLayout()
        self._rows.setSpacing(5)
        self._layout.addLayout(self._rows)
        self._layout.addStretch(1)
        self._empty = QLabel("No data yet")
        self._empty.setObjectName("Dim")
        self._rows.addWidget(self._empty)

    def set_items(self, items: list[tuple[str, str, float]], color: str | None = None) -> None:
        while self._rows.count():
            item = self._rows.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        if not items:
            empty = QLabel("No data yet")
            empty.setObjectName("Dim")
            self._rows.addWidget(empty)
            return
        peak = max((i[2] for i in items), default=1.0) or 1.0
        for index, (label, value_text, value) in enumerate(items):
            row = QWidget()
            row.setStyleSheet("background: transparent;")
            layout = QVBoxLayout(row)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(2)
            head = QHBoxLayout()
            head.setSpacing(6)
            name = QLabel(label)
            name.setStyleSheet("background: transparent; font-size: 12px;")
            amount = QLabel(value_text)
            amount.setObjectName("Muted")
            amount.setStyleSheet(f"color: {PALETTE.text_muted}; font-size: 11px; background: transparent;")
            head.addWidget(name, 1)
            head.addWidget(amount)
            layout.addLayout(head)
            bar = QFrame()
            bar.setFixedHeight(5)
            bar.setStyleSheet(f"background: {PALETTE.secondary}; border-radius: 3px;")
            inner = QFrame(bar)
            c = color or CHART_COLORS[index % len(CHART_COLORS)]
            width = max(3, int((value / peak) * 260))
            inner.setStyleSheet(f"background: {c}; border-radius: 3px;")
            inner.setFixedHeight(5)
            inner.setFixedWidth(width)
            layout.addWidget(bar)
            self._rows.addWidget(row)

    def set_title(self, text: str) -> None:
        self.title.setText(text.upper())


class DataTable(QTableWidget):
    """Table configured the way every page needs it."""

    def __init__(self, headers: list[str], parent: QWidget | None = None,
                 stretch_last: bool = True) -> None:
        super().__init__(0, len(headers), parent)
        self.setHorizontalHeaderLabels(headers)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(28)
        self.horizontalHeader().setHighlightSections(False)
        self.horizontalHeader().setStretchLastSection(stretch_last)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.setSortingEnabled(False)
        self.setWordWrap(False)
        self._headers = headers

    def set_rows(self, rows: list[list], colors: dict[int, str] | None = None) -> None:
        """Replace the content; ``colors`` maps row index to a text colour."""
        self.setUpdatesEnabled(False)
        self.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, value in enumerate(row):
                item = self.item(r, c)
                text = "" if value is None else str(value)
                if item is None:
                    item = QTableWidgetItem(text)
                    self.setItem(r, c, item)
                elif item.text() != text:
                    item.setText(text)
                if colors and r in colors:
                    item.setForeground(QColor(colors[r]))
        self.setUpdatesEnabled(True)

    def selected_row_data(self, column: int = 0):
        rows = self.selectionModel().selectedRows() if self.selectionModel() else []
        if not rows:
            return None
        item = self.item(rows[0].row(), column)
        return item.text() if item else None

    def column_widths(self, widths: list[int]) -> None:
        for index, width in enumerate(widths):
            if index < self.columnCount():
                self.setColumnWidth(index, width)


class Badge(QLabel):
    def __init__(self, text: str = "", color: str | None = None, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.set_color(color or PALETTE.accent)
        self.setAlignment(Qt.AlignCenter)

    def set_color(self, color: str) -> None:
        self.setStyleSheet(
            f"background: rgba(255,255,255,0.06); color: {color}; border: 1px solid {color};"
            "border-radius: 7px; padding: 1px 7px; font-size: 10px; font-weight: 600;"
        )


def heading(title: str, subtitle: str = "", trailing: QWidget | None = None) -> QWidget:
    wrapper = QWidget()
    layout = QHBoxLayout(wrapper)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(10)
    text = QVBoxLayout()
    text.setSpacing(1)
    title_label = QLabel(title)
    title_label.setObjectName("PageTitle")
    text.addWidget(title_label)
    if subtitle:
        sub = QLabel(subtitle)
        sub.setObjectName("PageSubtitle")
        sub.setWordWrap(True)
        text.addWidget(sub)
    layout.addLayout(text, 1)
    if trailing is not None:
        layout.addWidget(trailing, 0, Qt.AlignTop)
    return wrapper


def button(text: str, kind: str = "default", icon: str = "",
           on_click: Callable | None = None) -> QPushButton:
    btn = QPushButton(text)
    if icon:
        btn.setIcon(make_icon(icon, "#05221F" if kind == "primary" else PALETTE.accent))
        btn.setIconSize(QSize(15, 15))
    if kind == "primary":
        btn.setObjectName("Primary")
    elif kind == "secondary":
        btn.setObjectName("Secondary")
    elif kind == "danger":
        btn.setObjectName("Danger")
    elif kind == "ghost":
        btn.setObjectName("Ghost")
    btn.setCursor(Qt.PointingHandCursor)
    if on_click:
        btn.clicked.connect(on_click)
    return btn


def divider() -> QFrame:
    line = QFrame()
    line.setObjectName("Divider")
    line.setFixedHeight(1)
    return line


def muted(text: str = "") -> QLabel:
    label = QLabel(text)
    label.setObjectName("Muted")
    label.setWordWrap(True)
    return label


def dim(text: str = "") -> QLabel:
    label = QLabel(text)
    label.setObjectName("Dim")
    label.setWordWrap(True)
    return label


def mono(text: str = "") -> QLabel:
    label = QLabel(text)
    label.setObjectName("Mono")
    label.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return label


def kv_row(key: str, value: str, mono_value: bool = False) -> QWidget:
    widget = QWidget()
    widget.setStyleSheet("background: transparent;")
    layout = QHBoxLayout(widget)
    layout.setContentsMargins(0, 1, 0, 1)
    layout.setSpacing(8)
    key_label = QLabel(key)
    key_label.setObjectName("Muted")
    key_label.setMinimumWidth(140)
    value_label = QLabel(value)
    if mono_value:
        value_label.setObjectName("Mono")
    value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
    value_label.setWordWrap(True)
    layout.addWidget(key_label)
    layout.addWidget(value_label, 1)
    return widget


def availability(text: str) -> QLabel:
    """Standard label for information that cannot be observed."""
    label = QLabel(text)
    label.setStyleSheet(
        f"color: {PALETTE.text_dim}; font-style: italic; background: transparent;"
    )
    return label
