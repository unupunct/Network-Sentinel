"""Network Sentinel visual theme.

One palette, one QSS string.  Everything in the UI takes its colours from here,
so the application looks the same on Windows 11 and on Linux.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Palette:
    background: str = "#0B1117"
    secondary: str = "#111C24"
    panel: str = "#152430"
    panel_alt: str = "#1B2E3C"
    border: str = "#243B4A"
    accent: str = "#25D0C0"
    accent2: str = "#3DA9FC"
    success: str = "#3DDC97"
    warning: str = "#F7B32B"
    critical: str = "#FF5D5D"
    violet: str = "#A78BFA"
    text: str = "#E8F3F6"
    text_muted: str = "#93AAB6"
    text_dim: str = "#647C89"
    hover: str = "#1F3644"
    selection: str = "#134A50"


PALETTE = Palette()

SEVERITY_COLORS = {
    "Critical": PALETTE.critical,
    "High": PALETTE.warning,
    "Medium": PALETTE.accent2,
    "Low": PALETTE.accent,
    "Informational": PALETTE.text_muted,
    "Unknown": PALETTE.text_dim,
}

DEVICE_COLORS = {
    "Windows computer": PALETTE.accent2,
    "Linux computer": PALETTE.success,
    "macOS computer": PALETTE.violet,
    "Android device": "#7BE495",
    "iPhone / iPad": "#C0C7D6",
    "Smart TV": PALETTE.warning,
    "Printer": "#C8A97E",
    "Network equipment": "#F97316",
    "Server": PALETTE.accent,
    "Gaming console": "#F472B6",
    "IoT device": "#9AE6B4",
    "Virtual machine": PALETTE.text_dim,
    "Unknown": PALETTE.text_muted,
}

CHART_COLORS = [
    PALETTE.accent, PALETTE.accent2, PALETTE.warning, PALETTE.violet,
    PALETTE.success, PALETTE.critical, "#F97316", "#F472B6",
]


def device_color(device_type: str | None) -> str:
    return DEVICE_COLORS.get(device_type or "Unknown", PALETTE.text_muted)


def severity_color(severity: str | None) -> str:
    return SEVERITY_COLORS.get(severity or "Unknown", PALETTE.text_muted)


def stylesheet() -> str:
    p = PALETTE
    return f"""
* {{
    font-family: "Segoe UI Variable", "Segoe UI", "Inter", "Cantarell", "DejaVu Sans", sans-serif;
    font-size: 13px;
    color: {p.text};
}}
QWidget {{
    background-color: {p.background};
    selection-background-color: {p.selection};
    selection-color: {p.text};
}}
QMainWindow, QDialog {{ background-color: {p.background}; }}
QToolTip {{
    background-color: {p.panel};
    color: {p.text};
    border: 1px solid {p.border};
    padding: 6px 8px;
    border-radius: 6px;
}}

/* ---------- Sidebar ---------- */
#Sidebar {{
    background-color: {p.secondary};
    border-right: 1px solid {p.border};
}}
#BrandTitle {{ font-size: 16px; font-weight: 700; letter-spacing: 0.4px; background: transparent; }}
#BrandSubtitle {{ color: {p.text_dim}; font-size: 10px; letter-spacing: 1.6px; background: transparent; }}
#NavButton {{
    text-align: left;
    padding: 9px 12px;
    border: none;
    border-radius: 8px;
    background: transparent;
    color: {p.text_muted};
    font-size: 13px;
}}
#NavButton:hover {{ background-color: {p.hover}; color: {p.text}; }}
#NavButton:checked {{ background-color: {p.panel}; color: {p.accent}; font-weight: 600; }}
#SidebarFooter {{ color: {p.text_dim}; font-size: 10.5px; background: transparent; }}
#NavSection {{ color: {p.text_dim}; font-size: 10px; letter-spacing: 1.4px; padding: 10px 12px 4px; background: transparent; }}

/* ---------- Headings ---------- */
#PageTitle {{ font-size: 21px; font-weight: 700; background: transparent; }}
#PageSubtitle {{ color: {p.text_muted}; font-size: 12.5px; background: transparent; }}
#SectionTitle {{ font-size: 13.5px; font-weight: 600; background: transparent; }}
#Muted {{ color: {p.text_muted}; background: transparent; }}
#Dim {{ color: {p.text_dim}; background: transparent; }}
#AccentText {{ color: {p.accent}; background: transparent; }}
#Mono {{ font-family: "Cascadia Mono", "JetBrains Mono", "Consolas", "DejaVu Sans Mono", monospace; background: transparent; }}
#CardTitle {{ font-size: 11px; letter-spacing: 1.1px; color: {p.text_muted}; background: transparent; }}

/* ---------- Cards ---------- */
#Card {{ background-color: {p.panel}; border: 1px solid {p.border}; border-radius: 14px; }}
#Card:hover {{ border-color: {p.selection}; }}
#StatCard {{ background-color: {p.panel}; border: 1px solid {p.border}; border-radius: 14px; }}
#StatValue {{ font-size: 26px; font-weight: 700; background: transparent; }}
#StatLabel {{ color: {p.text_muted}; font-size: 10.5px; letter-spacing: 1px; background: transparent; }}
#StatHint {{ color: {p.text_dim}; font-size: 10.5px; background: transparent; }}
#Tile {{ background-color: {p.secondary}; border: 1px solid {p.border}; border-radius: 12px; }}

/* ---------- Buttons ---------- */
QPushButton {{
    background-color: {p.panel_alt};
    border: 1px solid {p.border};
    border-radius: 8px;
    padding: 7px 14px;
    color: {p.text};
}}
QPushButton:hover {{ background-color: {p.hover}; border-color: {p.accent}; }}
QPushButton:pressed {{ background-color: {p.selection}; }}
QPushButton:disabled {{ color: {p.text_dim}; background-color: {p.secondary}; }}
QPushButton#Primary {{ background-color: {p.accent}; color: #05221F; border: none; font-weight: 600; }}
QPushButton#Primary:hover {{ background-color: #46E4D4; }}
QPushButton#Primary:disabled {{ background-color: #1C4E4A; color: {p.text_dim}; }}
QPushButton#Secondary {{ background-color: transparent; border: 1px solid {p.accent2}; color: {p.accent2}; }}
QPushButton#Secondary:hover {{ background-color: rgba(61, 169, 252, 0.12); }}
QPushButton#Danger {{ background-color: transparent; border: 1px solid {p.critical}; color: {p.critical}; }}
QPushButton#Danger:hover {{ background-color: rgba(255, 93, 93, 0.14); }}
QPushButton#Ghost {{ background: transparent; border: none; color: {p.text_muted}; padding: 5px 8px; }}
QPushButton#Ghost:hover {{ color: {p.accent}; background-color: {p.hover}; }}
QPushButton#Link {{ background: transparent; border: none; color: {p.accent2}; padding: 0; text-align: left; }}
QPushButton#Link:hover {{ color: {p.accent}; }}

/* ---------- Inputs ---------- */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {{
    background-color: {p.secondary};
    border: 1px solid {p.border};
    border-radius: 8px;
    padding: 6px 10px;
    color: {p.text};
}}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus {{
    border-color: {p.accent};
}}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{ background-color: {p.panel}; border: 1px solid {p.border};
    selection-background-color: {p.selection}; outline: none; }}
QCheckBox, QRadioButton {{ background: transparent; spacing: 8px; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 15px; height: 15px; border: 1px solid {p.border}; border-radius: 4px; background: {p.secondary};
}}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {{ background-color: {p.accent}; border-color: {p.accent}; }}
QRadioButton::indicator {{ border-radius: 7px; }}
QSlider::groove:horizontal {{ height: 4px; background: {p.border}; border-radius: 2px; }}
QSlider::handle:horizontal {{ width: 14px; margin: -6px 0; border-radius: 7px; background: {p.accent}; }}
QSlider::sub-page:horizontal {{ background: {p.accent2}; border-radius: 2px; }}

/* ---------- Tables ---------- */
QTableView, QTreeView, QListWidget {{
    background-color: {p.secondary};
    alternate-background-color: #0F1A21;
    border: 1px solid {p.border};
    border-radius: 10px;
    gridline-color: transparent;
    outline: none;
}}
QTableView::item, QListWidget::item {{ padding: 5px 6px; border: none; }}
QTableView::item:selected, QListWidget::item:selected {{ background-color: {p.selection}; color: {p.text}; }}
QListWidget::item:hover {{ background-color: {p.hover}; }}
QHeaderView::section {{
    background-color: {p.panel};
    color: {p.text_muted};
    padding: 6px 6px;
    border: none;
    border-bottom: 1px solid {p.border};
    font-size: 10.5px;
    letter-spacing: 0.6px;
}}
QTableCornerButton::section {{ background-color: {p.panel}; border: none; }}

/* ---------- Tabs ---------- */
QTabWidget::pane {{ border: 1px solid {p.border}; border-radius: 10px; background-color: {p.secondary}; top: -1px; }}
QTabBar::tab {{ background: transparent; color: {p.text_muted}; padding: 7px 14px; border: none;
    border-bottom: 2px solid transparent; }}
QTabBar::tab:selected {{ color: {p.accent}; border-bottom: 2px solid {p.accent}; }}
QTabBar::tab:hover {{ color: {p.text}; }}

/* ---------- Progress ---------- */
QProgressBar {{ background-color: {p.secondary}; border: 1px solid {p.border}; border-radius: 6px;
    height: 10px; text-align: center; color: {p.text_muted}; font-size: 9px; }}
QProgressBar::chunk {{ background-color: {p.accent}; border-radius: 5px; }}

/* ---------- Scrollbars ---------- */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {p.border}; border-radius: 5px; min-height: 28px; }}
QScrollBar::handle:vertical:hover {{ background: {p.selection}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {p.border}; border-radius: 5px; min-width: 28px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ---------- Misc ---------- */
QSplitter::handle {{ background: {p.border}; }}
QSplitter::handle:horizontal {{ width: 1px; }}
QGroupBox {{ border: 1px solid {p.border}; border-radius: 10px; margin-top: 12px; padding-top: 10px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; color: {p.text_muted}; }}
QStatusBar {{ background: {p.secondary}; color: {p.text_muted}; border-top: 1px solid {p.border}; }}
QStatusBar::item {{ border: none; }}
QMenu {{ background: {p.panel}; border: 1px solid {p.border}; border-radius: 8px; padding: 4px; }}
QMenu::item {{ padding: 6px 20px; border-radius: 6px; }}
QMenu::item:selected {{ background: {p.selection}; }}
QScrollArea {{ border: none; background: transparent; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QTextBrowser {{ background-color: {p.secondary}; border: 1px solid {p.border}; border-radius: 10px; padding: 10px; }}
QMessageBox {{ background-color: {p.panel}; }}
QMessageBox QLabel {{ background: transparent; }}
#Divider {{ background-color: {p.border}; max-height: 1px; min-height: 1px; }}
#Pill {{ border-radius: 8px; padding: 2px 9px; font-size: 10.5px; font-weight: 600;
    background: {p.panel_alt}; color: {p.text_muted}; }}
#Banner {{ border-radius: 10px; background: rgba(255,255,255,0.03); }}
"""
