NETWORK SENTINEL 1.0.0
Professional desktop application for local network visibility.

WHAT IT IS
Network Sentinel is a defensive network monitoring tool for Windows 11 and Linux.
It puts an entire local network under an operator's eyes: which devices are on the
LAN, what they talk to, how much bandwidth they use, which applications open which
sockets, whether anything looks suspicious, and what happened and when.

It combines device inventory, connection exploration, DNS and TLS SNI telemetry,
bandwidth accounting, security detection and reporting into one local-first desktop app.

TECHNICAL HIGHLIGHTS
- Local SQLite database (%LOCALAPPDATA%\NetworkSentinel): settings, history, findings, alerts, audit log.
- Real-time monitoring loop with configurable sample interval, retention and traffic row limits.
- Metadata-only capture: packet headers, ports, flags, DNS questions, TLS SNI. Payloads, credentials, cookies and tokens are never captured, stored or displayed.
- Per-process attribution via OS socket tables (GetExtendedTcpTable on Windows, /proc on Linux).
- Security: behavioural detection + threat intelligence (bundled seed list + custom feed import).
- Reports: self-contained PDF, HTML and JSON from local database telemetry, with automated credential redaction.

FILES
  NetworkSentinel.exe        Portable single-file app (Windows 10/11 x64, no Python install needed)
  NetworkSentinel_Setup.exe  Installer (Start Menu shortcut, optional desktop shortcut, uninstaller)

INSTALL
  Run NetworkSentinel_Setup.exe. It installs per user by default (no administrator rights);
  choose "all users" in the dialog for Program Files. Running a newer setup upgrades in place and
  keeps your data. On uninstall you are asked whether to delete your data.
  Or just run NetworkSentinel.exe from anywhere.

DATA LOCATION
  %LOCALAPPDATA%\NetworkSentinel
    data\                SQLite database, logs
    logs\               rolling log files

PERMISSIONS
  Normal user rights are enough for all monitoring. Windows hides the executable path of some protected
  processes from non-administrators; those appear by name only. Settings > Restart as administrator is optional.
  Raw packet capture needs Npcap (Windows) or libpcap (Linux); without it the app falls back to OS socket tables.

KNOWN LIMITATIONS
  - Packet capture is optional; without Npcap/libpcap the app monitors OS socket tables and interface counters.
  - Linux capture depends on libpcap provider availability.
  - Reports are generated from local telemetry; enrichment sources are optional.

LICENSE
  MIT, see LICENSE.txt.

MORE
  Full documentation, feature list and screenshots: https://github.com/unupunct/Network-Sentinel
