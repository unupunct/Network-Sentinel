"""Agents page: optional companion agent for computers you manage."""

from __future__ import annotations

import shutil
from pathlib import Path

from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, QTextEdit, QVBoxLayout, QWidget,
)

from networksentinel import APP_NAME
from networksentinel.app.context import AppContext
from networksentinel.core.paths import resource_path
from networksentinel.core.util import fmt_ago, fmt_ts
from networksentinel.ui.theme import PALETTE
from networksentinel.widgets.common import (
    Card, DataTable, Pill, button, dim, heading, muted,
)


class AgentsPage(QWidget):
    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        layout.addWidget(heading(
            "Agents",
            "The agent is optional. It runs only on computers you administer, is started "
            "explicitly, and can be stopped and uninstalled like any other program.",
        ))

        top = QHBoxLayout()
        top.setSpacing(12)
        status_card = Card("Agent server")
        self.status_pill = Pill("—", PALETTE.text_muted)
        status_card.add_action(self.status_pill)
        self.server_text = muted("")
        status_card.body.addWidget(self.server_text)
        self.addresses = muted("")
        status_card.body.addWidget(self.addresses)
        buttons = QHBoxLayout()
        self.toggle_button = button("Start server", "primary", "play", self._toggle_server)
        buttons.addWidget(self.toggle_button)
        self.token_button = button("Create enrollment token", "secondary", "lock", self._create_token)
        buttons.addWidget(self.token_button)
        buttons.addStretch(1)
        status_card.body.addLayout(buttons)
        self.token_box = QPlainTextEdit()
        self.token_box.setReadOnly(True)
        self.token_box.setMaximumHeight(70)
        self.token_box.setPlaceholderText("Enrollment tokens appear here (valid 30 minutes, single use).")
        status_card.body.addWidget(self.token_box)
        top.addWidget(status_card, 3)

        privacy = Card("What the agent reports")
        body = QTextEdit()
        body.setReadOnly(True)
        body.setHtml(
            "<p>The agent collects, on the computer where it is installed:</p>"
            "<ul>"
            "<li>the process name, local and remote address and state of each socket;</li>"
            "<li>per-interface byte counters and per-process byte counters;</li>"
            "<li>the host name and operating system it runs on.</li>"
            "</ul>"
            "<p>It does <b>not</b> collect keystrokes, clipboard contents, files, screenshots, "
            "browser history, credentials or packet payloads. Traffic to the server is signed with "
            "a per-agent secret and stored locally by the server.</p>"
        )
        privacy.body.addWidget(body)
        top.addWidget(privacy, 2)
        layout.addLayout(top, 1)

        card = Card("Enrolled agents")
        self.table = DataTable(["Agent", "Host", "Address", "Status", "Last report", "Enrolled"])
        self.table.column_widths([150, 150, 130, 90, 130, 130])
        card.body.addWidget(self.table)
        row = QHBoxLayout()
        self.remove_button = button("Remove selected", "danger", "", self._remove)
        row.addWidget(self.remove_button)
        row.addStretch(1)
        card.body.addLayout(row)
        layout.addWidget(card, 2)

        install = Card("Installing the agent")
        self.install_text = QTextEdit()
        self.install_text.setReadOnly(True)
        install.body.addWidget(self.install_text)
        layout.addWidget(install, 1)

        self.refresh()

    def _agent_command(self) -> str:
        status = self.context.agents.status()
        address = (status.get("addresses") or ["<server-address>"])[0]
        port = status.get("port") or 8765
        return f"python -m networksentinel.agent --server http://{address}:{port} --token <TOKEN>"

    def refresh(self) -> None:
        status = self.context.agents.status()
        self.status_pill.set_status(
            "Running" if status["running"] else "Stopped",
            PALETTE.success if status["running"] else PALETTE.text_dim,
        )
        self.server_text.setText(
            f"Listening on {status['host']}:{status['port']} · {status['agents']} agents · "
            f"{status['reports']:,} reports received"
            + (f" · error: {status['error']}" if status.get("error") else "")
        )
        self.addresses.setText(
            "Agents can reach this server at: " + (", ".join(status["addresses"]) or "no address found")
        )
        self.toggle_button.setText("Stop server" if status["running"] else "Start server")
        agents = self.context.agents.list_agents()
        self.table.set_rows([
            [
                a.get("name") or a.get("agent_id", "")[:8],
                a.get("hostname") or "—",
                a.get("remote_addr") or "—",
                (a.get("status") or "").title(),
                fmt_ago(a.get("last_seen")),
                fmt_ts(a.get("enrolled_at")),
            ]
            for a in agents
        ])
        agent_script = resource_path("agent", "sentinel_agent.py")
        self.install_text.setHtml(
            "<b>1.</b> Copy the application folder (or the agent script "
            f"<code>{agent_script.name}</code>) to the target computer.<br>"
            "<b>2.</b> Create an enrollment token above.<br>"
            "<b>3.</b> Run, as the user you want monitored:<br>"
            f"<code>{self._agent_command()}</code><br>"
            "<b>4.</b> The computer appears in Devices with an agent badge; its sockets and "
            "counters start flowing into the dashboard.<br>"
            "<b>Uninstall:</b> stop the process and delete the folder - nothing is left behind "
            "except its own log file, which you can delete too."
        )

    def _toggle_server(self) -> None:
        status = self.context.agents.status()
        if status["running"]:
            self.context.agents.stop()
        else:
            result = self.context.agents.start()
            if not result.get("running"):
                QMessageBox.warning(self, "Agent server",
                                    f"Could not start: {result.get('error')}")
        self.refresh()

    def _create_token(self) -> None:
        token = self.context.agents.create_token()
        status = self.context.agents.status()
        address = (status.get("addresses") or ["<server-address>"])[0]
        self.token_box.setPlainText(
            f"{token}\n\npython -m networksentinel.agent --server http://{address}:{status['port']} "
            f"--token {token}"
        )
        QMessageBox.information(
            self, "Enrollment token",
            "A single-use token valid for 30 minutes has been created. Paste it into the agent "
            "command shown on this page.",
        )

    def _remove(self) -> None:
        row = self.table.currentRow()
        agents = self.context.agents.list_agents()
        if not (0 <= row < len(agents)):
            return
        agent = agents[row]
        answer = QMessageBox.question(
            self, "Remove agent", f"Remove {agent.get('hostname') or agent['agent_id']} from the list?"
        )
        if answer == QMessageBox.Yes:
            self.context.agents.remove_agent(agent["agent_id"])
            self.refresh()
