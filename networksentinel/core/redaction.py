"""Secret redaction helpers.

Reports, exports and logs must never contain credentials, cookies, tokens or
private message contents.  Everything written through these helpers is passed
through :func:`redact` first.
"""

from __future__ import annotations

import re

REDACTED = "[redacted]"

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey)\s*[:=]\s*\S+"), r"\1=" + REDACTED),
    (re.compile(r"(?i)\bauthorization\s*:\s*\S+"), "Authorization: " + REDACTED),
    (re.compile(r"(?i)\bcookie\s*:\s*\S+"), "Cookie: " + REDACTED),
    (re.compile(r"(?i)\bset-cookie\s*:\s*\S+"), "Set-Cookie: " + REDACTED),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-+/=]{8,}"), "Bearer " + REDACTED),
    (re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{8,}"), "Basic " + REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), REDACTED),
    (re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"), REDACTED),
    (re.compile(r"\b[0-9a-fA-F]{40,}\b"), REDACTED),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), REDACTED),
]

#: Keys whose values must never be persisted or exported.
SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "set-cookie",
    "private_key",
    "enrollment_secret",
    "agent_secret",
    "session_key",
}


def redact(text: str) -> str:
    """Return *text* with anything that looks like a secret replaced."""
    if not text:
        return text
    out = text
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def redact_mapping(data: dict) -> dict:
    """Return a copy of *data* with sensitive keys removed."""
    cleaned = {}
    for key, value in data.items():
        if str(key).lower() in SENSITIVE_KEYS:
            cleaned[key] = REDACTED
        elif isinstance(value, str):
            cleaned[key] = redact(value)
        elif isinstance(value, dict):
            cleaned[key] = redact_mapping(value)
        elif isinstance(value, list):
            cleaned[key] = [redact_mapping(v) if isinstance(v, dict) else redact(v) if isinstance(v, str) else v for v in value]
        else:
            cleaned[key] = value
    return cleaned


def contains_secret(text: str) -> bool:
    return redact(text) != text
