"""Device activity timeline.

Events are recorded from real observations.  Each event carries a ``certainty``
of ``observed`` (seen directly) or ``inferred`` (derived by a rule), so the UI
can distinguish fact from inference.
"""

from __future__ import annotations

from networksentinel.core.logging import get_logger
from networksentinel.core.util import now_ts

log = get_logger(__name__)

TIME_RANGES = {
    "Last 15 minutes": 15 * 60,
    "Last hour": 3600,
    "Last 6 hours": 6 * 3600,
    "Last 24 hours": 86400,
    "Last 7 days": 7 * 86400,
    "Last 30 days": 30 * 86400,
}


class TimelineService:
    def __init__(self, db, inventory) -> None:
        self.db = db
        self.inventory = inventory

    def record(self, device_id: int | None, kind: str, title: str, detail: str = "",
               certainty: str = "observed", source: str = "observation") -> None:
        self.db.execute(
            "INSERT INTO events(ts, device_id, kind, title, detail, certainty, source) "
            "VALUES(?,?,?,?,?,?,?)",
            (now_ts(), device_id, kind, title, detail, certainty, source),
        )

    def events(self, device_id: int | None = None, seconds: int = 86400,
               kinds: list[str] | None = None, limit: int = 500) -> list[dict]:
        since = now_ts() - seconds
        sql = ["SELECT e.*, d.custom_name AS dev_name, d.hostname AS dev_host, d.ip AS dev_ip,",
               "d.mac AS dev_mac FROM events e LEFT JOIN devices d ON d.id = e.device_id",
               "WHERE e.ts >= ?"]
        params: list = [since]
        if device_id:
            sql.append("AND e.device_id = ?")
            params.append(device_id)
        if kinds:
            placeholders = ",".join("?" for _ in kinds)
            sql.append(f"AND e.kind IN ({placeholders})")
            params.extend(kinds)
        sql.append("ORDER BY e.ts DESC LIMIT ?")
        params.append(limit)
        return [dict(r) for r in self.db.query(" ".join(sql), params)]

    def merged_timeline(self, device_id: int, seconds: int = 86400,
                        limit: int = 400) -> list[dict]:
        """Combine stored events with connections and DNS observations."""
        since = now_ts() - seconds
        items: list[dict] = []
        for row in self.db.query(
            "SELECT * FROM events WHERE device_id = ? AND ts >= ? ORDER BY ts DESC LIMIT ?",
            (device_id, since, limit),
        ):
            items.append(
                {
                    "ts": row["ts"], "kind": row["kind"], "title": row["title"],
                    "detail": row["detail"], "certainty": row["certainty"] or "observed",
                    "source": row["source"],
                }
            )
        for row in self.db.query(
            "SELECT c.* FROM connections c WHERE c.device_id = ? AND c.first_seen >= ? "
            "ORDER BY c.first_seen DESC LIMIT ?",
            (device_id, since, limit),
        ):
            items.append(
                {
                    "ts": row["first_seen"], "kind": "connection",
                    "title": f"{row['application'] or 'Unattributed'} → {row['domain'] or row['remote_ip']}",
                    "detail": (
                        f"{row['protocol']} {row['remote_ip']}:{row['remote_port']} "
                        f"state {row['state']} · source {row['source'] or 'OS socket table'}"
                    ),
                    "certainty": "observed",
                    "source": row["source"] or "OS socket table",
                }
            )
        for row in self.db.query(
            "SELECT * FROM dns_queries WHERE device_id = ? AND ts >= ? ORDER BY ts DESC LIMIT ?",
            (device_id, since, limit),
        ):
            items.append(
                {
                    "ts": row["ts"], "kind": "dns",
                    "title": f"DNS query: {row['domain']}",
                    "detail": (
                        f"{row['qtype']} · {row['category'] or ''} · "
                        f"answer {row['answer'] or 'not observed'} · {row['source']}"
                    ),
                    "certainty": "observed",
                    "source": row["source"] or "DNS observation",
                }
            )
        for row in self.db.query(
            "SELECT * FROM findings WHERE device_id = ? AND ts >= ? ORDER BY ts DESC LIMIT 50",
            (device_id, since),
        ):
            items.append(
                {
                    "ts": row["ts"], "kind": "finding",
                    "title": f"{row['severity']}: {row['title']}",
                    "detail": row["evidence"], "certainty": "inferred",
                    "source": row["source"] or "security analysis",
                }
            )
        items.sort(key=lambda item: item["ts"] or 0, reverse=True)
        return items[:limit]

    def counts_by_kind(self, device_id: int | None = None, seconds: int = 86400) -> dict[str, int]:
        since = now_ts() - seconds
        sql = "SELECT kind, COUNT(*) FROM events WHERE ts >= ?"
        params: list = [since]
        if device_id:
            sql += " AND device_id = ?"
            params.append(device_id)
        sql += " GROUP BY kind"
        return {row[0]: row[1] for row in self.db.query(sql, params)}

    def stats(self) -> dict:
        return {
            "events": self.db.scalar("SELECT COUNT(*) FROM events"),
            "today": self.db.scalar("SELECT COUNT(*) FROM events WHERE ts >= ?", (now_ts() - 86400,)),
        }
