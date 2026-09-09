"""SQLite storage for alerts and time-window traffic statistics.

All queries use parameter binding (never string-formatted SQL) to avoid
injection, even though input in this project is not typically
attacker-controlled text -- it's good practice regardless.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, List, Optional

from .models import Alert

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    rule_name TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    status TEXT NOT NULL DEFAULT 'new',
    note TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts (alert_type);

CREATE TABLE IF NOT EXISTS traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start REAL NOT NULL,
    window_seconds REAL NOT NULL,
    packet_count INTEGER NOT NULL,
    byte_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_traffic_window ON traffic_stats (window_start);
"""


class Database:
    def __init__(self, path: str = "nids.db"):
        self.path = path
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # -- Alerts ---------------------------------------------------------

    def insert_alert(self, alert: Alert) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO alerts
                    (timestamp, alert_type, severity, confidence, rule_name,
                     description, evidence, src_ip, dst_ip, src_port, dst_port,
                     status, note)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.timestamp, alert.alert_type, alert.severity, alert.confidence,
                    alert.rule_name, alert.description, alert.evidence_json(),
                    alert.src_ip, alert.dst_ip, alert.src_port, alert.dst_port,
                    alert.status, alert.note,
                ),
            )
            return cur.lastrowid

    def get_alerts(self, limit: int = 50, severity: Optional[str] = None,
                    status: Optional[str] = None, alert_type: Optional[str] = None) -> List[dict]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if alert_type:
            query += " AND alert_type = ?"
            params.append(alert_type)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def get_alert(self, alert_id: int) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            return self._row_to_dict(row) if row else None

    def update_alert(self, alert_id: int, status: Optional[str] = None,
                      note: Optional[str] = None) -> bool:
        fields, params = [], []
        if status is not None:
            fields.append("status = ?")
            params.append(status)
        if note is not None:
            fields.append("note = ?")
            params.append(note)
        if not fields:
            return False
        params.append(alert_id)
        with self._connect() as conn:
            cur = conn.execute(f"UPDATE alerts SET {', '.join(fields)} WHERE id = ?", params)
            return cur.rowcount > 0

    def summary(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
            new = conn.execute("SELECT COUNT(*) c FROM alerts WHERE status='new'").fetchone()["c"]
            by_sev = conn.execute(
                "SELECT severity, COUNT(*) c FROM alerts GROUP BY severity"
            ).fetchall()
            by_type = conn.execute(
                "SELECT alert_type, COUNT(*) c FROM alerts GROUP BY alert_type ORDER BY c DESC"
            ).fetchall()
        return {
            "total_alerts": total,
            "new_alerts": new,
            "by_severity": {r["severity"]: r["c"] for r in by_sev},
            "by_type": {r["alert_type"]: r["c"] for r in by_type},
        }

    def export_alerts(self, fmt: str = "json") -> str:
        alerts = self.get_alerts(limit=1_000_000)
        if fmt == "json":
            return json.dumps(alerts, indent=2, default=str)
        if fmt == "csv":
            import csv
            import io
            buf = io.StringIO()
            if alerts:
                writer = csv.DictWriter(buf, fieldnames=list(alerts[0].keys()))
                writer.writeheader()
                writer.writerows(alerts)
            return buf.getvalue()
        raise ValueError(f"Unsupported export format: {fmt}")

    def cleanup(self, retention_days: int) -> int:
        cutoff = time.time() - retention_days * 86400
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
            conn.execute("DELETE FROM traffic_stats WHERE window_start < ?", (cutoff,))
            return cur.rowcount

    # -- Traffic stats ----------------------------------------------------

    def insert_traffic_window(self, window_start: float, window_seconds: float,
                               packet_count: int, byte_count: int = 0) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO traffic_stats (window_start, window_seconds, packet_count, byte_count)
                VALUES (?, ?, ?, ?)
                """,
                (window_start, window_seconds, packet_count, byte_count),
            )

    def get_recent_traffic(self, limit: int = 60) -> List[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM traffic_stats ORDER BY window_start DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        if d.get("evidence"):
            try:
                d["evidence"] = json.loads(d["evidence"])
            except (TypeError, json.JSONDecodeError):
                pass
        return d
