"""SQLite storage for alerts and time-window traffic statistics.

All queries use parameter binding (never string-formatted SQL) to avoid
injection, even though input in this project is not typically
attacker-controlled text -- it's good practice regardless.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, List, Optional

from .models import Alert, HostRecord, SessionRecord, CredentialRecord

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

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE,
    mac TEXT,
    hostname TEXT,
    os_guess TEXT,
    ttl INTEGER,
    vendor TEXT,
    first_seen REAL,
    last_seen REAL,
    packet_count INTEGER,
    byte_count INTEGER,
    open_ports TEXT,
    services TEXT,
    banners TEXT,
    geo_country TEXT,
    geo_asn TEXT,
    is_local BOOLEAN
);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts (ip);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT UNIQUE,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    state TEXT,
    started REAL,
    ended REAL,
    packets_sent INTEGER,
    packets_recv INTEGER,
    bytes_sent INTEGER,
    bytes_recv INTEGER,
    http_host TEXT,
    tls_sni TEXT,
    tls_ja3 TEXT,
    service TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions (session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_src_ip ON sessions (src_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_dst_ip ON sessions (dst_ip);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    username TEXT,
    timestamp REAL,
    description TEXT
);
CREATE INDEX IF NOT EXISTS idx_credentials_timestamp ON credentials (timestamp);

CREATE TABLE IF NOT EXISTS signatures_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL,
    signature_name TEXT,
    alert_type TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    description TEXT,
    evidence TEXT
);
CREATE INDEX IF NOT EXISTS idx_signatures_log_timestamp ON signatures_log (timestamp);
"""


class Database:
    def __init__(self, path: str = "nids.db"):
        self.path = path
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._write_lock = threading.Lock()

    def close(self):
        self._conn.close()

    @contextmanager
    def _connect(self):
        with self._write_lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.execute('PRAGMA journal_mode=WAL')
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

    def insert_alerts_batch(self, alerts: List[Alert]) -> None:
        if not alerts:
            return
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO alerts
                    (timestamp, alert_type, severity, confidence, rule_name,
                     description, evidence, src_ip, dst_ip, src_port, dst_port,
                     status, note)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [(
                    a.timestamp, a.alert_type, a.severity, a.confidence,
                    a.rule_name, a.description, a.evidence_json(),
                    a.src_ip, a.dst_ip, a.src_port, a.dst_port,
                    a.status, a.note
                ) for a in alerts]
            )

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

    # -- Hosts ------------------------------------------------------------
    
    def upsert_host(self, host: HostRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO hosts (
                    ip, mac, hostname, os_guess, ttl, vendor, first_seen, last_seen,
                    packet_count, byte_count, open_ports, services, banners,
                    geo_country, geo_asn, is_local
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac = excluded.mac,
                    hostname = excluded.hostname,
                    os_guess = excluded.os_guess,
                    ttl = excluded.ttl,
                    vendor = excluded.vendor,
                    last_seen = excluded.last_seen,
                    packet_count = excluded.packet_count,
                    byte_count = excluded.byte_count,
                    open_ports = excluded.open_ports,
                    services = excluded.services,
                    banners = excluded.banners,
                    geo_country = excluded.geo_country,
                    geo_asn = excluded.geo_asn,
                    is_local = excluded.is_local
                """,
                (
                    host.ip, host.mac, host.hostname, host.os_guess, host.ttl, host.vendor,
                    host.first_seen, host.last_seen, host.packet_count, host.byte_count,
                    json.dumps(host.open_ports), json.dumps(host.services),
                    json.dumps(host.banners), host.geo_country, host.geo_asn, host.is_local
                )
            )

    def get_hosts(self, limit: int = 100) -> List[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM hosts LIMIT ?", (limit,)).fetchall()
            return [self._host_row_to_dict(r) for r in rows]

    def get_host(self, ip: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM hosts WHERE ip = ?", (ip,)).fetchone()
            return self._host_row_to_dict(row) if row else None
            
    # -- Sessions ---------------------------------------------------------
    
    def insert_session(self, session: SessionRecord) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO sessions (
                    session_id, src_ip, src_port, dst_ip, dst_port, state, started,
                    ended, packets_sent, packets_recv, bytes_sent, bytes_recv,
                    http_host, tls_sni, tls_ja3, service
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    state = excluded.state,
                    ended = excluded.ended,
                    packets_sent = excluded.packets_sent,
                    packets_recv = excluded.packets_recv,
                    bytes_sent = excluded.bytes_sent,
                    bytes_recv = excluded.bytes_recv
                """,
                (
                    session.session_id, session.src_ip, session.src_port, session.dst_ip,
                    session.dst_port, session.state, session.started, session.ended,
                    session.packets_sent, session.packets_recv, session.bytes_sent,
                    session.bytes_recv, session.http_host, session.tls_sni,
                    session.tls_ja3, session.service
                )
            )
            return cur.lastrowid

    def get_sessions(self, limit: int = 100, state: Optional[str] = None) -> List[dict]:
        query = "SELECT * FROM sessions"
        params = []
        if state:
            query += " WHERE state = ?"
            params.append(state)
        query += " ORDER BY started DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    # -- Credentials ------------------------------------------------------
    
    def insert_credential(self, cred: CredentialRecord) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO credentials (
                    protocol, src_ip, dst_ip, dst_port, username, timestamp, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cred.protocol, cred.src_ip, cred.dst_ip, cred.dst_port, cred.username,
                    cred.timestamp, cred.description
                )
            )
            return cur.lastrowid
            
    def get_credentials(self, limit: int = 100) -> List[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM credentials ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    # -- Dashboard Stats --------------------------------------------------

    def get_dashboard_stats(self) -> dict:
        with self._connect() as conn:
            alerts_total = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
            alerts_by_type = dict(conn.execute("SELECT alert_type, COUNT(*) c FROM alerts GROUP BY alert_type").fetchall())
            alerts_by_severity = dict(conn.execute("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity").fetchall())
            host_count = conn.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"]
            active_sessions = conn.execute("SELECT COUNT(*) c FROM sessions WHERE state != 'CLOSED' AND state != 'TIMEOUT' AND state != 'RESET'").fetchone()["c"]
            credentials_found = conn.execute("SELECT COUNT(*) c FROM credentials").fetchone()["c"]
            
        return {
            "alerts": {
                "total": alerts_total,
                "by_type": alerts_by_type,
                "by_severity": alerts_by_severity,
            },
            "host_count": host_count,
            "active_sessions": active_sessions,
            "credentials_found": credentials_found
        }

    # -- Helpers ----------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        if d.get("evidence"):
            try:
                d["evidence"] = json.loads(d["evidence"])
            except (TypeError, json.JSONDecodeError):
                pass
        return d

    @staticmethod
    def _host_row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        for field in ("open_ports", "services", "banners"):
            if d.get(field):
                try:
                    d[field] = json.loads(d[field])
                except (TypeError, json.JSONDecodeError):
                    pass
            else:
                d[field] = [] if field == "open_ports" else {}
        return d
