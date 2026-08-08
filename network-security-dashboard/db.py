"""
Lightweight SQLite storage for past scans, so the dashboard can show a
trend over time instead of just the most recent result.
"""

import json
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = "scan_history.db"


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at REAL NOT NULL,
                mode TEXT NOT NULL,
                target TEXT NOT NULL,
                max_risk_score INTEGER NOT NULL,
                device_count INTEGER NOT NULL,
                finding_count INTEGER NOT NULL,
                result_json TEXT NOT NULL
            )
        """)


def save_scan(scan_result):
    devices = scan_result.get("devices", [])
    max_score = max((d.get("risk_score", 0) for d in devices), default=0)
    finding_count = sum(d.get("finding_count", 0) for d in devices)

    with get_conn() as conn:
        conn.execute(
            """INSERT INTO scans
               (scanned_at, mode, target, max_risk_score, device_count, finding_count, result_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_result.get("scanned_at", time.time()),
                scan_result.get("mode", "unknown"),
                scan_result.get("target", ""),
                max_score,
                len(devices),
                finding_count,
                json.dumps(scan_result),
            ),
        )


def get_history(limit=20):
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT id, scanned_at, mode, target, max_risk_score, device_count, finding_count
               FROM scans ORDER BY scanned_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan_detail(scan_id):
    with get_conn() as conn:
        row = conn.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return json.loads(row["result_json"]) if row else None
