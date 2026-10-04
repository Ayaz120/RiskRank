"""
models.py
---------
Data model for the Vulnerability Triage Assistant.

A "Finding" represents a single security issue discovered from any
source (Nmap scan, manual pentest note, Burp export, etc). This is the
central object the whole pipeline works with:

    ingest (parsers) -> store (this file) -> triage (engine) -> score (scoring) -> report
"""

import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "triage.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            asset TEXT,
            raw_data TEXT,
            asset_criticality TEXT DEFAULT 'unknown',
            ai_explanation TEXT,
            ai_cvss_score REAL,
            ai_cvss_reasoning TEXT,
            ai_exploitability TEXT,
            ai_remediation TEXT,
            priority_score REAL,
            priority_rank INTEGER,
            status TEXT DEFAULT 'new',
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def insert_finding(source, title, description="", asset="", raw_data=None,
                    asset_criticality="unknown"):
    conn = get_db()
    cur = conn.execute(
        """
        INSERT INTO findings (source, title, description, asset, raw_data,
                               asset_criticality, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'new', ?)
        """,
        (
            source, title, description, asset,
            json.dumps(raw_data) if raw_data else None,
            asset_criticality,
            datetime.utcnow().isoformat(),
        ),
    )
    conn.commit()
    finding_id = cur.lastrowid
    conn.close()
    return finding_id


def get_all_findings(status=None):
    conn = get_db()
    if status:
        rows = conn.execute(
            "SELECT * FROM findings WHERE status = ? ORDER BY id", (status,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM findings ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_finding(finding_id):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM findings WHERE id = ?", (finding_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def update_triage(finding_id, explanation, cvss_score, cvss_reasoning,
                   exploitability, remediation):
    conn = get_db()
    conn.execute(
        """
        UPDATE findings
        SET ai_explanation = ?, ai_cvss_score = ?, ai_cvss_reasoning = ?,
            ai_exploitability = ?, ai_remediation = ?, status = 'triaged'
        WHERE id = ?
        """,
        (explanation, cvss_score, cvss_reasoning, exploitability, remediation, finding_id),
    )
    conn.commit()
    conn.close()


def update_priority(finding_id, priority_score, priority_rank):
    conn = get_db()
    conn.execute(
        """
        UPDATE findings
        SET priority_score = ?, priority_rank = ?, status = 'scored'
        WHERE id = ?
        """,
        (priority_score, priority_rank, finding_id),
    )
    conn.commit()
    conn.close()


def clear_all():
    conn = get_db()
    conn.execute("DELETE FROM findings")
    conn.commit()
    conn.close()
