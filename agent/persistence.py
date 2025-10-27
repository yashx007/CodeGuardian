"""Simple persistence layer for analysis reports using SQLite.

Provides a tiny API: init_db(path), save_report(report_dict), list_reports(limit=50).
Uses a local file under data/reports.db by default.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

DEFAULT_DB = os.environ.get("CODEGUARDIAN_DB", "data/reports.db")


def _ensure_dir(path: str):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def init_db(path: Optional[str] = None):
    path = path or DEFAULT_DB
    _ensure_dir(path)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            timestamp TEXT,
            summary TEXT,
            payload TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def save_report(filename: str, summary: Dict[str, Any], payload: Dict[str, Any], path: Optional[str] = None) -> int:
    path = path or DEFAULT_DB
    _ensure_dir(path)
    init_db(path)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    ts = datetime.now(timezone.utc).isoformat()
    cur.execute(
        "INSERT INTO reports (filename, timestamp, summary, payload) VALUES (?, ?, ?, ?)",
        (filename, ts, json.dumps(summary), json.dumps(payload)),
    )
    conn.commit()
    rowid = cur.lastrowid or 0
    conn.close()
    return rowid


def list_reports(limit: int = 50, path: Optional[str] = None) -> List[Dict[str, Any]]:
    path = path or DEFAULT_DB
    if not os.path.exists(path):
        return []
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("SELECT id, filename, timestamp, summary FROM reports ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    out: List[Dict[str, Any]] = []
    for r in rows:
        _id, filename, ts, summary_json = r
        try:
            summary = json.loads(summary_json)
        except Exception:
            summary = {"raw": summary_json}
        out.append({"id": _id, "filename": filename, "timestamp": ts, "summary": summary})
    return out


def get_report(report_id: int, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Return the full report payload and metadata for a given id, or None."""
    path = path or DEFAULT_DB
    if not os.path.exists(path):
        return None
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("SELECT id, filename, timestamp, summary, payload FROM reports WHERE id = ?", (report_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    _id, filename, ts, summary_json, payload_json = row
    try:
        summary = json.loads(summary_json)
    except Exception:
        summary = {"raw": summary_json}
    try:
        payload = json.loads(payload_json)
    except Exception:
        payload = {"raw": payload_json}
    return {"id": _id, "filename": filename, "timestamp": ts, "summary": summary, "payload": payload}


# ------------------ chat session persistence helpers ------------------


def _default_chat_db() -> str:
    return os.environ.get("CHAT_DB", "data/sessions.db")


def init_chat_db(path: Optional[str] = None):
    path = path or _default_chat_db()
    _ensure_dir(path)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            messages TEXT,
            last_active TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def save_session(session_id: str, messages: List[Dict[str, Any]], last_active: str, path: Optional[str] = None) -> None:
    path = path or _default_chat_db()
    _ensure_dir(path)
    init_chat_db(path)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute(
        "REPLACE INTO sessions (session_id, messages, last_active) VALUES (?, ?, ?)",
        (session_id, json.dumps(messages), last_active),
    )
    conn.commit()
    conn.close()


def load_session(session_id: str, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    path = path or _default_chat_db()
    if not os.path.exists(path):
        return None
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("SELECT messages, last_active FROM sessions WHERE session_id = ?", (session_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    messages_json, last_active = row
    try:
        messages = json.loads(messages_json)
    except Exception:
        messages = []
    return {"session_id": session_id, "messages": messages, "last_active": last_active}


def delete_session(session_id: str, path: Optional[str] = None) -> None:
    path = path or _default_chat_db()
    if not os.path.exists(path):
        return
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
    conn.commit()
    conn.close()


def list_sessions(path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return list of sessions with metadata (session_id, last_active)."""
    path = path or _default_chat_db()
    if not os.path.exists(path):
        return []
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("SELECT session_id, last_active FROM sessions")
    rows = cur.fetchall()
    conn.close()
    out: List[Dict[str, Any]] = []
    for sid, last_active in rows:
        out.append({"session_id": sid, "last_active": last_active})
    return out
