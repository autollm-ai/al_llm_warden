"""SQLite event store. One table for traffic events, one for daily aggregates."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB_PATH = os.environ.get("WARDEN_DB", "/data/warden.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                    TEXT    NOT NULL,
    host                  TEXT    NOT NULL,
    provider              TEXT    NOT NULL,
    method                TEXT    NOT NULL,
    path                  TEXT    NOT NULL,
    sensitivity           REAL    NOT NULL,   -- raw blended score (kept for audit)
    tier1_score           REAL    NOT NULL,
    tier2_score           REAL    NOT NULL,
    label                 TEXT    NOT NULL,   -- post-intent-clamp label shown in UI
    categories            TEXT    NOT NULL,
    hits                  TEXT    NOT NULL,
    summary               TEXT    NOT NULL,
    bytes_out             INTEGER NOT NULL,
    sample                TEXT    NOT NULL,
    intent                TEXT    NOT NULL DEFAULT 'unknown',
    intent_conf           REAL    NOT NULL DEFAULT 0.0,
    effective_sensitivity REAL    NOT NULL DEFAULT 0.0
);
CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_provider  ON events(provider);
CREATE INDEX IF NOT EXISTS idx_events_label     ON events(label);
"""

# The intent index depends on a column added by a migration, so it
# can't live in _SCHEMA (legacy DBs would fail because executescript
# runs before our ALTER). Created after migrations have completed.
_POST_MIGRATION_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_events_intent ON events(intent)",
]

# Idempotent ALTER TABLEs for existing databases. Each is wrapped so a
# second startup is a no-op even though SQLite has no IF NOT EXISTS for
# ADD COLUMN.
_MIGRATIONS: list[tuple[str, str]] = [
    ("intent",                "ALTER TABLE events ADD COLUMN intent TEXT NOT NULL DEFAULT 'unknown'"),
    ("intent_conf",           "ALTER TABLE events ADD COLUMN intent_conf REAL NOT NULL DEFAULT 0.0"),
    ("effective_sensitivity", "ALTER TABLE events ADD COLUMN effective_sensitivity REAL NOT NULL DEFAULT 0.0"),
]


@dataclass
class Event:
    ts: str
    host: str
    provider: str
    method: str
    path: str
    sensitivity: float
    tier1_score: float
    tier2_score: float
    label: str             # one of: clean, low, medium, high, critical
    categories: list[str]
    hits: list[dict]       # [{name, category, weight, snippet}]
    summary: str
    bytes_out: int
    sample: str
    intent: str = "unknown"
    intent_conf: float = 0.0
    effective_sensitivity: float = 0.0

    def to_row(self) -> tuple:
        return (
            self.ts,
            self.host,
            self.provider,
            self.method,
            self.path,
            self.sensitivity,
            self.tier1_score,
            self.tier2_score,
            self.label,
            json.dumps(self.categories),
            json.dumps(self.hits),
            self.summary,
            self.bytes_out,
            self.sample,
            self.intent,
            self.intent_conf,
            self.effective_sensitivity,
        )


class EventStore:
    def __init__(self, path: str | Path = DEFAULT_DB_PATH) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(events)")}
            for col, sql in _MIGRATIONS:
                if col not in cols:
                    conn.execute(sql)
            for sql in _POST_MIGRATION_INDEXES:
                conn.execute(sql)
            conn.commit()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def insert(self, event: Event) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO events
                   (ts, host, provider, method, path, sensitivity,
                    tier1_score, tier2_score, label, categories, hits,
                    summary, bytes_out, sample,
                    intent, intent_conf, effective_sensitivity)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                event.to_row(),
            )
            conn.commit()
            return int(cur.lastrowid)

    def list_events(
        self,
        limit: int = 100,
        offset: int = 0,
        provider: str | None = None,
        min_sensitivity: float | None = None,
        intent: str | None = None,
    ) -> list[dict]:
        clauses, params = [], []
        if provider:
            clauses.append("provider = ?")
            params.append(provider)
        if min_sensitivity is not None:
            # Filter on the user-facing (post-intent) score; falling back
            # to raw sensitivity for legacy rows where effective is 0.
            clauses.append("COALESCE(NULLIF(effective_sensitivity, 0), sensitivity) >= ?")
            params.append(min_sensitivity)
        if intent:
            clauses.append("intent = ?")
            params.append(intent)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_event(self, event_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        return self._row_to_dict(row) if row else None

    def summary(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
            counts = {
                row["label"]: row["c"]
                for row in conn.execute(
                    "SELECT label, COUNT(*) AS c FROM events GROUP BY label"
                ).fetchall()
            }
            providers = [
                dict(row)
                for row in conn.execute(
                    """SELECT provider,
                              COUNT(*)        AS events,
                              AVG(sensitivity) AS avg_sensitivity,
                              MAX(sensitivity) AS max_sensitivity,
                              SUM(bytes_out)   AS bytes_out
                       FROM events
                       GROUP BY provider
                       ORDER BY events DESC"""
                ).fetchall()
            ]
            recent = conn.execute(
                "SELECT MAX(ts) AS ts FROM events"
            ).fetchone()["ts"]
        return {
            "total": total,
            "by_label": counts,
            "by_provider": providers,
            "last_event_ts": recent,
        }

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["categories"] = json.loads(d["categories"])
        d["hits"] = json.loads(d["hits"])
        return d


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
