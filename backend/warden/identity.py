"""User-identity memory.

PII like the user's own login email and outbound IP appears in nearly
every outbound LLM request because the user authenticated upstream and
consented to share it. Flagging it as critical PII on every batch is
noise — the user already accepted that risk.

This module tracks recurring PII values locally. After a value (email
or IP) appears ≥`THRESHOLD` times in the trailing `DECAY_HOURS` window,
subsequent occurrences are demoted from "pii" to "user_identity" with a
near-zero weight, so they keep showing in the audit trail but no longer
drive the sensitivity score.

Strictly local. The signals table is in the same SQLite file as events.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

# How many recurrences before a value qualifies as the user's own.
THRESHOLD = int(os.environ.get("WARDEN_IDENTITY_THRESHOLD", "5"))
# Recurrences must fall within this trailing window.
DECAY_HOURS = int(os.environ.get("WARDEN_IDENTITY_DECAY_HOURS", "24"))
# A user has at most one login email and one or two outbound IPs (home
# + mobile/work, or v4 + v6). Anything above the cap stays flagged as
# PII even if it crosses THRESHOLD — multiple emails crossing threshold
# is more likely to be other people's data leaking through.
MAX_PER_KIND: dict[str, int] = {"email": 1, "ip": 2}

_DEFAULT_PATH = os.environ.get("WARDEN_DB", "/data/warden.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS identity_signals (
    kind       TEXT    NOT NULL,
    value      TEXT    NOT NULL,
    count      INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT    NOT NULL,
    last_seen  TEXT    NOT NULL,
    PRIMARY KEY (kind, value)
);
CREATE INDEX IF NOT EXISTS idx_identity_kind ON identity_signals(kind);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _cutoff_iso() -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=DECAY_HOURS)).isoformat(timespec="seconds")


def _norm(kind: str, value: str) -> str:
    v = value.strip()
    return v.lower() if kind == "email" else v


# Hit name → identity kind mapping. Anything not in this map is left
# alone (cards, SSNs, secrets — those should never be exempted).
KIND_FOR_HIT: dict[str, str] = {
    "email":       "email",
    "ipv4":        "ip",
    "ip_internal": "ip",
}


class IdentityMemory:
    def __init__(self, path: str = _DEFAULT_PATH) -> None:
        self.path = path
        self._lock = threading.Lock()
        with self._connect() as c:
            c.executescript(_SCHEMA)
            c.commit()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        try:
            yield conn
        finally:
            conn.close()

    def observe(self, kind: str, value: str) -> None:
        if not value:
            return
        v = _norm(kind, value)
        ts = _now_iso()
        with self._lock, self._connect() as c:
            c.execute(
                """INSERT INTO identity_signals(kind, value, count, first_seen, last_seen)
                   VALUES (?, ?, 1, ?, ?)
                   ON CONFLICT(kind, value) DO UPDATE SET
                       count     = count + 1,
                       last_seen = excluded.last_seen""",
                (kind, v, ts, ts),
            )
            c.commit()

    def qualified(self, kind: str) -> list[str]:
        """Return the top-N most-frequent values of `kind` that have
        crossed THRESHOLD in the trailing window. N is capped per kind by
        MAX_PER_KIND so the user-identity slot can't expand indefinitely
        — at most one email, at most two IPs."""
        cap = MAX_PER_KIND.get(kind, 1)
        cutoff = _cutoff_iso()
        with self._lock, self._connect() as c:
            rows = c.execute(
                """SELECT value FROM identity_signals
                   WHERE kind=? AND count >= ? AND last_seen >= ?
                   ORDER BY count DESC, last_seen DESC
                   LIMIT ?""",
                (kind, THRESHOLD, cutoff, cap),
            ).fetchall()
        return [r[0] for r in rows]

    def qualified_set(self) -> dict[str, set[str]]:
        """One-shot fetch of qualified values for every capped kind.
        Use this when classifying a single request so we don't issue a
        SELECT per hit."""
        return {kind: set(self.qualified(kind)) for kind in MAX_PER_KIND}

    def is_user_owned(self, kind: str, value: str) -> bool:
        if not value:
            return False
        return _norm(kind, value) in self.qualified(kind)

    def forget(self, kind: str, value: str) -> bool:
        """Remove a (kind, value) pair so it stops being treated as
        user-owned. Returns True if a row was deleted."""
        if not value:
            return False
        v = _norm(kind, value)
        with self._lock, self._connect() as c:
            cur = c.execute(
                "DELETE FROM identity_signals WHERE kind=? AND value=?",
                (kind, v),
            )
            c.commit()
            return cur.rowcount > 0

    def known(self) -> list[dict]:
        """Qualified user-owned values for the dashboard. Honors the
        per-kind cap so the API matches what's actually being exempted."""
        cutoff = _cutoff_iso()
        out: list[dict] = []
        with self._lock, self._connect() as c:
            for kind, cap in MAX_PER_KIND.items():
                rows = c.execute(
                    """SELECT kind, value, count, first_seen, last_seen
                       FROM identity_signals
                       WHERE kind=? AND count >= ? AND last_seen >= ?
                       ORDER BY count DESC, last_seen DESC
                       LIMIT ?""",
                    (kind, THRESHOLD, cutoff, cap),
                ).fetchall()
                for (k, v, n, fs, ls) in rows:
                    out.append({"kind": k, "value": v, "count": n,
                                "first_seen": fs, "last_seen": ls})
        return out
