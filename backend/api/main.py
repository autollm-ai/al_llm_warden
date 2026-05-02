"""Read-only dashboard API + static frontend.

GET  /api/health           — liveness probe
GET  /api/summary          — dashboard counts + per-provider breakdown
GET  /api/events           — paged event list
GET  /api/events/{id}      — full event detail
POST /api/classify         — ad-hoc classification (used by the validator)
"""
from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from warden import classifier as _cls
from warden import dcg as _dcg
from warden import domains as _domains
from warden.database import DomainStore, EventStore, Event, now_iso
from warden.identity import IdentityMemory

app = FastAPI(title="LLM Warden", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_store = EventStore()
_identity = IdentityMemory()
_tok_path, _model_path = _cls.default_paths()
_classifier = _cls.Classifier.from_paths(_tok_path, _model_path)
_domain_store = DomainStore()
_domain_store.ensure_seeded(_domains.SHADOW_AI_DOMAINS)

_FRONTEND_DIR = Path(os.environ.get("WARDEN_FRONTEND_DIR", "/app/frontend"))

_TEST_MODE = os.environ.get("WARDEN_TEST_MODE", "0").lower() in ("1", "true", "yes", "on")
_TEST_MODE_PATH = Path(os.environ.get("WARDEN_TEST_MODE_PATH", "/data/warden-test-mode.jsonl"))


class ClassifyBody(BaseModel):
    text: str


class DomainBody(BaseModel):
    host: str
    label: str | None = None


class DomainPatchBody(BaseModel):
    enabled: bool


class AdminPurgeBody(BaseModel):
    """Request body for /api/admin/purge.

    Three escalating scopes — each strictly larger than the previous:
      • events            — wipe events table only (preserves domains, identity)
      • events_and_admin  — also wipes domains + identity (re-seeds defaults)
      • full              — drops everything in the DB (irreversible)

    `confirm` MUST be true; otherwise the call is rejected. This protects
    against accidental triggering by a stray curl from a script.
    """
    scope: str = "events"
    confirm: bool = False


@app.get("/api/test-mode")
def test_mode_status() -> dict:
    """Test-mode capture state + file size, so the UI can show the link."""
    info = {"enabled": _TEST_MODE, "path": str(_TEST_MODE_PATH), "size": 0, "exists": False}
    if _TEST_MODE_PATH.exists():
        info["exists"] = True
        try:
            info["size"] = _TEST_MODE_PATH.stat().st_size
        except OSError:
            pass
    return info


@app.get("/api/test-mode.jsonl")
def test_mode_download() -> FileResponse:
    """Stream the captured JSONL file for offline inspection."""
    if not _TEST_MODE:
        raise HTTPException(404, "test mode is disabled (set WARDEN_TEST_MODE=1)")
    if not _TEST_MODE_PATH.exists():
        raise HTTPException(404, "no captures yet — generate some traffic first")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    return FileResponse(
        str(_TEST_MODE_PATH),
        media_type="application/x-ndjson",
        filename=f"warden-test-mode-{stamp}.jsonl",
    )


@app.get("/api/identity")
def identity() -> dict:
    """Return values that have qualified as user-owned (email/IP)."""
    rows = _identity.known()
    masked = []
    for r in rows:
        v = r["value"]
        if r["kind"] == "email" and "@" in v:
            local, _, dom = v.partition("@")
            shown = (local[:2] + "***" if len(local) > 2 else "***") + "@" + dom
        else:
            shown = v
        masked.append({**r, "shown": shown})
    return {"signals": masked}


@app.delete("/api/identity/{kind}/{value:path}")
def identity_forget(kind: str, value: str) -> dict:
    """Manually retract a qualified user-identity value."""
    if kind not in ("email", "ip"):
        raise HTTPException(400, "kind must be email or ip")
    deleted = _identity.forget(kind, value)
    if not deleted:
        raise HTTPException(404, f"no identity record for {kind}={value}")
    return {"deleted": True, "kind": kind, "value": value}


# ── Monitored-domain registry (live-edit from the UI) ────────────────────────
@app.get("/api/domains")
def domains_list() -> dict:
    """All known domains (seeded + user-added). The proxy ignores anything
    not in this list with enabled=1."""
    return {"domains": _domain_store.list()}


@app.post("/api/domains")
def domains_add(body: DomainBody) -> dict:
    try:
        row = _domain_store.add(body.host, body.label or body.host)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _domains.invalidate_cache()
    return row


@app.delete("/api/domains/{host}")
def domains_remove(host: str) -> dict:
    if not _domain_store.remove(host):
        raise HTTPException(404, f"no domain {host!r}")
    _domains.invalidate_cache()
    return {"deleted": True, "host": host}


@app.patch("/api/domains/{host}")
def domains_patch(host: str, body: DomainPatchBody) -> dict:
    if not _domain_store.set_enabled(host, body.enabled):
        raise HTTPException(404, f"no domain {host!r}")
    _domains.invalidate_cache()
    return {"host": host, "enabled": body.enabled}


# ── Audited destructive purge ──────────────────────────────────────────────
# Ops on Warden's own state never go through the proxy (localhost is in
# NO_PROXY and warden's own host isn't in SHADOW_AI_DOMAINS), so they'd
# otherwise escape every monitoring tier. This endpoint closes that gap:
# it runs the destructive SQL through DCG first, writes an audit event
# with direction='admin' BEFORE executing, then performs the purge.
# The audit row survives even if the SQL fails — so a partial purge or
# permission denial is still discoverable on the dashboard.
_ADMIN_SCOPES = {
    "events": [
        "DELETE FROM events",
        "DELETE FROM sqlite_sequence WHERE name='events'",
    ],
    "events_and_admin": [
        "DELETE FROM events",
        "DELETE FROM domains",
        "DELETE FROM sqlite_sequence",
    ],
    "full": [
        "DROP TABLE IF EXISTS events",
        "DROP TABLE IF EXISTS domains",
    ],
}


@app.post("/api/admin/purge")
def admin_purge(body: AdminPurgeBody) -> dict:
    if body.scope not in _ADMIN_SCOPES:
        raise HTTPException(400, f"unknown scope {body.scope!r}; valid: {sorted(_ADMIN_SCOPES)}")
    if not body.confirm:
        raise HTTPException(400, "refusing to purge without confirm=true")

    sql_statements = _ADMIN_SCOPES[body.scope]
    sql_text = ";\n".join(sql_statements) + ";"

    # 1. Run the synthesized SQL through DCG so the destructive intent is
    # scored on the same scale as outbound LLM traffic. `sql_delete_no_where`
    # and `sql_drop_table` will both fire; that's intentional — purges are
    # supposed to be loud in the audit trail.
    dcg_hits, dcg_score = _dcg.scan(sql_text)
    label = "critical" if dcg_score >= 0.85 else "high" if dcg_score >= 0.65 else "medium"

    # 2. Write the audit event up-front, with direction='admin' so it shows
    # up in the dashboard's direction filter as a separate channel.
    audit = Event(
        ts=now_iso(),
        host="warden-internal",
        provider="Warden Admin",
        method="POST",
        path=f"/api/admin/purge:{body.scope}",
        sensitivity=dcg_score,
        tier1_score=dcg_score,
        tier2_score=0.0,
        label=label,
        categories=sorted({h.category for h in dcg_hits}),
        hits=[{"name": h.name, "category": h.category,
               "weight": h.weight, "snippet": h.snippet, "span": list(h.span)}
              for h in dcg_hits],
        summary=f"administrative purge requested (scope={body.scope})",
        bytes_out=len(sql_text),
        sample=sql_text,
        intent="admin",
        intent_conf=1.0,
        effective_sensitivity=dcg_score,
        direction="admin",
    )
    audit_id = _store.insert(audit)

    # 3. Execute. Each statement is run separately so a failure mid-purge
    # leaves the rest skippable; we collect rowcounts per statement.
    import sqlite3
    affected: list[dict] = []
    error: str | None = None
    try:
        with sqlite3.connect(_store.path, timeout=10) as conn:
            for stmt in sql_statements:
                try:
                    cur = conn.execute(stmt)
                    affected.append({"sql": stmt, "rowcount": cur.rowcount})
                except sqlite3.Error as e:
                    affected.append({"sql": stmt, "error": str(e)})
            conn.execute("VACUUM")
            conn.commit()
    except Exception as e:
        error = str(e)

    # 4. If we wiped the schema (scope='full'), recreate it so the proxy
    # doesn't crash on next insert. ensure_seeded() also restores domains.
    if body.scope == "full":
        _store.__init__(_store.path)              # re-runs _SCHEMA + migrations
        _domain_store.__init__(_domain_store.path)
        _domain_store.ensure_seeded(_domains.SHADOW_AI_DOMAINS)
    elif body.scope == "events_and_admin":
        # Domains table was emptied — re-seed defaults so the proxy
        # doesn't go blind.
        _domain_store.ensure_seeded(_domains.SHADOW_AI_DOMAINS)

    _domains.invalidate_cache()
    return {
        "audit_event_id": audit_id,
        "scope": body.scope,
        "dcg_score": dcg_score,
        "dcg_hits": [h.name for h in dcg_hits],
        "label": label,
        "executed": affected,
        "error": error,
    }


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "tier2_enabled": _classifier.model is not None,
        "db": _store.path,
        "test_mode": _TEST_MODE,
    }


@app.get("/api/summary")
def summary() -> dict:
    return _store.summary()


@app.get("/api/events")
def events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    provider: str | None = None,
    min_sensitivity: float | None = Query(None, ge=0.0, le=1.0),
    intent: str | None = None,
    direction: str | None = Query(None, regex="^(request|response)$"),
) -> dict:
    rows = _store.list_events(
        limit=limit, offset=offset, provider=provider,
        min_sensitivity=min_sensitivity, intent=intent, direction=direction,
    )
    return {"events": rows, "limit": limit, "offset": offset}


@app.get("/api/events.csv")
def events_csv(
    min_sensitivity: float = Query(0.15, ge=0.0, le=1.0),
    provider: str | None = None,
    label: str | None = Query(None, description="exact label filter, e.g. 'low,medium,high,critical'"),
    intent: str | None = Query(None, description="filter on classified intent (chat,telemetry,antiabuse,handshake,auth,unknown)"),
    limit: int = Query(10000, ge=1, le=100000),
) -> StreamingResponse:
    """Stream flagged events as CSV. Defaults to anything not 'clean'
    (sensitivity ≥ 0.15) so it's a one-click false-positive audit dump."""
    rows = _store.list_events(
        limit=limit, offset=0, provider=provider, min_sensitivity=min_sensitivity
    )
    if label:
        wanted = {x.strip() for x in label.split(",") if x.strip()}
        rows = [r for r in rows if r.get("label") in wanted]
    if intent:
        wanted_i = {x.strip() for x in intent.split(",") if x.strip()}
        rows = [r for r in rows if r.get("intent") in wanted_i]

    cols = [
        "id", "ts", "provider", "host", "method", "path",
        "label", "sensitivity", "effective_sensitivity",
        "tier1_score", "tier2_score",
        "intent", "intent_conf",
        "categories", "hit_names", "hit_categories",
        "summary", "bytes_out", "sample",
    ]

    def gen():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(cols)
        yield buf.getvalue(); buf.seek(0); buf.truncate()
        for r in rows:
            hits = r.get("hits") or []
            hit_names = ";".join(h.get("name", "") for h in hits if isinstance(h, dict))
            hit_categories = ";".join(h.get("category", "") for h in hits if isinstance(h, dict))
            cats = r.get("categories") or []
            writer.writerow([
                r.get("id", ""),
                r.get("ts", ""),
                r.get("provider", ""),
                r.get("host", ""),
                r.get("method", ""),
                r.get("path", ""),
                r.get("label", ""),
                f"{float(r.get('sensitivity') or 0):.4f}",
                f"{float(r.get('effective_sensitivity') or 0):.4f}",
                f"{float(r.get('tier1_score') or 0):.4f}",
                f"{float(r.get('tier2_score') or 0):.4f}",
                r.get("intent", ""),
                f"{float(r.get('intent_conf') or 0):.3f}",
                ";".join(cats) if isinstance(cats, list) else json.dumps(cats),
                hit_names,
                hit_categories,
                r.get("summary", ""),
                r.get("bytes_out", ""),
                r.get("sample", ""),
            ])
            yield buf.getvalue(); buf.seek(0); buf.truncate()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    fname = f"warden-flagged-{stamp}.csv"
    return StreamingResponse(
        gen(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/api/events/{event_id}")
def event_detail(event_id: int) -> dict:
    row = _store.get_event(event_id)
    if not row:
        raise HTTPException(404, "not found")
    return row


@app.post("/api/classify")
def classify(body: ClassifyBody) -> dict:
    return _classifier.classify(body.text).to_dict()


# ── Static frontend ──────────────────────────────────────────────────────────
if _FRONTEND_DIR.exists():
    app.mount(
        "/static",
        StaticFiles(directory=str(_FRONTEND_DIR / "static")),
        name="static",
    )

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(str(_FRONTEND_DIR / "index.html"))

    @app.get("/favicon.ico")
    def favicon() -> FileResponse:
        path = _FRONTEND_DIR / "static" / "favicon.png"
        if path.exists():
            return FileResponse(str(path))
        raise HTTPException(404)
