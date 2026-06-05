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
import subprocess
import sys
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
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)

_store = EventStore()
_identity = IdentityMemory()
_tok_path, _model_path = _cls.default_paths()
_classifier = _cls.Classifier.from_paths(_tok_path, _model_path)
_classifier_lock = __import__("threading").Lock()
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


class AnnotateBody(BaseModel):
    ground_truth_label: str | None = None


class RealGenerateBody(BaseModel):
    openai_count: int = 0


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
        # Commit the DELETE statements first, then VACUUM outside the transaction.
        # VACUUM cannot run inside a transaction; running it inside the `with` block
        # would raise an exception and roll back the deletes.
        with sqlite3.connect(_store.path, timeout=10) as conn:
            for stmt in sql_statements:
                try:
                    cur = conn.execute(stmt)
                    affected.append({"sql": stmt, "rowcount": cur.rowcount})
                except sqlite3.Error as e:
                    affected.append({"sql": stmt, "error": str(e)})
            conn.commit()
        # VACUUM runs outside the transaction context on a fresh connection.
        with sqlite3.connect(_store.path, timeout=10) as conn:
            conn.execute("VACUUM")
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


@app.get("/api/events/export.json")
def events_export_json(
    min_sensitivity: float = Query(0.0, ge=0.0, le=1.0),
    provider: str | None = None,
    label: str | None = None,
    limit: int = Query(100000, ge=1, le=500000),
) -> StreamingResponse:
    """Download all events as a JSON array for offline annotation and analysis."""
    rows = _store.list_events(limit=limit, offset=0, provider=provider,
                              min_sensitivity=min_sensitivity if min_sensitivity > 0 else None)
    if label:
        wanted = {x.strip() for x in label.split(",") if x.strip()}
        rows = [r for r in rows if r.get("label") in wanted]

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")

    def gen():
        yield "[\n"
        for i, r in enumerate(rows):
            yield ("" if i == 0 else ",\n") + json.dumps(r, ensure_ascii=False)
        yield "\n]\n"

    return StreamingResponse(
        gen(),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="warden-events-{stamp}.json"'},
    )


@app.get("/api/events/{event_id}")
def event_detail(event_id: int) -> dict:
    row = _store.get_event(event_id)
    if not row:
        raise HTTPException(404, "not found")
    return row


@app.patch("/api/events/{event_id}")
def event_annotate(event_id: int, body: AnnotateBody) -> dict:
    """Set or clear the human ground-truth label on an event."""
    valid = {"clean", "low", "medium", "high", "critical", "false_positive", None}
    if body.ground_truth_label not in valid:
        raise HTTPException(400, f"invalid label {body.ground_truth_label!r}")
    if not _store.annotate_event(event_id, body.ground_truth_label):
        raise HTTPException(404, "not found")
    return {"id": event_id, "ground_truth_label": body.ground_truth_label}


# ── Training pipeline ────────────────────────────────────────────────────────

_REAL_GEN_STATUS_PATH   = Path(os.environ.get("WARDEN_MODEL_DIR", "/models")) / "real_generate_status.json"
_TRAINING_STATUS_PATH   = Path(os.environ.get("WARDEN_MODEL_DIR", "/models")) / "training_status.json"
_LABEL_TO_INT = {"false_positive": 0, "clean": 0, "low": 1, "medium": 1, "high": 1, "critical": 1}


@app.get("/api/config/keys")
def config_keys() -> dict:
    """Return which API keys are available (booleans only, never the values)."""
    return {
        "has_openai": bool(os.environ.get("OPENAI_API_KEY", "").strip()),
    }


@app.get("/api/events/generate-real/status")
def events_generate_real_status() -> dict:
    """Poll progress of a running real-LLM-call generation job."""
    if not _REAL_GEN_STATUS_PATH.exists():
        return {"running": False, "done": 0, "total": 0, "ok": 0}
    try:
        return json.loads(_REAL_GEN_STATUS_PATH.read_text())
    except Exception:
        return {"running": False, "done": 0, "total": 0, "ok": 0}


@app.post("/api/events/generate-real")
def events_generate_real(body: RealGenerateBody) -> dict:
    """Start a background job that makes real OpenAI API calls and records events.
    Claude events are generated on the host via scripts/generate_real_traffic.py."""
    if body.openai_count < 1:
        raise HTTPException(400, "openai_count must be at least 1")
    if not os.environ.get("OPENAI_API_KEY", "").strip():
        raise HTTPException(400, "OPENAI_API_KEY not configured")

    try:
        cur = json.loads(_REAL_GEN_STATUS_PATH.read_text()) if _REAL_GEN_STATUS_PATH.exists() else {}
        if cur.get("running"):
            raise HTTPException(409, "real generation already running")
    except HTTPException:
        raise
    except Exception:
        pass

    cmd = [
        sys.executable, "-m", "training.generate_real",
        "--openai", str(body.openai_count),
    ]
    try:
        proc = subprocess.Popen(cmd, cwd="/app",
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env=dict(os.environ))
    except Exception as e:
        raise HTTPException(500, f"failed to start generation: {e}")
    return {"started": True, "pid": proc.pid, "openai_count": body.openai_count}


@app.get("/api/annotation/summary")
def annotation_summary() -> dict:
    """Ground-truth label distribution across all manually annotated events."""
    import sqlite3
    counts: dict[str, int] = {}
    total_annotated = 0
    try:
        with sqlite3.connect(_store.path, timeout=10) as conn:
            rows = conn.execute(
                "SELECT ground_truth_label, COUNT(*) FROM events "
                "WHERE ground_truth_label IS NOT NULL "
                "GROUP BY ground_truth_label"
            ).fetchall()
            for label, n in rows:
                counts[label] = n
                total_annotated += n
    except Exception:
        pass
    total_events = _store.summary().get("total", 0)
    return {
        "by_ground_truth_label": counts,
        "annotated": total_annotated,
        "total": total_events,
        "coverage_pct": round(total_annotated / max(total_events, 1) * 100, 1),
    }


@app.get("/api/training/status")
def training_status() -> dict:
    """Return latest training run status and model metrics."""
    status: dict = {"running": False, "metrics": None, "annotated_count": 0}
    status["annotated_count"] = len(_store.annotated_for_training())
    if _TRAINING_STATUS_PATH.exists():
        try:
            status.update(json.loads(_TRAINING_STATUS_PATH.read_text()))
        except Exception:
            pass
    metrics_path = Path(os.environ.get("WARDEN_MODEL_DIR", "/models")) / "metrics.json"
    if metrics_path.exists():
        try:
            status["metrics"] = json.loads(metrics_path.read_text())
        except Exception:
            pass
    return status


@app.post("/api/training/start")
def training_start() -> dict:
    """Kick off a retraining run using annotated events."""
    try:
        cur = json.loads(_TRAINING_STATUS_PATH.read_text()) if _TRAINING_STATUS_PATH.exists() else {}
        if cur.get("running"):
            raise HTTPException(409, "training already running")
    except HTTPException:
        raise
    except Exception:
        pass

    annotated = _store.annotated_for_training()
    if not annotated:
        raise HTTPException(400, "no annotated events — label some events in the Events table first")

    real_csv_path = Path(os.environ.get("WARDEN_MODEL_DIR", "/models")) / "annotated_training.csv"
    with open(real_csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["text", "label", "spans"])
        for r in annotated:
            text = r.get("sample") or ""
            gtl = r.get("ground_truth_label") or "clean"
            int_label = _LABEL_TO_INT.get(gtl, 0)
            hits = r.get("hits") or []
            span_list = [[h["span"][0], h["span"][1]]
                         for h in hits if isinstance(h, dict) and h.get("span")]
            if int_label == 1 and not span_list and text:
                span_list = [[0, len(text)]]
            w.writerow([text, int_label, json.dumps(span_list)])

    _TRAINING_STATUS_PATH.write_text(json.dumps({"running": True, "started_at": now_iso()}))
    cmd = [sys.executable, "-m", "training.train", "--data", str(real_csv_path), "--real-only", "--force"]
    try:
        proc = subprocess.Popen(cmd, cwd="/app", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        _TRAINING_STATUS_PATH.write_text(json.dumps({"running": False, "error": str(e)}))
        raise HTTPException(500, f"failed to start training: {e}")
    return {"started": True, "pid": proc.pid, "annotated_samples": len(annotated)}


@app.post("/api/training/reload")
def training_reload() -> dict:
    """Hot-reload the classifier from the latest model files without restarting."""
    global _classifier
    tok_path, model_path = _cls.default_paths()
    if not Path(tok_path).exists() or not Path(model_path).exists():
        raise HTTPException(404, "model files not found — run training first")
    with _classifier_lock:
        _classifier = _cls.Classifier.from_paths(tok_path, model_path)
    tier2 = _classifier.model is not None
    return {"reloaded": True, "tier2_enabled": tier2}


@app.get("/api/training/export.csv")
def training_export_csv() -> StreamingResponse:
    """Export annotated events as a training CSV for the LSTM."""
    rows = _store.annotated_for_training()
    if not rows:
        raise HTTPException(404, "no annotated events yet")

    def gen():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["text", "label", "spans"])
        yield buf.getvalue(); buf.seek(0); buf.truncate()
        for r in rows:
            text = r.get("sample") or ""
            gtl = r.get("ground_truth_label") or "clean"
            int_label = _LABEL_TO_INT.get(gtl, 0)
            hits = r.get("hits") or []
            span_list = [[h["span"][0], h["span"][1]]
                         for h in hits if isinstance(h, dict) and h.get("span")]
            if int_label == 1 and not span_list and text:
                span_list = [[0, len(text)]]
            writer.writerow([text, int_label, json.dumps(span_list)])
            yield buf.getvalue(); buf.seek(0); buf.truncate()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    return StreamingResponse(
        gen(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="warden-training-{stamp}.csv"'},
    )


@app.post("/api/classify")
def classify(body: ClassifyBody) -> dict:
    with _classifier_lock:
        clf = _classifier
    return clf.classify(body.text).to_dict()


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
