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
from warden.database import EventStore

app = FastAPI(title="LLM Warden", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_store = EventStore()
_tok_path, _model_path = _cls.default_paths()
_classifier = _cls.Classifier.from_paths(_tok_path, _model_path)

_FRONTEND_DIR = Path(os.environ.get("WARDEN_FRONTEND_DIR", "/app/frontend"))


class ClassifyBody(BaseModel):
    text: str


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "tier2_enabled": _classifier.model is not None,
        "db": _store.path,
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
) -> dict:
    rows = _store.list_events(
        limit=limit, offset=offset, provider=provider, min_sensitivity=min_sensitivity
    )
    return {"events": rows, "limit": limit, "offset": offset}


@app.get("/api/events.csv")
def events_csv(
    min_sensitivity: float = Query(0.15, ge=0.0, le=1.0),
    provider: str | None = None,
    label: str | None = Query(None, description="exact label filter, e.g. 'low,medium,high,critical'"),
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

    cols = [
        "id", "ts", "provider", "host", "method", "path",
        "label", "sensitivity", "tier1_score", "tier2_score",
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
                f"{float(r.get('tier1_score') or 0):.4f}",
                f"{float(r.get('tier2_score') or 0):.4f}",
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
