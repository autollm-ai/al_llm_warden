"""Read-only dashboard API + static frontend.

GET  /api/health           — liveness probe
GET  /api/summary          — dashboard counts + per-provider breakdown
GET  /api/events           — paged event list
GET  /api/events/{id}      — full event detail
POST /api/classify         — ad-hoc classification (used by the validator)
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
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
