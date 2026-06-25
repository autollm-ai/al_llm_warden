---
name: push-stats
description: Export LLM Warden stats to a CSV file and email that file as an attachment to the AutoLLM team. Use when the user wants to push, send, report, or share Warden stats / events with AutoLLM (e.g. "push my stats", "send the warden stats", "/push-stats"). The user may pass a recipient email to override the default.
---

# Push Warden stats

Export the local LLM Warden event data to a CSV file and email it as an
attachment. This is the one feature that deliberately sends Warden data off
the machine — the CSV includes the masked `sample` previews, so treat it as
an explicit, user-initiated egress action, not background telemetry.

**Recipient:** default `saumye@autollm.ai`. If the user supplied an email
address when invoking the skill, use that instead.

**Prerequisites:** Docker must be running with the Warden containers up
(`warden-api` / `warden-proxy`), and Gmail must be authorized for this
session (`/mcp` → "claude.ai Gmail"). If Gmail isn't connected yet, ask the
user to run `/mcp` and authorize it before continuing.

The event data is read **directly from the SQLite database** that the proxy
writes to (`/data/warden.db`, inside the container on the `warden-data`
volume) — not through the dashboard API. The API's CSV endpoint is hard-
capped at 100k events, so it can't export a dev's full history; reading the
DB directly has no such cap. We open it **read-only** so the live proxy
writer is never blocked, and use the container's stdlib Python (no `sqlite3`
CLI or file copy needed).

## Steps

### 1. Confirm the Warden container is running

```bash
docker ps --filter name=warden-api --filter status=running --format '{{.Names}}' | grep -q warden-api \
  || { echo "warden-api is not running — start Warden with: docker compose up -d"; exit 1; }
```

If it isn't running, stop and tell the user to start Warden
(`docker compose up -d`). Do not proceed. (`warden-proxy` also works as the
exec target — both containers mount the same `/data` volume.)

### 2. Export the full event table directly from the database

Open the SQLite file read-only and dump **every** row to a timestamped CSV
in the repo root. The heredoc must stay at column 0 so the `PY` terminator
matches — run it exactly as written.

```bash
OUT="warden-stats-$(date +%Y%m%d-%H%M%S).csv"
docker exec -i warden-api python - > "$OUT" <<'PY'
import csv, json, sqlite3, sys
con = sqlite3.connect("file:/data/warden.db?mode=ro", uri=True)
con.row_factory = sqlite3.Row
cols = ["id","ts","provider","host","method","path","label",
        "sensitivity","effective_sensitivity","tier1_score","tier2_score",
        "intent","intent_conf","categories","hit_names","hit_categories",
        "summary","bytes_out","sample"]
w = csv.writer(sys.stdout)
w.writerow(cols)
for r in con.execute("SELECT * FROM events ORDER BY id"):
    try: hits = json.loads(r["hits"] or "[]")
    except Exception: hits = []
    try: cats = json.loads(r["categories"] or "[]")
    except Exception: cats = []
    hit_names = ";".join(h.get("name","") for h in hits if isinstance(h, dict))
    hit_cats  = ";".join(h.get("category","") for h in hits if isinstance(h, dict))
    w.writerow([
        r["id"], r["ts"], r["provider"], r["host"], r["method"], r["path"], r["label"],
        f'{float(r["sensitivity"] or 0):.4f}',
        f'{float(r["effective_sensitivity"] or 0):.4f}',
        f'{float(r["tier1_score"] or 0):.4f}',
        f'{float(r["tier2_score"] or 0):.4f}',
        r["intent"],
        f'{float(r["intent_conf"] or 0):.3f}',
        ";".join(cats) if isinstance(cats, list) else "",
        hit_names, hit_cats,
        r["summary"], r["bytes_out"], r["sample"],
    ])
PY
echo "exported -> $OUT ($(wc -c < "$OUT") bytes)"
```

Columns: `id, ts, provider, host, method, path, label, sensitivity,
effective_sensitivity, tier1_score, tier2_score, intent, intent_conf,
categories, hit_names, hit_categories, summary, bytes_out, sample`.

If the export contains only the header row, tell the user there are no events
to push yet and stop. (Note: `wc -l` over-counts because the `sample` field
contains newlines — don't use it as the event count; use the count from
step 3.)

### 3. Get a one-line summary for the email body

Queried from the same database, read-only:

```bash
docker exec -i warden-api python - <<'PY'
import sqlite3
con = sqlite3.connect("file:/data/warden.db?mode=ro", uri=True)
total  = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
provs  = con.execute("SELECT COUNT(DISTINCT provider) FROM events").fetchone()[0]
labels = dict(con.execute("SELECT label, COUNT(*) FROM events GROUP BY label").fetchall())
print(f"{total} events across {provs} providers — " +
      ", ".join(f"{n} {l}" for l, n in sorted(labels.items())))
PY
```

Use that line as context in the email body.

### 4. Create the Gmail draft with the CSV attached

The claude.ai Gmail connector can only **create drafts** — it has no send
tool — and an attachment is passed as base64 with a combined 25 MB cap.

1. Base64-encode the export: `base64 < "$OUT"`.
2. Call `mcp__claude_ai_Gmail__create_draft` (load its schema via ToolSearch:
   `select:mcp__claude_ai_Gmail__create_draft`) with:
   - **to:** the recipient.
   - **subject:** `LLM Warden stats — <hostname> — <date>` (`hostname`;
     `date +%Y-%m-%d`).
   - **body:** the one-line summary from step 3.
   - **attachments:** one entry `{filename, mimeType: "text/csv", content: <base64>}`.
3. Verify with `mcp__claude_ai_Gmail__get_thread` (FULL_CONTENT) that the
   draft's `attachments` list contains the CSV.

**Size limit:** if the export is larger than ~20 MB it won't fit — base64
inflates it past the 25 MB cap and is impractical to pass through a tool
call. Bound the export instead: re-run step 2 with a `WHERE` clause
(flagged-only `WHERE label != 'clean'`, or recent-N `ORDER BY id DESC LIMIT
N`), or share the full CSV via a link rather than an attachment and say so in
the body.

### 5. Report back

This produces a **draft, not a sent message** — the connector cannot send on
its own. Tell the user: the recipient, the filename, the event count (from
step 3), the draft id, and that the draft is waiting in **Gmail → Drafts**
for them to review and click **Send**.

## Notes

- The recipient is overridable per invocation; default to `saumye@autollm.ai`
  only when the user didn't specify one.
- Never modify or delete the exported CSV after sending — leave it in the
  repo root so the user has a local copy of exactly what was sent.
- This skill reads the SQLite database **read-only** (`mode=ro`) through the
  container's Python; it never writes to the DB and never blocks the proxy.