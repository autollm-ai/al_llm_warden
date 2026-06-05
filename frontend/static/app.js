// LLM Warden — dashboard frontend.
// Pure vanilla JS, no build step. Polls the FastAPI backend on /api/*.

const $  = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const LABEL_ORDER = ["clean", "low", "medium", "high", "critical"];
const LABEL_COLOR = {
  clean: "#2BBF7E", low: "#5BA3F5", medium: "#F2A93B",
  high: "#F26C3B", critical: "#E83A5C",
};

let cachedProviders = new Set();

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) throw new Error(`${path} ${res.status}`);
  return res.json();
}

// ── HEADER STATS / HEALTH ────────────────────────────────────────────────────

async function loadHealth() {
  try {
    const h = await api("/api/health");
    const status = $("#proxy-status");
    if (h.status === "ok") {
      const parts = [h.tier2_enabled ? "Online · LSTM" : "Online · Regex"];
      if (h.test_mode) parts.push("test-mode");
      status.textContent = parts.join(" · ");
      status.classList.remove("badge-outline", "badge-warn");
      status.classList.add("badge-ok");
    }
    $("#api-info").textContent = `db: ${h.db}`;
    await refreshTestModeButton(h.test_mode);
  } catch (e) {
    const s = $("#proxy-status");
    s.textContent = "API unreachable";
    s.classList.remove("badge-outline", "badge-ok");
    s.classList.add("badge-warn");
  }
}

async function loadIdentity() {
  let signals = [];
  try {
    const r = await api("/api/identity");
    signals = r.signals || [];
  } catch { return; }

  // Pick the top-count entry per kind. There can only be a "single"
  // user identity per kind in practice; dups are rare false positives.
  const byKind = { email: null, ip: null };
  for (const s of signals) {
    if (!byKind[s.kind] || s.count > byKind[s.kind].count) byKind[s.kind] = s;
  }

  for (const kind of ["email", "ip"]) {
    const card = document.querySelector(`.identity-card[data-kind="${kind}"]`);
    const slot = card.querySelector(`[data-slot="${kind}"]`);
    const meta = card.querySelector(`[data-slot="${kind}-meta"]`);
    let evictBtn = card.querySelector(".identity-evict");

    const sig = byKind[kind];
    if (sig) {
      slot.textContent = sig.shown;
      const last = formatTime(sig.last_seen);
      meta.textContent = `Recognised after ${sig.count} recurrence${sig.count===1?"":"s"} · last seen ${last}`;
      card.classList.add("is-known");
      if (!evictBtn) {
        evictBtn = document.createElement("button");
        evictBtn.className = "identity-evict";
        evictBtn.textContent = "Evict";
        card.appendChild(evictBtn);
      }
      evictBtn.hidden = false;
      evictBtn.dataset.kind = sig.kind;
      evictBtn.dataset.value = sig.value;
    } else {
      slot.textContent = "—";
      meta.textContent = kind === "email"
        ? "Not yet identified · keep using LLM tools"
        : "Not yet identified";
      card.classList.remove("is-known");
      if (evictBtn) evictBtn.hidden = true;
    }
  }
}

document.addEventListener("click", async (e) => {
  if (!e.target.classList.contains("identity-evict")) return;
  const btn = e.target;
  const kind = btn.dataset.kind;
  const value = btn.dataset.value;
  if (!kind || !value) return;
  if (!confirm(`Stop treating ${value} as your own ${kind}?\n\nFuture occurrences will be flagged as PII again until it re-qualifies.`)) {
    return;
  }
  btn.disabled = true; btn.textContent = "Evicting…";
  try {
    const res = await fetch(`/api/identity/${encodeURIComponent(kind)}/${encodeURIComponent(value)}`,
                            { method: "DELETE" });
    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      try { const j = await res.json(); if (j.detail) msg += ` — ${j.detail}`; } catch {}
      alert("Evict failed: " + msg);
      btn.disabled = false; btn.textContent = "Evict";
      return;
    }
    await loadIdentity();
  } catch (err) {
    alert("Evict failed: " + err.message);
    btn.disabled = false; btn.textContent = "Evict";
  }
});

async function refreshTestModeButton(testModeOn) {
  const btn  = $("#export-jsonl");
  const info = $("#export-jsonl-info");
  if (!btn) return;
  if (!testModeOn) {
    btn.hidden = true;
    info.hidden = true;
    return;
  }
  btn.hidden = false;
  let stat;
  try { stat = await api("/api/test-mode"); }
  catch { return; }
  if (!stat.exists || stat.size === 0) {
    btn.disabled = true;
    info.hidden = false;
    info.textContent = "No captures yet — send a request through the proxy first.";
  } else {
    btn.disabled = false;
    info.hidden = false;
    info.textContent = `${fmtBytes(stat.size)} captured`;
  }
}

document.addEventListener("click", async (e) => {
  if (e.target.id !== "export-jsonl") return;
  e.preventDefault();
  try {
    const res = await fetch("/api/test-mode.jsonl");
    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      try { const j = await res.json(); if (j.detail) msg += ` — ${j.detail}`; } catch {}
      alert("Download failed: " + msg);
      return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const stamp = new Date().toISOString().replace(/[-:]/g,"").replace(/\..+/, "Z");
    a.download = `warden-test-mode-${stamp}.jsonl`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    alert("Download failed: " + err.message);
  }
});

function fmtNum(n) {
  if (n == null) return "0";
  if (n >= 1e9) return (n/1e9).toFixed(1) + "B";
  if (n >= 1e6) return (n/1e6).toFixed(1) + "M";
  if (n >= 1e3) return (n/1e3).toFixed(1) + "k";
  return String(n);
}

function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B","KB","MB","GB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n >= 100 ? 0 : 1)} ${u[i]}`;
}

async function loadSummary() {
  let s;
  try { s = await api("/api/summary"); }
  catch { return; }
  const flagged = LABEL_ORDER
    .filter(l => l !== "clean")
    .reduce((a, l) => a + (s.by_label?.[l] || 0), 0);
  $("#stat-total").textContent = fmtNum(s.total);
  $("#stat-flagged").textContent = fmtNum(flagged);
  $("#stat-providers").textContent = fmtNum((s.by_provider || []).length);
  $("#stat-bytes").textContent = fmtBytes(
    (s.by_provider || []).reduce((a, p) => a + (p.bytes_out || 0), 0)
  );

  const grid = $("#provider-grid");
  if (!s.by_provider || s.by_provider.length === 0) {
    grid.innerHTML = `<div class="empty-state">
      <strong>No traffic yet.</strong><br/>
      Run the one-line installer once, then open
      <a href="https://chatgpt.com" target="_blank" rel="noopener">chatgpt.com</a>,
      <a href="https://claude.ai" target="_blank" rel="noopener">claude.ai</a>,
      or any other LLM tool. Events will appear here automatically.
      <pre style="margin-top: var(--sp-4); background: var(--mp-near-black); color: #e0e0e0; border-radius: var(--r-md); padding: 14px 16px; font-family: var(--font-mono); font-size: 12px; overflow-x: auto; text-align: left;">bash scripts/install-mac.sh</pre>
      <span style="display:block; margin-top: 8px; color: var(--mp-text-tertiary); font-size: 12px;">
        Trusts the certificate, flips the macOS system proxy, and verifies the path. Reverse with <code>scripts/uninstall-mac.sh</code>.
      </span>
    </div>`;
    return;
  }
  grid.innerHTML = s.by_provider.map(p => {
    const sens = Math.round((p.avg_sensitivity || 0) * 100);
    const max  = Math.round((p.max_sensitivity || 0) * 100);
    const color = sens >= 65 ? LABEL_COLOR.high
                : sens >= 40 ? LABEL_COLOR.medium
                : sens >= 15 ? LABEL_COLOR.low
                : LABEL_COLOR.clean;
    return `<div class="provider-card">
      <div class="provider-card-head">
        <div class="provider-name">${escapeHtml(p.provider)}</div>
        <span class="badge badge-purple">${fmtNum(p.events)} events</span>
      </div>
      <div class="provider-meta">
        <span>avg sens <b>${sens}%</b></span>
        <span>max <b>${max}%</b></span>
        <span>out <b>${fmtBytes(p.bytes_out || 0)}</b></span>
      </div>
      <div class="sensitivity-bar"><div style="width:${sens}%; background:${color}"></div></div>
    </div>`;
  }).join("");

  // Populate provider filter
  const sel = $("#filter-provider");
  const seen = new Set();
  s.by_provider.forEach(p => seen.add(p.provider));
  if (![...seen].every(x => cachedProviders.has(x)) || seen.size !== cachedProviders.size) {
    cachedProviders = seen;
    const cur = sel.value;
    sel.innerHTML = `<option value="">All providers</option>` +
      [...seen].map(p => `<option value="${escapeAttr(p)}">${escapeHtml(p)}</option>`).join("");
    sel.value = cur;
  }
}

// ── EVENT TABLE ──────────────────────────────────────────────────────────────

async function loadEvents() {
  const provider = $("#filter-provider").value;
  const minSens = $("#filter-sensitivity").value;
  const intent = $("#filter-intent").value;
  const direction = $("#filter-direction") ? $("#filter-direction").value : "";
  const params = new URLSearchParams({ limit: "100" });
  if (provider) params.set("provider", provider);
  if (minSens) params.set("min_sensitivity", minSens);
  if (intent) params.set("intent", intent);
  if (direction) params.set("direction", direction);
  let data;
  try { data = await api(`/api/events?${params}`); }
  catch (e) {
    $("#event-tbody").innerHTML = `<tr><td colspan="10" class="empty">Failed to load events.</td></tr>`;
    return;
  }
  const rows = data.events;
  if (!rows.length) {
    $("#event-tbody").innerHTML = `<tr><td colspan="10" class="empty">No events match these filters yet.</td></tr>`;
    return;
  }
  $("#event-tbody").innerHTML = rows.map(r => {
    // Show the post-intent (effective) score in the badge so the colour
    // band reflects what users should actually act on. Fall back to raw
    // sensitivity for legacy rows captured before intent existed.
    const eff = (r.effective_sensitivity ?? 0) || r.sensitivity || 0;
    const sens = Math.round(eff * 100);
    const cats = r.categories?.length
      ? r.categories.map(c => {
          const cls = c === "user_identity" ? "badge-identity" : "badge-purple";
          const label = c === "user_identity" ? "your identity" : c;
          return `<span class="badge ${cls}">${escapeHtml(label)}</span>`;
        }).join("")
      : `<span class="badge badge-outline">none</span>`;
    const intentBadge = r.intent
      ? `<span class="badge badge-outline" title="confidence ${(r.intent_conf*100|0)}%">${escapeHtml(r.intent)}</span>`
      : `<span class="badge badge-outline">—</span>`;
    // Direction arrow: ↑ (request: client → model) or ↓ (response: model → client).
    const isResp = r.direction === "response";
    const dirBadge = `<span class="badge ${isResp ? 'badge-purple' : 'badge-outline'}"
      title="${isResp ? 'model response' : 'outbound request'}">${isResp ? '↓ R' : '↑ Q'}</span>`;
    return `<tr>
      <td class="event-time">${escapeHtml(formatTime(r.ts))}</td>
      <td>${dirBadge}</td>
      <td>${escapeHtml(r.provider)}</td>
      <td>${intentBadge}</td>
      <td><code>${escapeHtml(r.method)}</code></td>
      <td><span class="event-path" title="${escapeAttr(r.path)}">${escapeHtml(r.path)}</span></td>
      <td><span class="badge badge-${r.label}">${r.label} · ${sens}%</span></td>
      <td><span class="event-cats">${cats}</span></td>
      <td class="event-summary">${escapeHtml(r.summary)}</td>
      <td><button class="row-link" data-id="${r.id}">View →</button></td>
    </tr>`;
  }).join("");

  $$("#event-tbody .row-link").forEach(btn => {
    btn.addEventListener("click", () => openDetail(btn.dataset.id));
  });
}

// ── DOMAIN REGISTRY ──────────────────────────────────────────────────────────

async function loadDomains() {
  const tbody = $("#domain-tbody");
  if (!tbody) return;
  let data;
  try { data = await api("/api/domains"); }
  catch {
    tbody.innerHTML = `<tr><td colspan="5" class="empty">Failed to load domains.</td></tr>`;
    return;
  }
  const rows = data.domains || [];
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty">No domains configured.</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map(d => {
    const enabled = d.enabled === 1 || d.enabled === true;
    const sourceBadge = d.source === "seed"
      ? `<span class="badge badge-outline" title="Built-in default">seed</span>`
      : `<span class="badge badge-purple" title="Added from this UI">user</span>`;
    return `<tr data-host="${escapeAttr(d.host)}">
      <td><code>${escapeHtml(d.host)}</code></td>
      <td>${escapeHtml(d.label || "")}</td>
      <td>${sourceBadge}</td>
      <td>
        <label class="domain-toggle" title="Toggle monitoring for this host">
          <input type="checkbox" class="domain-enabled" ${enabled ? "checked" : ""} />
          <span>${enabled ? "monitored" : "ignored"}</span>
        </label>
      </td>
      <td><button class="row-link domain-remove" data-host="${escapeAttr(d.host)}">Remove</button></td>
    </tr>`;
  }).join("");

  tbody.querySelectorAll(".domain-enabled").forEach(cb => {
    cb.addEventListener("change", async (e) => {
      const host = e.target.closest("tr").dataset.host;
      try {
        const res = await fetch(`/api/domains/${encodeURIComponent(host)}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: e.target.checked }),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      } catch (err) {
        alert("Toggle failed: " + err.message);
        e.target.checked = !e.target.checked;
        return;
      }
      loadDomains();
    });
  });
  tbody.querySelectorAll(".domain-remove").forEach(btn => {
    btn.addEventListener("click", async (e) => {
      const host = btn.dataset.host;
      if (!confirm(`Stop monitoring ${host}?\n\nFuture traffic to this host will pass through Warden untouched (no logs, no scoring).`)) {
        return;
      }
      btn.disabled = true; btn.textContent = "Removing…";
      try {
        const res = await fetch(`/api/domains/${encodeURIComponent(host)}`, { method: "DELETE" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      } catch (err) {
        alert("Remove failed: " + err.message);
        btn.disabled = false; btn.textContent = "Remove";
        return;
      }
      loadDomains();
    });
  });
}

const domainAddForm = $("#domain-add-form");
if (domainAddForm) {
  domainAddForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const host = $("#domain-host").value.trim();
    const label = $("#domain-label").value.trim();
    if (!host) return;
    try {
      const res = await fetch("/api/domains", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host, label: label || null }),
      });
      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try { const j = await res.json(); if (j.detail) msg += ` — ${j.detail}`; } catch {}
        alert("Add failed: " + msg);
        return;
      }
      $("#domain-host").value = "";
      $("#domain-label").value = "";
      loadDomains();
    } catch (err) {
      alert("Add failed: " + err.message);
    }
  });
}

function formatTime(iso) {
  if (!iso) return "";
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  } catch { return iso; }
}

// ── EVENT DETAIL MODAL ───────────────────────────────────────────────────────

async function openDetail(id) {
  let r;
  try { r = await api(`/api/events/${id}`); }
  catch { return; }
  const hits = (r.hits || []).map(h => {
    const isIdentity = h.category === "user_identity";
    const cls = isIdentity ? "badge-identity" : "badge-purple";
    const label = isIdentity ? "your identity (exempt)" : h.category;
    return `<li><span class="badge ${cls}">${escapeHtml(label)}</span>
         <code>${escapeHtml(h.name)}</code>
         <span style="margin-left:auto; color: var(--mp-text-secondary)">${escapeHtml(h.snippet)}</span></li>`;
  }).join("") || `<li style="color: var(--mp-text-tertiary)">No deterministic hits.</li>`;

  const ANNOTATE_OPTIONS = ["false_positive", "clean", "low", "medium", "high", "critical"];
  const currentGtl = r.ground_truth_label || "";
  const annotationBtns = ANNOTATE_OPTIONS.map(l =>
    `<button class="btn btn-sm annotate-btn ${currentGtl === l ? "btn-primary" : "btn-secondary"}"
             data-label="${escapeAttr(l)}">${escapeHtml(l)}</button>`
  ).join("") +
    `<button class="btn btn-sm btn-secondary annotate-btn" data-label="">Clear</button>`;

  $("#modal-body").innerHTML = `
    <h3 style="font-size: 22px; font-weight: 700; letter-spacing: -0.02em; margin-bottom: 4px">
      Event #${r.id} — ${escapeHtml(r.provider)}
    </h3>
    <p style="color: var(--mp-text-secondary); font-size: 14px; margin-bottom: 24px">
      ${escapeHtml(r.summary)}
    </p>
    <dl>
      <div class="detail-row"><dt>Time</dt><dd>${escapeHtml(r.ts)}</dd></div>
      <div class="detail-row"><dt>Host</dt><dd>${escapeHtml(r.host)}</dd></div>
      <div class="detail-row"><dt>Request</dt><dd><code>${escapeHtml(r.method)} ${escapeHtml(r.path)}</code></dd></div>
      <div class="detail-row"><dt>Sensitivity</dt>
        <dd><span class="badge badge-${r.label}">${r.label}</span>
            &nbsp;effective ${((r.effective_sensitivity ?? r.sensitivity)*100).toFixed(0)}%
            &nbsp;<span style="color: var(--mp-text-tertiary)">(raw ${(r.sensitivity*100).toFixed(0)}%,
            regex ${(r.tier1_score*100).toFixed(0)}%,
            lstm ${(r.tier2_score*100).toFixed(0)}%)</span></dd></div>
      <div class="detail-row"><dt>Intent</dt>
        <dd>${escapeHtml(r.intent || "unknown")}
            <span style="color: var(--mp-text-tertiary)">&nbsp;(conf ${((r.intent_conf||0)*100).toFixed(0)}%)</span></dd></div>
      <div class="detail-row"><dt>Bytes out</dt><dd>${fmtBytes(r.bytes_out)}</dd></div>
      <div class="detail-row"><dt>Categories</dt>
        <dd>${(r.categories||[]).map(c=>`<span class="badge badge-purple">${escapeHtml(c)}</span>`).join(" ") || "<em>none</em>"}</dd></div>
      <div class="detail-row"><dt>Regex hits</dt><dd><ul class="hits-list">${hits}</ul></dd></div>
      <div class="detail-row"><dt>Request preview</dt>
        <dd><pre class="copy-block">${escapeHtml(r.sample || "")}</pre></dd></div>
      <div class="detail-row">
        <dt>Ground truth</dt>
        <dd>
          <div class="annotate-btns" data-event-id="${r.id}" style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:6px">
            ${annotationBtns}
          </div>
          <span class="annotate-feedback" style="font-size:13px; color: var(--mp-text-secondary)">
            ${currentGtl ? `Saved: ${escapeHtml(currentGtl)}` : "Not annotated yet"}
          </span>
        </dd>
      </div>
    </dl>`;
  $("#modal").hidden = false;
}

$("#modal-close").addEventListener("click", () => { $("#modal").hidden = true; });
$("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") $("#modal").hidden = true; });

// ── TEST CLASSIFIER ──────────────────────────────────────────────────────────

$("#test-run").addEventListener("click", async () => {
  const text = $("#test-text").value.trim();
  if (!text) return;
  const out = $("#test-result");
  out.hidden = false;
  out.textContent = "Classifying…";
  try {
    const r = await api("/api/classify", {
      method: "POST", body: JSON.stringify({ text }),
    });
    out.textContent = JSON.stringify(r, null, 2);
  } catch (e) {
    out.textContent = `Error: ${e.message}`;
  }
});

$("#refresh-btn").addEventListener("click", refresh);
$("#filter-provider").addEventListener("change", loadEvents);
$("#filter-sensitivity").addEventListener("change", loadEvents);
$("#filter-intent").addEventListener("change", loadEvents);
if ($("#filter-direction")) $("#filter-direction").addEventListener("change", loadEvents);

// Keep the CSV export URL in sync with the active filters so users download
// exactly what they see on screen.
function updateExportHref() {
  const provider = $("#filter-provider").value;
  const minSens  = $("#filter-sensitivity").value || "0.15";
  const intent   = $("#filter-intent").value;
  const params = new URLSearchParams({ limit: "10000", min_sensitivity: minSens });
  if (provider) params.set("provider", provider);
  if (intent)   params.set("intent", intent);
  $("#export-csv").href = `/api/events.csv?${params}`;
}
$("#filter-provider").addEventListener("change", updateExportHref);
$("#filter-sensitivity").addEventListener("change", updateExportHref);
$("#filter-intent").addEventListener("change", updateExportHref);
updateExportHref();

// ── HELPERS ──────────────────────────────────────────────────────────────────

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function escapeAttr(s) { return escapeHtml(s); }

// ── BROWSER ALERTS FOR CRITICAL RESPONSE EVENTS ─────────────────────────────
// Fires a Notification when a new event with direction=response and
// label=critical lands. Triggers regardless of the dashboard's filter
// settings — the user might be browsing requests when a destructive
// command surfaces in a model response.
const ALERT_STORAGE_KEY = "warden:alerts:enabled";
const ALERT_LAST_ID_KEY = "warden:alerts:lastId";
let alertsEnabled = localStorage.getItem(ALERT_STORAGE_KEY) === "1";
let alertsLastSeenId = parseInt(localStorage.getItem(ALERT_LAST_ID_KEY) || "0", 10) || 0;
let alertsPrimed = false; // skip notifications on the first poll after page load

function renderAlertsButton() {
  const btn = $("#alerts-btn");
  if (!btn) return;
  if (typeof Notification === "undefined") {
    btn.textContent = "Alerts unsupported";
    btn.disabled = true;
    return;
  }
  if (alertsEnabled && Notification.permission === "granted") {
    btn.textContent = "🔔 Alerts on";
    btn.classList.add("btn-primary");
    btn.classList.remove("btn-secondary");
  } else {
    btn.textContent = "Enable alerts";
    btn.classList.add("btn-secondary");
    btn.classList.remove("btn-primary");
  }
}

async function toggleAlerts() {
  if (typeof Notification === "undefined") return;
  if (alertsEnabled) {
    alertsEnabled = false;
    localStorage.setItem(ALERT_STORAGE_KEY, "0");
    renderAlertsButton();
    return;
  }
  let perm = Notification.permission;
  if (perm === "default") perm = await Notification.requestPermission();
  if (perm !== "granted") {
    alert("Notifications were blocked. Re-enable them in your browser's site settings to use this.");
    return;
  }
  alertsEnabled = true;
  alertsPrimed = false; // baseline next poll so old events don't fire on toggle-on
  localStorage.setItem(ALERT_STORAGE_KEY, "1");
  renderAlertsButton();
}

async function pollCriticalResponses() {
  if (!alertsEnabled || typeof Notification === "undefined" || Notification.permission !== "granted") return;
  let data;
  try { data = await api(`/api/events?limit=20&direction=response`); } catch { return; }
  const rows = data.events || [];
  if (!rows.length) return;
  const newest = rows[0].id;
  if (!alertsPrimed) {
    // Don't notify on whatever was already in the DB when the dashboard opened.
    alertsLastSeenId = Math.max(alertsLastSeenId, newest);
    localStorage.setItem(ALERT_LAST_ID_KEY, String(alertsLastSeenId));
    alertsPrimed = true;
    return;
  }
  const fresh = rows
    .filter(r => r.id > alertsLastSeenId && r.label === "critical")
    .reverse(); // oldest first so the most recent ends up on top of the OS stack
  for (const r of fresh) {
    try {
      const n = new Notification(`⚠ Destructive command in ${r.provider} response`, {
        body: r.summary || `${r.method} ${r.path}`,
        tag: `warden-${r.id}`,
        requireInteraction: false,
      });
      n.onclick = () => { window.focus(); openDetail(r.id); n.close(); };
    } catch (e) { /* notification API errors are non-fatal */ }
  }
  alertsLastSeenId = newest;
  localStorage.setItem(ALERT_LAST_ID_KEY, String(alertsLastSeenId));
}

if ($("#alerts-btn")) $("#alerts-btn").addEventListener("click", toggleAlerts);
renderAlertsButton();

// ── ANNOTATION BUTTONS ───────────────────────────────────────────────────────

document.addEventListener("click", async (e) => {
  if (!e.target.classList.contains("annotate-btn")) return;
  const btn = e.target;
  const container = btn.closest(".annotate-btns");
  if (!container) return;
  const eventId = container.dataset.eventId;
  const label = btn.dataset.label || null;
  const feedback = container.parentElement.querySelector(".annotate-feedback");
  btn.disabled = true;
  try {
    await api(`/api/events/${eventId}`, {
      method: "PATCH",
      body: JSON.stringify({ ground_truth_label: label }),
    });
    container.querySelectorAll(".annotate-btn").forEach(b => {
      b.classList.remove("btn-primary");
      b.classList.add("btn-secondary");
    });
    if (label) {
      btn.classList.remove("btn-secondary");
      btn.classList.add("btn-primary");
    }
    if (feedback) {
      feedback.textContent = label ? `Saved: ${label}` : "Cleared";
    }
  } catch (err) {
    if (feedback) feedback.textContent = "Save failed: " + err.message;
  } finally {
    btn.disabled = false;
  }
});

// ── JSON EXPORT ──────────────────────────────────────────────────────────────

document.addEventListener("click", async (e) => {
  if (e.target.id !== "export-json") return;
  e.preventDefault();
  const btn = e.target;
  btn.disabled = true;
  btn.textContent = "Exporting…";
  try {
    const res = await fetch("/api/events/export.json");
    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      try { const j = await res.json(); if (j.detail) msg += ` — ${j.detail}`; } catch {}
      alert("Export failed: " + msg);
      return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "Z");
    a.download = `warden-events-${stamp}.json`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    alert("Export failed: " + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Export all (JSON)";
  }
});

// ── CLAUDE TERMINAL COMMAND ───────────────────────────────────────────────────

function updateClaudeCmd() {
  const count = parseInt($("#claude-count")?.value || "50", 10) || 50;
  const cmdEl = $("#claude-gen-cmd");
  if (cmdEl) cmdEl.textContent = `python scripts/generate_real_traffic.py --claude-only --count ${count}`;
}

const claudeCountInput = $("#claude-count");
if (claudeCountInput) claudeCountInput.addEventListener("input", updateClaudeCmd);
updateClaudeCmd();

document.addEventListener("click", async (e) => {
  if (e.target.id !== "claude-cmd-copy") return;
  const cmd = $("#claude-gen-cmd")?.textContent || "";
  try {
    await navigator.clipboard.writeText(cmd);
    e.target.textContent = "Copied!";
    setTimeout(() => { e.target.textContent = "Copy command"; }, 2000);
  } catch {
    e.target.textContent = "Select the box above";
    setTimeout(() => { e.target.textContent = "Copy command"; }, 2000);
  }
});

async function loadAnthropicEventCount() {
  try {
    const data = await api("/api/events?provider=Anthropic&limit=1");
    // The API returns a count indirectly — check total via summary
    const s = await api("/api/summary");
    const byProvider = s.by_provider || [];
    const ant = byProvider.find(p => p.provider === "Anthropic");
    const el = $("#anthropic-event-count");
    if (el) el.textContent = fmtNum(ant ? ant.events : 0);
  } catch { /* ignore */ }
}

// ── API KEY STATUS ────────────────────────────────────────────────────────────

async function loadKeyStatus() {
  let keys;
  try { keys = await api("/api/config/keys"); }
  catch { return; }

  const oaiEl  = $("#key-openai");
  if (oaiEl) {
    oaiEl.textContent = keys.has_openai ? "OpenAI: configured" : "OpenAI: not set";
    oaiEl.className = keys.has_openai ? "badge badge-ok" : "badge badge-warn";
  }
}

// ── GENERATE REAL LLM EVENTS ──────────────────────────────────────────────────

function fmtEta(seconds) {
  if (seconds == null) return "—";
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

async function loadRealGenStatus() {
  let s;
  try { s = await api("/api/events/generate-real/status"); }
  catch { return; }

  const doneEl = $("#real-gen-done");
  const okEl   = $("#real-gen-ok");
  const etaEl  = $("#real-gen-eta");
  const hintEl = $("#real-gen-hint");
  const btn    = $("#real-gen-btn");

  if (doneEl) doneEl.textContent = s.total ? `${fmtNum(s.done)} / ${fmtNum(s.total)}` : fmtNum(s.done || 0);
  if (okEl)   okEl.textContent = fmtNum(s.ok || 0);
  if (etaEl)  etaEl.textContent = s.running ? fmtEta(s.eta_seconds) : (s.finished_at ? "Done" : "—");
  if (hintEl) {
    hintEl.textContent = s.running
      ? `Running at ${s.rate || "?"} calls/s…`
      : (s.finished_at ? `Finished ${formatTime(s.finished_at)} · ${s.ok || 0} responses recorded` : "");
  }
  if (btn) btn.disabled = !!s.running;
}

const realGenBtn = $("#real-gen-btn");
if (realGenBtn) {
  realGenBtn.addEventListener("click", async () => {
    const openaiCount = parseInt($("#openai-count")?.value || "0", 10);
    if (openaiCount < 1) {
      alert("Enter at least 1 for OpenAI calls."); return;
    }
    const estMin = Math.ceil(openaiCount * 2 / 60);
    if (!confirm(
      `Make ${openaiCount.toLocaleString()} real OpenAI API calls?\n\n` +
      `This will consume API credits. Estimated time: ~${estMin} min.\n` +
      `Each call generates up to 2 events (request + response).`
    )) return;

    realGenBtn.disabled = true;
    realGenBtn.textContent = "Starting…";
    try {
      await api("/api/events/generate-real", {
        method: "POST",
        body: JSON.stringify({ openai_count: openaiCount }),
      });
      const hintEl = $("#real-gen-hint");
      if (hintEl) hintEl.textContent = "Started — progress updates every few seconds.";
      await loadRealGenStatus();
    } catch (err) {
      alert("Failed to start: " + err.message);
      realGenBtn.disabled = false;
    } finally {
      realGenBtn.textContent = "Generate OpenAI events";
    }
  });
}

// ── PIPELINE SUMMARY ────────────────────────────────────────────────────────

async function loadPipelineSummary() {
  let summary, annSummary;
  try { summary    = await api("/api/summary"); }            catch { return; }
  try { annSummary = await api("/api/annotation/summary"); } catch { annSummary = {}; }

  const total      = summary.total || 0;
  const annotated  = annSummary.annotated || 0;
  const unannotated = Math.max(0, total - annotated);
  const coverage   = annSummary.coverage_pct ?? (total > 0 ? Math.round((annotated / total) * 100) : 0);

  setText("ps-total",       fmtNum(total));
  setText("ps-annotated",   fmtNum(annotated));
  setText("ps-unannotated", fmtNum(unannotated));
  setText("ps-coverage",    coverage + "%");

  const fill = document.getElementById("ps-coverage-fill");
  if (fill) fill.style.width = coverage + "%";

  // Use ground_truth_label distribution (not classifier labels)
  const byLabel = annSummary.by_ground_truth_label || {};
  const labelOrder = ["false_positive", "clean", "low", "medium", "high", "critical"];
  const labelColors = {
    false_positive: "#aaa", clean: "#2BBF7E", low: "#5BA3F5",
    medium: "#F2A93B", high: "#F26C3B", critical: "#E83A5C",
  };

  labelOrder.forEach(l => {
    const el = document.getElementById("ps-ann-" + (l === "false_positive" ? "fp" : l));
    if (el) el.textContent = fmtNum(byLabel[l] || 0);
  });

  // Stacked bar from ground_truth_label counts
  const bar = document.getElementById("ps-stacked-bar");
  if (bar) {
    const totalLabeled = labelOrder.reduce((a, l) => a + (byLabel[l] || 0), 0) || 1;
    bar.innerHTML = labelOrder.map(l => {
      const pct = ((byLabel[l] || 0) / totalLabeled * 100).toFixed(1);
      return `<span style="flex:${pct};background:${labelColors[l]}" title="${l}: ${byLabel[l]||0}"></span>`;
    }).join("");
  }

  // Label dist pills — ground_truth only
  const distEl = document.getElementById("ps-label-dist");
  if (distEl) {
    distEl.innerHTML = Object.entries(byLabel)
      .sort((a, b) => b[1] - a[1])
      .map(([l, n]) => `<span class="badge badge-${l}" style="background:${labelColors[l]}20;color:${labelColors[l]};border-color:${labelColors[l]}40">${l} ${fmtNum(n)}</span>`)
      .join("");
  }

  // Model card — populated from training/status metrics
  let training = {};
  try { training = await api("/api/training/status"); } catch { /* no model yet */ }
  const m = training.metrics || {};
  const h = m.history || [];
  setText("ps-model-mode",   m.vocab_size ? "BiLSTM + CRF" : "Regex-only");
  setText("ps-model-params", m.params    ? fmtNum(m.params) : "—");
  setText("ps-model-vocab",  m.vocab_size ? fmtNum(m.vocab_size) : "—");
  const td = m.test_doc || {};
  setText("ps-model-valf1",  m.best_val_doc_f1 != null ? (m.best_val_doc_f1 * 100).toFixed(2) + "%" : "—");
  setText("ps-model-testf1", td.f1 != null ? (td.f1 * 100).toFixed(2) + "%" : "—");
  setText("ps-model-device", m.device || "—");
}

// ── TRAINING PANEL ───────────────────────────────────────────────────────────

async function loadTrainingStatus() {
  let s;
  try { s = await api("/api/training/status"); } catch { return; }

  const annotatedEl = $("#training-annotated");
  const coverageEl  = $("#training-coverage");
  const statusEl    = $("#training-status-text");
  const valf1El     = $("#training-valf1");
  const testf1El    = $("#training-testf1");
  const hintEl      = $("#training-hint");

  if (annotatedEl) annotatedEl.textContent = fmtNum(s.annotated_count || 0);

  // coverage from annotation summary
  try {
    const ann = await api("/api/annotation/summary");
    if (coverageEl) coverageEl.textContent = (ann.coverage_pct ?? 0) + "%";
  } catch { /* ignore */ }

  if (statusEl) {
    statusEl.textContent = s.running
      ? "Training…"
      : (s.finished_at ? `Done ${formatTime(s.finished_at)}` : "Idle");
  }

  const m = s.metrics || {};
  const td = m.test_doc || {};
  if (valf1El)  valf1El.textContent  = m.best_val_doc_f1 != null ? (m.best_val_doc_f1 * 100).toFixed(1) + "%" : "—";
  if (testf1El) testf1El.textContent = td.f1 != null ? (td.f1 * 100).toFixed(1) + "%" : "—";

  if (hintEl) {
    hintEl.textContent = s.annotated_count === 0
      ? "Label some events in the Events table first."
      : (s.running ? "Training in progress — refresh in a few minutes." : "");
  }
}

const trainingStartBtn = $("#training-start-btn");
if (trainingStartBtn) {
  trainingStartBtn.addEventListener("click", async () => {
    if (!confirm(
      "Start retraining the LSTM classifier?\n\n" +
      "This runs in the background and may take several minutes. " +
      "The proxy keeps scoring traffic normally while it runs."
    )) return;
    trainingStartBtn.disabled = true;
    trainingStartBtn.textContent = "Starting…";
    try {
      const r = await api("/api/training/start", { method: "POST", body: JSON.stringify({}) });
      const log = $("#training-log");
      if (log) {
        log.hidden = false;
        log.textContent =
          `Training started (PID ${r.pid}).\n` +
          `Using ${r.annotated_samples} annotated samples.\n` +
          `Refresh in a few minutes to see val F1 update.`;
      }
      await loadTrainingStatus();
    } catch (err) {
      alert("Failed to start training: " + err.message);
    } finally {
      trainingStartBtn.disabled = false;
      trainingStartBtn.textContent = "Start retraining";
    }
  });
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

async function refresh() {
  await Promise.all([
    loadHealth(), loadSummary(), loadEvents(),
    loadIdentity(), loadDomains(),
    pollCriticalResponses(),
    loadKeyStatus(), loadAnthropicEventCount(),
    loadRealGenStatus(), loadTrainingStatus(),
    loadPipelineSummary(),
  ]);
}

refresh();
setInterval(refresh, 5000);
