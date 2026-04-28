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
      status.textContent = h.tier2_enabled ? "Online · LSTM" : "Online · Regex";
      status.classList.remove("badge-outline", "badge-warn");
      status.classList.add("badge-ok");
    }
    $("#api-info").textContent = `db: ${h.db}`;
  } catch (e) {
    const s = $("#proxy-status");
    s.textContent = "API unreachable";
    s.classList.remove("badge-outline", "badge-ok");
    s.classList.add("badge-warn");
  }
}

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
      Point your LLM client at <code>http://localhost:8080</code> and start chatting.
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
  const params = new URLSearchParams({ limit: "100" });
  if (provider) params.set("provider", provider);
  if (minSens) params.set("min_sensitivity", minSens);
  let data;
  try { data = await api(`/api/events?${params}`); }
  catch (e) {
    $("#event-tbody").innerHTML = `<tr><td colspan="8" class="empty">Failed to load events.</td></tr>`;
    return;
  }
  const rows = data.events;
  if (!rows.length) {
    $("#event-tbody").innerHTML = `<tr><td colspan="8" class="empty">No events match these filters yet.</td></tr>`;
    return;
  }
  $("#event-tbody").innerHTML = rows.map(r => {
    const sens = Math.round(r.sensitivity * 100);
    const cats = r.categories?.length
      ? r.categories.map(c => `<span class="badge badge-purple">${escapeHtml(c)}</span>`).join("")
      : `<span class="badge badge-outline">none</span>`;
    return `<tr>
      <td class="event-time">${escapeHtml(formatTime(r.ts))}</td>
      <td>${escapeHtml(r.provider)}</td>
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
  const hits = (r.hits || []).map(h =>
    `<li><span class="badge badge-purple">${escapeHtml(h.category)}</span>
         <code>${escapeHtml(h.name)}</code>
         <span style="margin-left:auto; color: var(--mp-text-secondary)">${escapeHtml(h.snippet)}</span></li>`
  ).join("") || `<li style="color: var(--mp-text-tertiary)">No deterministic hits.</li>`;
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
            &nbsp;${(r.sensitivity*100).toFixed(0)}%
            (regex ${(r.tier1_score*100).toFixed(0)}%, lstm ${(r.tier2_score*100).toFixed(0)}%)</dd></div>
      <div class="detail-row"><dt>Bytes out</dt><dd>${fmtBytes(r.bytes_out)}</dd></div>
      <div class="detail-row"><dt>Categories</dt>
        <dd>${(r.categories||[]).map(c=>`<span class="badge badge-purple">${escapeHtml(c)}</span>`).join(" ") || "<em>none</em>"}</dd></div>
      <div class="detail-row"><dt>Regex hits</dt><dd><ul class="hits-list">${hits}</ul></dd></div>
      <div class="detail-row"><dt>Request preview</dt>
        <dd><pre class="copy-block">${escapeHtml(r.sample || "")}</pre></dd></div>
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

// ── HELPERS ──────────────────────────────────────────────────────────────────

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function escapeAttr(s) { return escapeHtml(s); }

async function refresh() {
  await Promise.all([loadHealth(), loadSummary(), loadEvents()]);
}

refresh();
setInterval(refresh, 5000);
