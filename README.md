# LLM Warden

A local proxy + dashboard that watches every outbound request to shadow-AI
tools (ChatGPT, Claude, Claude Code, Gemini, Mistral, Perplexity, …) and
scores it for sensitive content **before** it leaves your laptop.

- **Tier-1 — regex engine:** deterministic detection of API keys, AWS
  credentials, SSNs, credit cards, IBANs, JWTs, internal hostnames, etc.
- **Tier-2 — BPE + LSTM:** a small bidirectional LSTM trained on
  ~200-token windows of synthetic data so the model can flag *semantically*
  sensitive prose (medical notes, financials, internal strategy) that the
  regexes miss.
- **Local-only:** SQLite event store, the dashboard runs on `localhost`,
  and **nothing is shipped off your machine.**
- **One command:** `docker compose up` brings up the proxy, the API, the
  dashboard, and the model.

---

## Quick start — two commands

You need Docker (Docker Desktop / Colima / Orbstack on macOS, or Docker
Engine + the compose plugin on Linux) and `git`. That's it.

**macOS:**

```bash
git clone <this-repo> al_llm_warden
cd al_llm_warden
docker compose up -d --build              # boots warden in the background
bash scripts/install-mac.sh               # trusts the CA + flips the macOS proxy
```

**Linux** (Ubuntu/Debian, Fedora/RHEL, Arch, openSUSE):

```bash
git clone <this-repo> al_llm_warden
cd al_llm_warden
docker compose up -d --build              # boots warden in the background
bash scripts/install-linux.sh             # trusts the CA + flips the GNOME proxy
```

That's it. Now open `chatgpt.com`, `claude.ai`, `gemini.google.com`, or any
LLM tool in your normal browser — events appear at
<http://localhost:8090>. Nothing else to configure.

To revert (turn the proxy off, remove the certificate):

```bash
bash scripts/uninstall-mac.sh             # macOS
bash scripts/uninstall-linux.sh           # Linux
docker compose down                       # add -v to also wipe the SQLite + model volumes
```

What `install-mac.sh` does, in order:

1. Waits for `warden-proxy` to be healthy.
2. Pulls `mitmproxy-ca-cert.pem` out of the container.
3. Trusts that CA in the macOS System keychain (1 sudo prompt).
4. Sets the system-wide HTTP+HTTPS proxy to `127.0.0.1:8080`, with a
   localhost bypass so the dashboard isn't proxied.
5. Verifies the proxy is in the path with a real HTTPS request.

What `install-linux.sh` does, in order:

1. Waits for `warden-proxy` to be healthy.
2. Pulls `mitmproxy-ca-cert.pem` out of the container.
3. Installs the CA into the system trust store via the right tool for
   your distro (`update-ca-certificates`, `update-ca-trust`, or
   `trust extract-compat`).
4. Auto-installs `libnss3-tools` (or your distro's equivalent) if
   needed — Chrome and Firefox on Linux read their own per-user NSS DB,
   *not* the system trust store, so this is required.
5. Adds the CA to that NSS DB plus any Firefox profiles (system path,
   Snap path, and Snap Chromium / Snap google-chrome paths) so the
   browser accepts it without a manual import.
6. On GNOME, sets `org.gnome.system.proxy` to `manual` →
   `127.0.0.1:8080` with a localhost bypass. On other desktops it
   prints the env-var lines to add to your shell rc.
7. Verifies the proxy is in the path with a real HTTPS request.

If you ran the installer under `sudo`, the script automatically routes
the GNOME-proxy and NSS-DB steps to `$SUDO_USER`'s session/home — so you
get the same result as running it as your normal user. **You must fully
quit Chrome (`pkill -f 'chrome|chromium'`) before reopening** — Chrome
caches the NSS trust DB at process start and a backgrounded helper will
keep stale state pinned across window reopens.

When `docker compose up` boots for the first time it generates synthetic
training data and trains the BPE tokenizer + LSTM (a few minutes on CPU).
Subsequent starts are instant — the model is cached in a named volume. If
you ship a pre-trained `models/lstm.pt` + `models/bpe.json` in the repo,
training is skipped entirely on first boot.

Two services run inside the stack:

| Service       | URL                       | What it does                              |
| ------------- | ------------------------- | ----------------------------------------- |
| `warden-proxy`| `http://localhost:8080`   | mitmproxy listener (the system proxy points here) |
| `warden-api`  | `http://localhost:8090`   | Dashboard + JSON API — open this in your browser |

> **Non-GNOME Linux:** `install-linux.sh` still installs the CA system-
> wide and into the NSS DB; the system-proxy step is skipped and the
> script prints the `HTTP_PROXY` / `HTTPS_PROXY` env vars to add to your
> shell rc (or your DE's network panel) so CLIs and GUI apps pick it up.

---

## Routing your tools through the proxy

### 1. Trust the mitmproxy CA (one-time)

mitmproxy intercepts TLS traffic with a generated CA. Trust it once so your
tools don't reject the connection.

```bash
# Copy the CA out of the container
docker cp warden-proxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem ./mitmproxy-ca.pem
```

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ./mitmproxy-ca.pem
```

**Linux (Ubuntu/Debian):**
```bash
sudo cp ./mitmproxy-ca.pem /usr/local/share/ca-certificates/warden-mitmproxy.crt
sudo update-ca-certificates
```

**Linux (Fedora/RHEL):**
```bash
sudo cp ./mitmproxy-ca.pem /etc/pki/ca-trust/source/anchors/warden-mitmproxy.crt
sudo update-ca-trust extract
```

**Linux (Arch):**
```bash
sudo cp ./mitmproxy-ca.pem /etc/ca-certificates/trust-source/anchors/warden-mitmproxy.crt
sudo trust extract-compat
```

Chrome / Chromium / Firefox on Linux read from a **per-user NSS DB**, not
the system store, so add the CA there too (`scripts/install-linux.sh` does
this for you when `libnss3-tools` is installed):

```bash
mkdir -p ~/.pki/nssdb
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n warden-mitmproxy -i ./mitmproxy-ca.pem
```

**Python tools** also respect `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`:
```bash
export REQUESTS_CA_BUNDLE=$(pwd)/mitmproxy-ca.pem
export SSL_CERT_FILE=$(pwd)/mitmproxy-ca.pem
```

### 2. Point your shell at the proxy

```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
export ALL_PROXY=http://localhost:8080
export NO_PROXY=localhost,127.0.0.1
```

That's enough for most CLIs (`curl`, `python -m openai`, `anthropic`, `gh`,
…). Verify with:

```bash
python scripts/validate_proxy.py
```

### 3. Per-tool configuration

#### Claude Code

`~/.claude/settings.json`:

```json
{
  "env": {
    "HTTPS_PROXY": "http://localhost:8080",
    "HTTP_PROXY":  "http://localhost:8080",
    "NODE_EXTRA_CA_CERTS": "/absolute/path/to/mitmproxy-ca.pem"
  }
}
```

#### ChatGPT / Claude desktop apps

Set the system-wide HTTP/HTTPS proxy in **System Settings → Network →
Proxies**. The app will pick it up on next launch.

#### OpenAI / Anthropic Python SDKs

Either export the env vars above, or pass an explicit `http_client`:

```python
import httpx
from openai import OpenAI
client = OpenAI(http_client=httpx.Client(
    proxy="http://localhost:8080",
    verify="/absolute/path/to/mitmproxy-ca.pem",
))
```

#### `curl`

```bash
curl --proxy http://localhost:8080 \
     --cacert ./mitmproxy-ca.pem \
     https://api.openai.com/v1/models
```

---

## Validating the proxy is in the path

```bash
python scripts/validate_proxy.py
```

The script:

1. Pings `http://localhost:8090/api/health`.
2. Confirms the proxy port is open on `8080`.
3. Sends a synthetic sensitive payload to `/api/classify` and checks the
   response.
4. Issues a real HTTPS request to `api.openai.com` *through* the proxy and
   confirms the response carries the `X-Warden-Scanned: 1` header — proof
   the proxy is in the path.
5. Reads `/api/summary` to confirm events are being stored.

Pass `--skip-network` to skip step 4 in offline / CI environments.

---

## What the dashboard shows

The Mixpanel-styled dashboard at <http://localhost:8090> renders:

- **Hero stats** — total events, count flagged sensitive, distinct providers, total bytes outbound.
- **Provider breakdown cards** — one card per shadow-AI vendor, with the
  average and peak sensitivity for that provider.
- **Recent events table** — every intercepted request, scored and tagged.
  Click *View* on any row for the full request preview (with secrets
  pre-masked), the regex hits, the LSTM probability, and the per-tier
  scores.
- **Try the classifier** — paste any text to score it locally without
  going through the proxy. Useful for ad-hoc checks.

---

## How sensitivity is scored

```
text  ─►  Tier-1 regex engine ──┐
                                ├─►  blended score  ─►  label
text  ─►  BPE  ─►  LSTM  ───────┘                       in {clean, low, medium, high, critical}
```

- Tier-1 returns a saturating score in `[0, 1]` based on the weight and count of regex hits.
- Tier-2 returns a probability from a sigmoid-output bidirectional LSTM trained on ~200 BPE tokens.
- Final sensitivity = `max(tier1, tier2)` lifted by the weaker signal — so a single secret-key hit is enough to flag a request, but the model can also flag prose containing no obvious patterns.

---

## Tracking experiments with Weights & Biases (optional)

`training/train.py` ships with a thin W&B integration. Logs land per-batch
(loss) and per-epoch (loss, accuracy, precision, recall, F1, confusion-matrix
counts), with the final test metrics + the model files uploaded as a W&B
artifact.

```bash
pip install wandb
wandb login            # or: export WANDB_API_KEY=...

# Inside docker — pass the key + flags through:
docker compose run --rm \
  -e WANDB_API_KEY \
  -e WARDEN_WANDB=1 \
  -e WANDB_PROJECT=llm-warden \
  -e WANDB_ENTITY=<your-team-or-username> \
  warden-proxy warden-train --force --wandb \
    --n-samples 50000 --vocab-size 6000 --epochs 6
```

Available CLI/env knobs:

| Flag                | Env                | Purpose                              |
| ------------------- | ------------------ | ------------------------------------ |
| `--wandb`           | `WARDEN_WANDB=1`   | Enable W&B for this run              |
| `--no-wandb`        | `WANDB_MODE=disabled` | Force off                          |
| `--wandb-project`   | `WANDB_PROJECT`    | Project name (default `llm-warden`)  |
| `--wandb-entity`    | `WANDB_ENTITY`     | Team / username                      |
| `--wandb-run-name`  | `WANDB_RUN_NAME`   | Optional human-readable run name     |

If `wandb` is not installed (or login fails) the trainer prints a notice and
keeps running — local `metrics.json` is always written.

## Retraining the model

To regenerate the data and retrain from scratch:

```bash
docker compose run --rm warden-proxy warden-train --force
```

Tweak knobs via env vars or CLI flags:

```bash
docker compose run --rm warden-proxy \
  warden-train --force \
    --n-samples 20000 \
    --vocab-size 6000 \
    --epochs 6 \
    --batch-size 128
```

Training metrics land at `/models/metrics.json` inside the container
(`docker compose run --rm warden-proxy cat /models/metrics.json`).

To regenerate just the CSV (no training):

```bash
docker compose run --rm warden-proxy warden-generate --n 20000 --out /models/training_data.csv
docker cp warden-proxy:/models/training_data.csv ./training_data.csv
```

---

## Project layout

```
.
├── docker-compose.yml
├── README.md
├── backend/
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── requirements.txt
│   ├── warden/                 # core library
│   │   ├── classifier.py       # tier-1 + tier-2 orchestrator
│   │   ├── regex_engine.py     # tier-1 patterns + Luhn check
│   │   ├── bpe.py              # pure-Python BPE tokenizer
│   │   ├── lstm.py             # PyTorch BiLSTM
│   │   ├── domains.py          # shadow-AI host registry
│   │   └── database.py         # SQLite event store
│   ├── proxy/addon.py          # mitmproxy addon (intercepts + classifies)
│   ├── api/main.py             # FastAPI dashboard backend
│   └── training/
│       ├── generate_data.py    # synthetic CSV generator
│       └── train.py            # train BPE + LSTM end-to-end
├── frontend/
│   ├── index.html              # dashboard SPA (Mixpanel design)
│   └── static/
│       ├── styles.css
│       ├── app.js
│       └── favicon.png         # autollm.ai mark
└── scripts/
    ├── install-mac.sh          # macOS: trust CA + flip system proxy
    ├── uninstall-mac.sh        # macOS: revert install-mac.sh
    ├── install-linux.sh        # Linux: trust CA + flip GNOME / env-var proxy
    ├── uninstall-linux.sh      # Linux: revert install-linux.sh
    ├── eval_threshold.py       # sweep classifier thresholds against held-out data
    └── validate_proxy.py       # health-check + interception verifier
```

---

## FAQ

**Does any data leave my laptop?**
No. The proxy runs locally, the database is local SQLite, and the model
runs on CPU in the container. The classifier only ever inspects bytes that
were already on their way to a third-party LLM.

**Does the proxy block traffic?**
No. It is observation-only by design — it tags requests with
`X-Warden-Scanned: 1` and writes an event, but it never modifies the
request body or response. (It is straightforward to extend `proxy/addon.py`
if you want hard blocking on, say, `label == "critical"`.)

**The first start is slow.**
First start does the synthetic-data generation + LSTM training (~2-4
minutes on a modern laptop). After that the model is cached in the
`warden-models` Docker volume.

**How do I wipe everything?**
```bash
docker compose down -v   # removes the named volumes too
```
