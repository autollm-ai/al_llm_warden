#!/usr/bin/env python3
"""Validate that outbound LLM API calls are flowing through LLM Warden.

Checks, in order:
  1. The dashboard API is reachable on http://localhost:8090.
  2. The mitmproxy listener is up on http://localhost:8080.
  3. A test request to api.openai.com routed via the proxy returns the
     X-Warden-Scanned response header (proves the proxy intercepted it).
  4. A new event with sensitive content shows up in the dashboard.
  5. Optional: emits the env-var snippet you should export so all your
     CLIs (claude, claude-code, openai, curl) route through the proxy.

Run:
  python scripts/validate_proxy.py
  python scripts/validate_proxy.py --proxy http://localhost:8080 --api http://localhost:8090
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

DEFAULT_PROXY = "http://localhost:8080"
DEFAULT_API = "http://localhost:8090"

# ANSI for friendlier output (skipped if NO_COLOR is set).
def _c(s: str, code: str) -> str:
    if os.environ.get("NO_COLOR"):
        return s
    return f"\033[{code}m{s}\033[0m"

OK   = lambda s: _c("✔ " + s, "32")
FAIL = lambda s: _c("✘ " + s, "31")
WARN = lambda s: _c("! " + s, "33")
DIM  = lambda s: _c(s, "2")


def _get(url: str, proxy: str | None = None, timeout: float = 8.0) -> tuple[int, dict, bytes]:
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": "warden-validator/1.0"})
    with opener.open(req, timeout=timeout) as resp:
        return resp.status, dict(resp.headers), resp.read()


def _post_json(url: str, body: dict, proxy: str | None = None, timeout: float = 8.0):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "warden-validator/1.0"},
    )
    with opener.open(req, timeout=timeout) as resp:
        return resp.status, dict(resp.headers), resp.read()


def check_api(api_url: str) -> bool:
    print(DIM(f"GET {api_url}/api/health"))
    try:
        status, _, body = _get(api_url + "/api/health")
    except Exception as e:
        print(FAIL(f"Dashboard API not reachable: {e}"))
        print(DIM("    Is `docker compose up` running? Try: docker compose ps"))
        return False
    j = json.loads(body)
    if j.get("status") == "ok":
        print(OK(f"Dashboard API ok (tier-2 enabled: {j.get('tier2_enabled')})"))
        return True
    print(FAIL(f"Unexpected health response: {j}"))
    return False


def check_proxy_listener(proxy_url: str) -> bool:
    # mitmproxy listens for CONNECT — a plain GET to it returns a 502/404 from
    # mitmproxy itself. We just want to confirm something is listening.
    host_port = proxy_url.split("://", 1)[1]
    import socket
    host, port = host_port.split(":")
    try:
        with socket.create_connection((host, int(port)), timeout=3):
            print(OK(f"Proxy listener reachable on {host}:{port}"))
            return True
    except Exception as e:
        print(FAIL(f"Proxy listener unreachable on {host}:{port}: {e}"))
        return False


def check_intercept_via_test_endpoint(api_url: str) -> bool:
    """Use the /api/classify endpoint to prove the model + DB are wired up,
    independent of any external network access."""
    sample = (
        "Please summarize this thread: customer email john.doe@example.com "
        "called about charge on card 4111 1111 1111 1111 — also our "
        "OPENAI_API_KEY is sk-abcd1234efgh5678ijkl9012mnop3456qrst7890."
    )
    try:
        status, _, body = _post_json(api_url + "/api/classify", {"text": sample})
    except Exception as e:
        print(FAIL(f"/api/classify request failed: {e}"))
        return False
    j = json.loads(body)
    print(OK(
        f"Classifier responded: label={j['label']} sensitivity={j['sensitivity']:.2f} "
        f"(regex={j['tier1_score']:.2f}, lstm={j['tier2_score']:.2f})"
    ))
    if j["sensitivity"] < 0.4:
        print(WARN("Sensitivity unexpectedly low — model may be untrained."))
        return False
    return True


def check_intercept_via_proxy(proxy_url: str) -> bool:
    """Issue an HTTPS request to a known shadow-AI host through the proxy and
    confirm the response carries the X-Warden-Scanned tag.

    NOTE: This requires the mitmproxy CA to be trusted by the OS. We disable
    cert verification here purely for the validator handshake — the goal is
    to confirm the proxy is in the path, not to talk to OpenAI for real.
    """
    target = "https://api.openai.com/v1/models"
    print(DIM(f"GET {target}  (via {proxy_url})"))
    try:
        # urllib doesn't expose a simple cert-disable knob, so use ssl context.
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        https_handler = urllib.request.HTTPSHandler(context=ctx)
        opener = urllib.request.build_opener(proxy_handler, https_handler)
        req = urllib.request.Request(
            target,
            headers={
                "User-Agent": "warden-validator/1.0",
                "Authorization": "Bearer sk-fake-token-for-validator-only-not-real-1234567890",
            },
        )
        try:
            resp = opener.open(req, timeout=10)
            headers = dict(resp.headers)
        except urllib.error.HTTPError as e:
            # 401/403 is fine — we're not actually authenticated. We just want
            # to see the X-Warden-Scanned header on whatever response came back.
            headers = dict(e.headers or {})
    except Exception as e:
        print(FAIL(f"Failed to send proxied request: {e}"))
        print(DIM("    On macOS, install the mitmproxy CA: open ~/.mitmproxy/mitmproxy-ca-cert.pem"))
        return False

    if "X-Warden-Scanned" in {k.title() for k in headers} or "x-warden-scanned" in headers:
        print(OK("Outbound request was tagged X-Warden-Scanned ✓ proxy is in the path"))
        return True
    print(FAIL("Response did not carry X-Warden-Scanned — proxy may be bypassed"))
    print(DIM(f"    Response headers seen: {list(headers.keys())[:8]}"))
    return False


def check_event_appeared(api_url: str) -> bool:
    print(DIM(f"GET {api_url}/api/summary"))
    try:
        _, _, body = _get(api_url + "/api/summary")
    except Exception as e:
        print(FAIL(f"Could not load summary: {e}"))
        return False
    j = json.loads(body)
    total = j.get("total", 0)
    if total > 0:
        print(OK(f"Dashboard shows {total} event(s) total ({len(j.get('by_provider', []))} provider(s))"))
        return True
    print(WARN("No events yet. Make a real request through the proxy to populate the dashboard."))
    return False


def print_setup_hint(proxy_url: str) -> None:
    print()
    print(DIM("─── Point your CLIs at the proxy ───────────────────────────────"))
    print("  export HTTP_PROXY="  + proxy_url)
    print("  export HTTPS_PROXY=" + proxy_url)
    print("  export ALL_PROXY="   + proxy_url)
    print("  # Trust the mitmproxy CA (one-time):")
    print("  #   docker cp warden-proxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem .")
    print("  #   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain mitmproxy-ca-cert.pem")
    print(DIM("─────────────────────────────────────────────────────────────────"))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--proxy", default=os.environ.get("WARDEN_PROXY", DEFAULT_PROXY))
    p.add_argument("--api",   default=os.environ.get("WARDEN_API", DEFAULT_API))
    p.add_argument("--skip-network", action="store_true",
                   help="skip the live HTTPS check (useful in CI / offline)")
    args = p.parse_args()

    print(_c("LLM Warden — proxy validation", "1;35"))
    print(DIM(f"proxy: {args.proxy}    api: {args.api}"))
    print()

    results = {
        "api":        check_api(args.api),
        "proxy_port": check_proxy_listener(args.proxy),
        "classifier": check_intercept_via_test_endpoint(args.api),
    }
    if not args.skip_network:
        # Brief pause so the just-classified event lands.
        time.sleep(0.5)
        results["intercept"] = check_intercept_via_proxy(args.proxy)
    results["events"] = check_event_appeared(args.api)

    print()
    failed = [k for k, v in results.items() if not v]
    if not failed:
        print(_c("All checks passed.", "1;32"))
        print_setup_hint(args.proxy)
        return 0

    print(_c(f"{len(failed)} check(s) failed: {', '.join(failed)}", "1;31"))
    print_setup_hint(args.proxy)
    return 1


if __name__ == "__main__":
    sys.exit(main())
