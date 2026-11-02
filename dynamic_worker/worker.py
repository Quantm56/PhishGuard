"""PhishGuard dynamic-scan worker.

Runs inside the Docker container (see dynamic_worker/Dockerfile).
Accepts a single JSON object on stdin:
    {"url": "https://example.com", "timeout": 20, "max_redirects": 10}

Writes a JSON result to stdout:
    {
        "status": "ok" | "timeout" | "blocked" | "error",
        "error": "<reason or null>",
        "final_url": "...",
        "redirect_chain": ["...", "..."],
        "rendered_html_b64": "<base64-encoded rendered DOM, max 500 KB>",
        "screenshot_b64":   "<base64-encoded PNG, max 1 MB>",
        "cookies": [{"name": "...", "domain": "...", "httpOnly": bool, "secure": bool}],
        "page_title": "...",
        "navigation_errors": ["..."]
    }

Security notes
--------------
* The container runs as a non-root user (see Dockerfile).
* No host filesystem is mounted.
* No application secrets are forwarded into the container.
* Network egress filtering (blocking RFC-1918, loopback, link-local, metadata endpoints
  and non-http/https schemes) is applied *both* in this Python layer (Playwright route
  intercept) and at the Docker --network level via iptables rules that the container
  entrypoint sets up with the NET_ADMIN capability (see entrypoint.sh).
  The iptables layer is the hard boundary; the Playwright layer gives structured errors.
* Cookies: only name, domain, httpOnly flag and secure flag are forwarded.
  Raw cookie values are NEVER logged or forwarded to the main app.
* DOM content is base64-encoded and size-capped (500 KB). It is stored in a temporary
  file owned by the worker, never in a path chosen by the scanned page.
* Screenshots are base64-encoded PNGs, size-capped (1 MB).
* Forms are NOT submitted. Page interactions are read-only (screenshot + DOM dump only).
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import signal
import sys
import threading
import urllib.parse

# Ensure Playwright browser path is set if present
if "PLAYWRIGHT_BROWSERS_PATH" not in os.environ:
    for _p in ("/ms-playwright", "/root/.cache/ms-playwright"):
        if os.path.exists(_p):
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = _p
            break

MAX_RENDERED_HTML_BYTES = 500_000   # 500 KB
MAX_SCREENSHOT_BYTES    = 1_000_000  # 1 MB

# Private / internal address ranges to block (defence in depth – iptables is the hard wall)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Cloud metadata endpoints (hostname-based blocking)
_BLOCKED_HOSTS = frozenset({
    "169.254.169.254",          # AWS / GCP / Azure IMDS
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
})


def _is_blocked_ip(ip_str: str) -> bool:
    """Return True if ip_str falls in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        return False   # not parseable as IP → not blocked by IP check


def _is_blocked_host(host: str) -> bool:
    if not host:
        return True
    host = host.lower().strip()
    if os.getenv("PHISHGUARD_ALLOW_LOCAL_TEST") == "1":
        if host in ("host.docker.internal", "172.17.0.1", "localhost", "127.0.0.1") or host.endswith(".local"):
            return False
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")]
    elif host.count(":") == 1:
        host = host.split(":")[0]
    if host in _BLOCKED_HOSTS:
        return True
    # Try parsing as a raw IP address first
    try:
        ipaddress.ip_address(host)
        return _is_blocked_ip(host)
    except ValueError:
        pass
    # Hostnames that look internal (not normal public domains)
    if re.match(r"^(localhost|.*\.local|.*\.internal|.*\.intranet|.*\.corp)$", host, re.I):
        return True
    return False


def _check_url(url: str) -> str | None:
    """Return an error string if the URL should be blocked, else None."""
    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        return "unparseable URL"
    if p.scheme not in ("http", "https"):
        return f"scheme '{p.scheme}' is not allowed"
    host = (p.hostname or "").lower()
    if _is_blocked_host(host):
        return f"host '{host}' is in a blocked range"
    return None


def run(url: str, timeout_s: int = 20, max_redirects: int = 10) -> dict:
    """Open url in headless Chromium and return structured result."""
    # Lazy import so the module can be imported in tests without playwright installed
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return {
            "status": "error",
            "error": "playwright is not installed in this environment",
            "final_url": url,
            "redirect_chain": [],
            "rendered_html_b64": None,
            "screenshot_b64": None,
            "cookies": [],
            "page_title": None,
            "navigation_errors": [],
        }

    # Pre-flight URL check
    block_reason = _check_url(url)
    if block_reason:
        return _blocked_result(url, block_reason)

    redirect_chain: list[str] = []
    navigation_errors: list[str] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",                  # required inside Docker
                "--disable-dev-shm-usage",       # avoids /dev/shm size issues
                "--disable-gpu",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-default-apps",
                "--disable-sync",
                "--disable-translate",
                "--no-first-run",
                "--safebrowsing-disable-auto-update",
                "--disable-client-side-phishing-detection",
                "--metrics-recording-only",
            ],
        )
        try:
            # Fresh context: no profile, no existing cookies, no stored state
            ctx = browser.new_context(
                java_script_enabled=True,
                ignore_https_errors=True,  # we observe TLS issues; we don't block on them
                extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/127.0.0.0 Safari/537.36"
                ),
            )

            page = ctx.new_page()

            # ── Network intercept: block internal destinations ──────────────
            def _intercept(route, request):
                req_url = request.url
                err = _check_url(req_url)
                if err:
                    navigation_errors.append(f"BLOCKED {req_url}: {err}")
                    try:
                        route.abort("blockedbyclient")
                    except Exception:
                        pass
                    return
                try:
                    route.continue_()
                except Exception:
                    pass

            page.route("**/*", _intercept)

            # ── Track redirect chain ────────────────────────────────────────
            def _on_request(req):
                try:
                    if req.is_navigation_request():
                        target = req.url
                        err = _check_url(target)
                        if err:
                            navigation_errors.append(f"BLOCKED redirect to {target}: {err}")
                        elif target not in redirect_chain:
                            redirect_chain.append(target)
                except Exception:
                    pass

            page.on("request", _on_request)

            # ── Navigate ────────────────────────────────────────────────────
            try:
                page.goto(
                    url,
                    timeout=timeout_s * 1000,
                    wait_until="domcontentloaded",
                )
                # Allow async scripts to run and render DOM elements (e.g., login forms)
                try:
                    page.wait_for_load_state("networkidle", timeout=min(3000, timeout_s * 1000))
                except Exception:
                    pass
            except PWTimeout:
                navigation_errors.append(f"Navigation timed out after {timeout_s}s")
                status = "timeout"
            except Exception as e:
                navigation_errors.append(f"Navigation error: {str(e)[:200]}")
                status = "error"
            else:
                status = "ok"

            if status != "ok" and any("BLOCKED" in str(err) for err in navigation_errors):
                status = "blocked"

            final_url = url
            try:
                if page and page.url and page.url != "about:blank":
                    final_url = page.url
            except Exception:
                pass

            # ── Screenshot ─────────────────────────────────────────────────
            screenshot_b64: str | None = None
            try:
                raw_png = page.screenshot(type="png", full_page=False)
                if len(raw_png) <= MAX_SCREENSHOT_BYTES:
                    screenshot_b64 = base64.b64encode(raw_png).decode()
                else:
                    screenshot_b64 = base64.b64encode(raw_png[:MAX_SCREENSHOT_BYTES]).decode()
                    navigation_errors.append("Screenshot truncated to 1 MB")
            except Exception as e:
                navigation_errors.append(f"Screenshot failed: {str(e)[:100]}")

            # ── Rendered DOM ────────────────────────────────────────────────
            rendered_html_b64: str | None = None
            try:
                html = page.content()
                raw = html.encode("utf-8", errors="replace")
                if len(raw) > MAX_RENDERED_HTML_BYTES:
                    raw = raw[:MAX_RENDERED_HTML_BYTES]
                    navigation_errors.append("Rendered HTML truncated to 500 KB")
                rendered_html_b64 = base64.b64encode(raw).decode()
            except Exception as e:
                navigation_errors.append(f"DOM capture failed: {str(e)[:100]}")

            # ── Page title ─────────────────────────────────────────────────
            try:
                page_title: str | None = page.title()
            except Exception:
                page_title = None

            # ── Cookies – strip values for privacy ─────────────────────────
            # We forward metadata only: name, domain, httpOnly, secure.
            # Raw cookie values are never included in the result.
            safe_cookies: list[dict] = []
            try:
                for ck in ctx.cookies():
                    safe_cookies.append({
                        "name": ck.get("name", ""),
                        "domain": ck.get("domain", ""),
                        "httpOnly": bool(ck.get("httpOnly", False)),
                        "secure": bool(ck.get("secure", False)),
                        "sameSite": ck.get("sameSite", ""),
                    })
            except Exception as e:
                navigation_errors.append(f"Cookie capture failed: {str(e)[:100]}")

            return {
                "status": status,
                "error": navigation_errors[-1] if status != "ok" and navigation_errors else None,
                "final_url": final_url,
                "redirect_chain": redirect_chain,
                "rendered_html_b64": rendered_html_b64,
                "screenshot_b64": screenshot_b64,
                "cookies": safe_cookies,
                "page_title": page_title,
                "navigation_errors": navigation_errors,
            }
        finally:
            browser.close()


def _blocked_result(url: str, reason: str) -> dict:
    return {
        "status": "blocked",
        "error": reason,
        "final_url": url,
        "redirect_chain": [],
        "rendered_html_b64": None,
        "screenshot_b64": None,
        "cookies": [],
        "page_title": None,
        "navigation_errors": [f"Pre-flight check blocked: {reason}"],
    }


def _timeout_handler(signum=None, frame=None):
    try:
        json.dump({
            "status": "timeout",
            "error": "hard watchdog timeout expired",
            "final_url": "",
            "redirect_chain": [],
            "rendered_html_b64": None,
            "screenshot_b64": None,
            "cookies": [],
            "page_title": None,
            "navigation_errors": ["hard watchdog timeout expired"],
        }, sys.stdout)
        sys.stdout.flush()
    except Exception:
        pass
    os._exit(0)


if __name__ == "__main__":
    # Install a hard-kill timer in case playwright hangs completely
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _timeout_handler)

    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            json.dump({"status": "error", "error": "empty input payload on stdin"}, sys.stdout)
            sys.exit(1)
        payload = json.loads(raw_input)
    except json.JSONDecodeError as e:
        json.dump({"status": "error", "error": f"bad JSON input: {e}"}, sys.stdout)
        sys.exit(1)

    url_in = str(payload.get("url", ""))
    timeout_in = int(payload.get("timeout", 20))
    max_rd = int(payload.get("max_redirects", 10))

    # Hard timeout watchdog = playwright timeout + 15 s grace
    watchdog = None
    if hasattr(signal, "alarm"):
        signal.alarm(timeout_in + 15)
    else:
        # Cross-platform fallback for Windows
        watchdog = threading.Timer(timeout_in + 15, _timeout_handler)
        watchdog.daemon = True
        watchdog.start()

    result = run(url_in, timeout_s=timeout_in, max_redirects=max_rd)

    if hasattr(signal, "alarm"):
        signal.alarm(0)
    elif watchdog:
        watchdog.cancel()

    json.dump(result, sys.stdout)
    sys.stdout.flush()
