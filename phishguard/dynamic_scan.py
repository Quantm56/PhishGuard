"""Dynamic-scan bridge: launches the Docker worker container and collects results.

This module is the *only* place in the main PhishGuard process that knows about
Docker.  It is completely decoupled from the existing static scanner so that
the fast path (PhishGuard.assess) is never affected when dynamic scanning is
not requested.

Security design
---------------
* Each scan gets a brand-new, ephemeral container (--rm).
* No host filesystem is mounted; input is passed via stdin.
* No application API keys (.env) are forwarded into the container.
* The container is started with --cap-add NET_ADMIN so entrypoint.sh can set up
  iptables egress rules.  This capability is the hard network boundary.
* Output size is capped before decoding. Artifact filenames are chosen by this
  module (UUID-based), never by the scanned page.
* Rendered HTML and screenshots are written to a caller-supplied artifact
  directory (default: results/dynamic/). The small JSON summary returned by
  assess_dynamic() never contains raw cookie values or full DOM text.

LIMITATION (documented, not hidden)
------------------------------------
Docker container-level network isolation (--network=none or custom networks) is
NOT enforced by this code for the prototype. The hard egress block lives in
entrypoint.sh (iptables with NET_ADMIN). If the container cannot obtain
NET_ADMIN (e.g. in restricted cloud environments), the iptables rules silently
fail and only the Playwright-layer filtering applies.  See README § Security
Limitations for production hardening steps.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from phishguard import content as _content

# ── Defaults ─────────────────────────────────────────────────────────────────
DOCKER_IMAGE       = os.getenv("PHISHGUARD_WORKER_IMAGE", "phishguard-worker:latest")
SCAN_TIMEOUT_S     = int(os.getenv("PHISHGUARD_SCAN_TIMEOUT", "25"))
DOCKER_MEM_LIMIT   = os.getenv("PHISHGUARD_DOCKER_MEM", "512m")
DOCKER_CPU_LIMIT   = os.getenv("PHISHGUARD_DOCKER_CPUS", "1.0")
DOCKER_PIDS_LIMIT  = int(os.getenv("PHISHGUARD_DOCKER_PIDS", "256"))
MAX_OUTPUT_BYTES   = 3_000_000   # 3 MB total stdout from container
ARTIFACT_MAX_HTML  = 500_000     # bytes
ARTIFACT_MAX_PNG   = 1_000_000   # bytes


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def assess_dynamic(
    url: str,
    artifact_dir: str | None = None,
    scan_timeout: int = SCAN_TIMEOUT_S,
) -> dict:
    """Run a dynamic scan and return a structured result.

    Parameters
    ----------
    url:            URL to scan (must already be normalised).
    artifact_dir:   Directory to write screenshot + rendered HTML files.
                    Defaults to ``<repo_root>/results/dynamic/``.
    scan_timeout:   Seconds to wait for the page to load.

    Returns
    -------
    dict with keys:
        status          "ok" | "timeout" | "blocked" | "error" | "docker_unavailable"
        error           human-readable error string or None
        final_url       URL after all redirects
        redirect_chain  list of URLs visited
        cookies         list of {name, domain, httpOnly, secure} – no values
        page_title      string or None
        navigation_errors  list of strings
        content_features   dict from extract_content_features() on rendered DOM, or None
        content_signals    list of signal dicts from content_signals(), or []
        artifacts       {screenshot_path, rendered_html_path} relative to artifact_dir
        scanned_at      ISO-8601 timestamp
    """
    scan_id = uuid.uuid4().hex
    scanned_at = _now_utc()

    # ── Resolve artifact directory ────────────────────────────────────────────
    if artifact_dir is None:
        repo_root = Path(__file__).parent.parent
        artifact_dir = str(repo_root / "results" / "dynamic")
    art_path = Path(artifact_dir)
    art_path.mkdir(parents=True, exist_ok=True)

    # ── Launch Docker container ───────────────────────────────────────────────
    payload = json.dumps({
        "url": url,
        "timeout": scan_timeout,
        "max_redirects": 10,
    })

    cmd = [
        "docker", "run", "--rm", "--interactive",
        "--memory",         DOCKER_MEM_LIMIT,
        "--cpus",           DOCKER_CPU_LIMIT,
        "--pids-limit",     str(DOCKER_PIDS_LIMIT),
        "--cap-add",        "NET_ADMIN",
        # No host mounts, no env forwarding
        "--network",        "bridge",  # allows internet but iptables blocks internal
        "--security-opt",   "no-new-privileges",
    ]
    if os.getenv("PHISHGUARD_ALLOW_LOCAL_TEST") == "1":
        cmd.extend(["-e", "PHISHGUARD_ALLOW_LOCAL_TEST=1", "--add-host", "host.docker.internal:host-gateway"])
    cmd.append(DOCKER_IMAGE)

    try:
        proc = subprocess.run(
            cmd,
            input=payload.encode(),
            capture_output=True,
            timeout=scan_timeout + 30,   # outer OS timeout
        )
    except FileNotFoundError:
        return _error_result(url, "docker_unavailable",
                             "Docker CLI not found. Install Docker Desktop and ensure it is running.",
                             scanned_at)
    except subprocess.TimeoutExpired:
        return _error_result(url, "timeout",
                             "Docker container did not finish within the allotted time.",
                             scanned_at)
    except Exception as e:
        return _error_result(url, "error", f"docker run failed: {str(e)[:200]}", scanned_at)

    if proc.returncode not in (0, 1):
        stderr = proc.stderr.decode(errors="replace")[:500]
        return _error_result(url, "error",
                             f"Container exited {proc.returncode}: {stderr}", scanned_at)

    # ── Parse worker output ───────────────────────────────────────────────────
    raw_out = proc.stdout[:MAX_OUTPUT_BYTES]
    try:
        worker_result: dict = json.loads(raw_out)
    except json.JSONDecodeError as e:
        return _error_result(url, "error",
                             f"Worker output was not valid JSON: {e}", scanned_at)

    # ── Save artifacts to disk ────────────────────────────────────────────────
    artifact_paths: dict[str, str | None] = {
        "screenshot_path": None,
        "rendered_html_path": None,
    }

    png_b64 = worker_result.pop("screenshot_b64", None)
    if png_b64:
        try:
            png_bytes = base64.b64decode(png_b64)[:ARTIFACT_MAX_PNG]
            fname = f"screenshot_{scan_id}.png"
            fpath = art_path / fname
            fpath.write_bytes(png_bytes)
            artifact_paths["screenshot_path"] = str(fpath)
        except Exception:
            pass

    html_b64 = worker_result.pop("rendered_html_b64", None)
    rendered_html: str | None = None
    if html_b64:
        try:
            html_bytes = base64.b64decode(html_b64)[:ARTIFACT_MAX_HTML]
            rendered_html = html_bytes.decode("utf-8", errors="replace")
            fname = f"rendered_{scan_id}.html"
            fpath = art_path / fname
            fpath.write_text(rendered_html, encoding="utf-8")
            artifact_paths["rendered_html_path"] = str(fpath)
        except Exception:
            pass

    # ── Re-use static content feature extractor on rendered DOM ──────────────
    # NOTE on accuracy: the existing ML models were trained on PhiUSIIL features
    # computed from *statically fetched* HTML. Rendered DOM content may differ
    # substantially from static HTML (e.g. JS-injected forms, deferred iframes).
    # The feature values here are informational; the same model_full weights
    # cannot be naively applied to rendered DOM and claimed to achieve 99.66%
    # accuracy. A retrained or recalibrated model would be needed for production
    # use of rendered-DOM features.
    content_features: dict | None = None
    content_sigs: list = []
    final_url = worker_result.get("final_url") or url
    if rendered_html and worker_result.get("status") == "ok":
        try:
            content_features = _content.extract_content_features(rendered_html, final_url, 0)
            from urllib.parse import urlsplit
            scheme = (urlsplit(final_url).scheme or "http").lower()
            content_sigs = _content.content_signals(content_features, scheme)
        except Exception:
            pass

    # ── Sanitise cookie list (values already stripped by worker) ─────────────
    safe_cookies = [
        {k: v for k, v in ck.items() if k in ("name", "domain", "httpOnly", "secure", "sameSite")}
        for ck in (worker_result.get("cookies") or [])
    ]

    return {
        "status":             worker_result.get("status", "error"),
        "error":              worker_result.get("error"),
        "final_url":          final_url,
        "redirect_chain":     worker_result.get("redirect_chain", []),
        "cookies":            safe_cookies,
        "page_title":         worker_result.get("page_title"),
        "navigation_errors":  worker_result.get("navigation_errors", []),
        "content_features":   content_features,
        "content_signals":    content_sigs,
        "artifacts":          artifact_paths,
        "scanned_at":         scanned_at,
        # Note: rendered HTML is saved to artifact_paths["rendered_html_path"],
        # not returned inline, so the API response stays small.
        "_note": (
            "content_features were computed by re-using the static extractor on rendered DOM. "
            "The full-model 99.66% accuracy claim does NOT apply to these rendered-DOM features; "
            "retraining or recalibration is required for production use."
        ),
    }


def _error_result(url: str, status: str, error: str, scanned_at: str) -> dict:
    return {
        "status":            status,
        "error":             error,
        "final_url":         url,
        "redirect_chain":    [],
        "cookies":           [],
        "page_title":        None,
        "navigation_errors": [error],
        "content_features":  None,
        "content_signals":   [],
        "artifacts":         {"screenshot_path": None, "rendered_html_path": None},
        "scanned_at":        scanned_at,
    }

