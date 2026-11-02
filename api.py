"""PhishGuard REST API + web dashboard.

    python api.py                      # http://127.0.0.1:5000

    Static scan (fast, no Docker):
        curl -X POST localhost:5000/api/predict -H 'Content-Type: application/json' \
             -d '{"url": "http://secure-login-update-paypal.com", "live": false}'

    Dynamic scan (requires Docker + phishguard-worker image):
        curl -X POST localhost:5000/api/dynamic_scan -H 'Content-Type: application/json' \
             -d '{"url": "https://example.com"}'
"""
import json
import os

from flask import Flask, jsonify, render_template, request, send_from_directory

from phishguard.predictor import PhishGuard

ROOT = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(ROOT, "results")

app = Flask(__name__)
_guard = None


def guard() -> PhishGuard:
    global _guard
    if _guard is None:
        _guard = PhishGuard()
    return _guard


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify(status="ok")


@app.post("/api/predict")
def predict():
    body = request.get_json(silent=True) or {}
    url = (body.get("url") or "").strip()
    if not url or len(url) > 4096:
        return jsonify(error="Provide a 'url' (max 4096 characters)."), 400
    live = bool(body.get("live", True))
    try:
        return jsonify(guard().assess(url, live=live, fetch_page=bool(body.get("fetch_page", live))))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    except Exception as e:  # noqa: BLE001
        app.logger.exception("assessment failed")
        return jsonify(error=f"internal error: {e}"), 500


@app.post("/api/dynamic_scan")
def dynamic_scan():
    """Trigger a sandboxed Playwright/Docker scan of a URL.

    Request body
    ------------
    {
        "url":     "https://example.com",   // required
        "timeout": 25                        // optional, seconds (default 25)
    }

    Response (always 200; check 'status' field)
    -------------------------------------------
    {
        "status":           "ok" | "timeout" | "blocked" | "error" | "docker_unavailable",
        "error":            null | "<reason>",
        "final_url":        "https://example.com",
        "redirect_chain":   ["https://example.com"],
        "cookies":          [{"name": "session", "domain": "example.com", "httpOnly": true, "secure": true}],
        "page_title":       "Example Domain",
        "navigation_errors":[],
        "content_features": { ... },   // re-computed on rendered DOM; see _note
        "content_signals":  [ ... ],
        "artifacts":        {"screenshot_path": "results/dynamic/screenshot_<id>.png",
                             "rendered_html_path": "results/dynamic/rendered_<id>.html"},
        "scanned_at":       "2026-11-02T07:05:00+00:00",
        "_note":            "content_features were computed by re-using the static extractor …"
    }

    Important
    ---------
    - A failed scan returns status "error"/"timeout"/"blocked", never "LEGITIMATE".
    - Cookie *values* are never included – only metadata (name, domain, flags).
    - Screenshots and rendered HTML are stored under results/dynamic/ (not in the response).
    - Requires Docker Desktop to be running and the phishguard-worker image to be built.
    """
    # Lazy import: only fails if dynamic_scan module can't import (never happens here)
    from phishguard.dynamic_scan import assess_dynamic
    from phishguard.urlfeatures import normalize_url

    body = request.get_json(silent=True) or {}
    url = (body.get("url") or "").strip()
    if not url or len(url) > 4096:
        return jsonify(error="Provide a 'url' (max 4096 characters)."), 400

    timeout = int(body.get("timeout", 25))
    if not (5 <= timeout <= 60):
        return jsonify(error="'timeout' must be between 5 and 60 seconds."), 400

    try:
        url = normalize_url(url)
    except Exception:
        pass

    artifact_dir = os.path.join(RESULTS, "dynamic")
    try:
        result = assess_dynamic(url, artifact_dir=artifact_dir, scan_timeout=timeout)
        return jsonify(result)
    except Exception as e:  # noqa: BLE001
        app.logger.exception("dynamic scan failed")
        return jsonify(error=f"internal error: {e}"), 500


@app.get("/api/metrics")
def metrics():
    path = os.path.join(RESULTS, "metrics.json")
    if not os.path.exists(path):
        return jsonify(error="Run train.py first"), 404
    with open(path) as f:
        return jsonify(json.load(f))


@app.get("/results/<path:name>")
def results_file(name):
    return send_from_directory(RESULTS, name)


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", 5000)), debug=False)
