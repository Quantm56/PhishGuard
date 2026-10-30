"""PhishGuard REST API + web dashboard.

    python api.py                      # http://127.0.0.1:5000
    curl -X POST localhost:5000/api/predict -H 'Content-Type: application/json' \
         -d '{"url": "http://secure-login-update-paypal.com", "live": false}'
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
