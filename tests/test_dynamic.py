"""Tests for the dynamic-scan subsystem.

Run:
    python -m unittest tests.test_dynamic -v

Tests are designed to run WITHOUT Docker.  The docker-dependent test
(TestStaticVsDynamic.test_dynamic_worker_sees_js_form) is skipped automatically
when Docker is unavailable.

Test coverage:
  1. Worker URL pre-flight check: blocks internal/private ranges and bad schemes.
  2. Static vs. dynamic HTML difference: static fetcher misses JS-injected form;
     Playwright worker sees it in rendered DOM (requires Docker).
  3. Timeout / error result shape: status field is never "LEGITIMATE".
  4. Blocked internal destination: worker refuses 127.x, 192.168.x etc.
  5. API endpoint shape: /api/dynamic_scan returns expected keys.
"""
import os
import sys
import threading
import unittest
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Fixtures ──────────────────────────────────────────────────────────────────
FIXTURE_DIR  = Path(__file__).parent / "fixtures"
JS_LOGIN_HTML = (FIXTURE_DIR / "js_login.html").read_text(encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Helper: detect Docker and worker image availability
# ─────────────────────────────────────────────────────────────────────────────
def _docker_worker_available() -> bool:
    import subprocess
    try:
        info = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        if info.returncode != 0:
            return False
        img = subprocess.run(
            ["docker", "image", "inspect", "phishguard-worker:latest"],
            capture_output=True,
            timeout=5,
        )
        return img.returncode == 0
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 1. Worker URL pre-flight (no Docker needed)
# ─────────────────────────────────────────────────────────────────────────────
class TestWorkerPreFlight(unittest.TestCase):
    """dynamic_worker/worker.py URL checker runs without Docker or Playwright."""

    def setUp(self):
        # Directly import worker helper functions without needing playwright
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "worker",
            Path(__file__).parent.parent / "dynamic_worker" / "worker.py",
        )
        self.worker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.worker)

    def _check(self, url):
        return self.worker._check_url(url)

    def test_blocks_loopback(self):
        self.assertIsNotNone(self._check("http://127.0.0.1/admin"))
        self.assertIsNotNone(self._check("http://localhost/"))

    def test_blocks_private_ranges(self):
        for url in ("http://192.168.1.1/", "http://10.0.0.1/", "http://172.16.5.5/"):
            self.assertIsNotNone(self._check(url), f"should block {url}")

    def test_blocks_metadata_endpoint(self):
        self.assertIsNotNone(self._check("http://169.254.169.254/latest/meta-data/"))

    def test_blocks_bad_scheme(self):
        self.assertIsNotNone(self._check("file:///etc/passwd"))
        self.assertIsNotNone(self._check("ftp://example.com/file"))

    def test_allows_public_https(self):
        self.assertIsNone(self._check("https://example.com/"))

    def test_allows_public_http(self):
        self.assertIsNone(self._check("http://example.com/page"))


# ─────────────────────────────────────────────────────────────────────────────
# 2. Static vs. JS-rendered HTML comparison (local HTTP server, no Docker)
# ─────────────────────────────────────────────────────────────────────────────
def _start_fixture_server():
    """Start a temporary HTTP server serving the fixtures/ directory.
    Binds to 0.0.0.0 so both host and Docker container can reach it.
    """
    import functools
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(FIXTURE_DIR))
    server = HTTPServer(("0.0.0.0", 0), handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, f"http://127.0.0.1:{port}"


class TestStaticVsDynamic(unittest.TestCase):
    """Verify that JS-injected forms are invisible to safe_fetch but visible
    to Playwright.  The Playwright portion is skipped unless Docker is running.
    """

    def test_static_fetch_does_not_see_js_form(self):
        """safe_fetch / extract_content_features on the static fixture HTML
        should NOT detect the password field (it is injected by JS)."""
        from phishguard import content
        feats = content.extract_content_features(JS_LOGIN_HTML, "http://test.local/", 0)
        # The <input type="password"> does NOT exist in the raw HTML source
        self.assertEqual(feats["HasPasswordField"], 0,
                         "Static extractor must NOT see the JS-injected password field")
        self.assertEqual(feats["HasSubmitButton"], 0,
                         "Static extractor must NOT see the JS-injected submit button")

    @unittest.skipUnless(
        _docker_worker_available(),
        "Docker or phishguard-worker:latest image not available – skipping live Playwright container test",
    )
    def test_dynamic_worker_sees_js_form(self):
        """Playwright (via Docker worker) MUST see the JS-injected form."""
        server, _ = _start_fixture_server()
        port = server.server_address[1]
        fixture_url = f"http://host.docker.internal:{port}/js_login.html"

        os.environ["PHISHGUARD_ALLOW_LOCAL_TEST"] = "1"
        try:
            from phishguard.dynamic_scan import assess_dynamic
            result = assess_dynamic(fixture_url, scan_timeout=20)
        finally:
            os.environ.pop("PHISHGUARD_ALLOW_LOCAL_TEST", None)
            server.shutdown()

        self.assertEqual(result["status"], "ok", result.get("error"))
        cf = result.get("content_features")
        self.assertIsNotNone(cf, "content_features should be populated after a successful scan")
        self.assertEqual(cf["HasPasswordField"], 1.0,
                         "Playwright worker MUST see the JS-injected password field")
        self.assertEqual(cf["HasSubmitButton"], 1.0,
                         "Playwright worker MUST see the JS-injected submit button")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Error and timeout result shape
# ─────────────────────────────────────────────────────────────────────────────
class TestDynamicScanResultShape(unittest.TestCase):
    """Verify that error/unavailable results have the right shape and never
    claim a URL is safe."""

    def _make_result(self, status, error=None):
        from phishguard.dynamic_scan import _error_result
        return _error_result("http://example.com", status, error or status, "2026-01-01T00:00:00+00:00")

    def test_error_result_has_required_keys(self):
        r = self._make_result("error", "docker not running")
        for key in ("status", "error", "final_url", "redirect_chain", "cookies",
                    "navigation_errors", "content_features", "content_signals",
                    "artifacts", "scanned_at"):
            self.assertIn(key, r, f"missing key: {key}")

    def test_error_status_is_not_legitimate(self):
        for status in ("error", "timeout", "blocked", "docker_unavailable"):
            r = self._make_result(status)
            # The result dict has no 'verdict' key – that is the static scanner's job
            self.assertNotIn("verdict", r, "dynamic scan result must not have a 'verdict' field")
            self.assertEqual(r["status"], status)
            # content_features and cookies must be empty/None on error
            self.assertIsNone(r["content_features"])
            self.assertEqual(r["cookies"], [])

    def test_artifacts_dict_present(self):
        r = self._make_result("docker_unavailable", "Docker CLI not found")
        self.assertIsInstance(r["artifacts"], dict)
        self.assertIn("screenshot_path", r["artifacts"])
        self.assertIn("rendered_html_path", r["artifacts"])

    def test_docker_unavailable_when_docker_missing(self):
        """When docker binary is not found, status must be 'docker_unavailable'."""
        from phishguard import dynamic_scan
        with mock.patch("subprocess.run", side_effect=FileNotFoundError("docker not found")):
            result = dynamic_scan.assess_dynamic("https://example.com")
        self.assertEqual(result["status"], "docker_unavailable")
        self.assertIsNotNone(result["error"])


# ─────────────────────────────────────────────────────────────────────────────
# 4. Blocked internal destination via assess_dynamic mock path
# ─────────────────────────────────────────────────────────────────────────────
class TestBlockedDestination(unittest.TestCase):
    """assess_dynamic itself does NOT block by URL (the worker does).
    This verifies the worker's _blocked_result path is reachable via the
    'blocked' status returned by a mocked Docker run."""

    def test_worker_blocked_result_reported_correctly(self):
        """Simulate Docker container returning status=blocked for a private IP."""
        from phishguard import dynamic_scan
        fake_worker_output = {
            "status": "blocked",
            "error": "host '192.168.1.1' is in a blocked range",
            "final_url": "http://192.168.1.1/",
            "redirect_chain": [],
            "rendered_html_b64": None,
            "screenshot_b64": None,
            "cookies": [],
            "page_title": None,
            "navigation_errors": ["Pre-flight check blocked: host '192.168.1.1' is in a blocked range"],
        }
        import json, subprocess
        fake_proc = mock.Mock()
        fake_proc.returncode = 0
        fake_proc.stdout = json.dumps(fake_worker_output).encode()
        fake_proc.stderr = b""
        with mock.patch("subprocess.run", return_value=fake_proc):
            result = dynamic_scan.assess_dynamic("http://192.168.1.1/")
        self.assertEqual(result["status"], "blocked")
        self.assertIsNone(result["content_features"])
        self.assertIsNotNone(result["error"])


# ─────────────────────────────────────────────────────────────────────────────
# 5. API endpoint /api/dynamic_scan shape test (Flask test client, no Docker)
# ─────────────────────────────────────────────────────────────────────────────
class TestDynamicScanAPI(unittest.TestCase):
    def setUp(self):
        import api
        self.c = api.app.test_client()

    def test_missing_url_returns_400(self):
        r = self.c.post("/api/dynamic_scan", json={})
        self.assertEqual(r.status_code, 400)

    def test_timeout_out_of_range_returns_400(self):
        r = self.c.post("/api/dynamic_scan", json={"url": "https://example.com", "timeout": 120})
        self.assertEqual(r.status_code, 400)

    def test_docker_unavailable_returns_200_with_status_field(self):
        """Even when Docker is not running the endpoint returns 200 with an
        informative status field, never a 500."""
        from phishguard import dynamic_scan
        with mock.patch.object(dynamic_scan, "assess_dynamic",
                               return_value=dynamic_scan._error_result(
                                   "https://example.com",
                                   "docker_unavailable",
                                   "Docker CLI not found",
                                   "2026-01-01T00:00:00+00:00",
                               )):
            r = self.c.post("/api/dynamic_scan", json={"url": "https://example.com"})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body["status"], "docker_unavailable")
        self.assertIn("error", body)

    def test_predict_endpoint_unaffected(self):
        """Regression: adding dynamic scan must not break /api/predict."""
        r = self.c.post("/api/predict", json={"url": "https://example.com", "live": False})
        self.assertEqual(r.status_code, 200)
        self.assertIn("verdict", r.get_json())


if __name__ == "__main__":
    unittest.main()
