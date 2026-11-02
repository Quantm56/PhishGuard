"""Automated tests for PhishGuard Extension API contract, CORS, and manifest validity."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestExtensionAPI(unittest.TestCase):
    def setUp(self):
        self.client = api.app.test_client()

    def test_cors_headers_on_predict(self):
        """Test that CORS headers are returned so browser extension fetch requests succeed."""
        res = self.client.post("/api/predict", json={"url": "https://example.com", "live": False})
        self.assertIn("Access-Control-Allow-Origin", res.headers)
        self.assertEqual(res.headers["Access-Control-Allow-Origin"], "*")
        self.assertIn("Access-Control-Allow-Methods", res.headers)

    def test_options_preflight(self):
        """Test preflight OPTIONS request returns 204 No Content with CORS headers."""
        res = self.client.open("/api/predict", method="OPTIONS")
        self.assertEqual(res.status_code, 204)
        self.assertEqual(res.headers.get("Access-Control-Allow-Origin"), "*")
        self.assertIn("POST", res.headers.get("Access-Control-Allow-Methods", ""))

    def test_health_endpoint(self):
        """Test health check returns status ok and CORS headers."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "ok")
        self.assertEqual(res.headers.get("Access-Control-Allow-Origin"), "*")

    def test_predict_contract_legitimate(self):
        """Verify the JSON response structure matches the extension contract for legitimate URLs."""
        res = self.client.post("/api/predict", json={"url": "https://github.com/pallets/flask", "live": False})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Contract fields expected by the extension
        self.assertIn("url", data)
        self.assertIn("verdict", data)
        self.assertIn("final_score", data)
        self.assertIn("ml_probability", data)
        self.assertIn("signals", data)
        self.assertIn("explanation", data)
        self.assertIn("reason", data)
        self.assertIn("thresholds", data)

        self.assertEqual(data["verdict"], "LEGITIMATE")
        self.assertLess(data["final_score"], data["thresholds"]["suspicious"])
        self.assertIsInstance(data["reason"], str)
        self.assertIsInstance(data["signals"], list)
        self.assertIsInstance(data["explanation"], list)

    def test_predict_contract_phishing(self):
        """Verify the JSON response structure matches the extension contract for high-risk URLs."""
        res = self.client.post(
            "/api/predict",
            json={"url": "http://secure-login-update-paypal.com", "live": False}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertIn(data["verdict"], ("PHISHING", "SUSPICIOUS"))
        self.assertGreaterEqual(data["final_score"], data["thresholds"]["suspicious"])
        self.assertIsInstance(data["reason"], str)

    def test_predict_invalid_payloads(self):
        """Test validation: missing url, empty url, or oversized payload."""
        res1 = self.client.post("/api/predict", json={})
        self.assertEqual(res1.status_code, 400)
        self.assertIn("error", res1.get_json())

        res2 = self.client.post("/api/predict", json={"url": ""})
        self.assertEqual(res2.status_code, 400)

        res3 = self.client.post("/api/predict", json={"url": "https://example.com/" + "a" * 5000})
        self.assertEqual(res3.status_code, 400)


class TestExtensionManifestAndFiles(unittest.TestCase):
    def test_manifest_structure(self):
        """Verify manifest.json exists, is valid Manifest V3, and has minimum required permissions."""
        manifest_path = os.path.join(ROOT, "extension", "manifest.json")
        self.assertTrue(os.path.exists(manifest_path), "manifest.json must exist")

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        self.assertEqual(manifest.get("manifest_version"), 3)
        self.assertIn("tabs", manifest.get("permissions", []))
        self.assertIn("storage", manifest.get("permissions", []))
        self.assertIn("declarativeNetRequest", manifest.get("permissions", []))

        # Host permissions must include local API and web schemes for DNR redirection
        host_perms = manifest.get("host_permissions", [])
        self.assertTrue(any("127.0.0.1:5000" in p for p in host_perms))
        self.assertTrue(any("*://*/*" in p for p in host_perms))

        # Web accessible resources must include checking page assets
        war = manifest.get("web_accessible_resources", [])
        self.assertTrue(len(war) > 0)
        accessible = war[0].get("resources", [])
        self.assertIn("checking.html", accessible)
        self.assertIn("checking.js", accessible)
        self.assertIn("checking.css", accessible)

        # Background worker must be module
        bg = manifest.get("background", {})
        self.assertEqual(bg.get("service_worker"), "background.js")
        self.assertEqual(bg.get("type"), "module")

        # Action popup
        action = manifest.get("action", {})
        self.assertEqual(action.get("default_popup"), "popup.html")

    def test_extension_files_exist(self):
        """Verify all referenced files in the extension folder actually exist."""
        ext_dir = os.path.join(ROOT, "extension")
        required_files = [
            "manifest.json",
            "config.js",
            "background.js",
            "checking.html",
            "checking.js",
            "checking.css",
            "popup.html",
            "popup.js",
            "popup.css",
            os.path.join("icons", "icon16.png"),
            os.path.join("icons", "icon32.png"),
            os.path.join("icons", "icon48.png"),
            os.path.join("icons", "icon128.png"),
        ]
        for rel in required_files:
            full = os.path.join(ext_dir, rel)
            self.assertTrue(os.path.exists(full), f"File missing: {rel}")

    def test_config_port_matches_api(self):
        """Verify config.js uses port 5000 matching api.py default."""
        config_path = os.path.join(ROOT, "extension", "config.js")
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("5000", content, "config.js must reference port 5000 discovered from api.py")
        self.assertIn("CHECK_TIMEOUT_MS", content, "config.js must define pre-visit timeout")
        self.assertIn("RULES", content, "config.js must define DNR rule constants")

    def test_config_timeout_headroom(self):
        """Verify extension config timeout has sufficient headroom for live SPA analysis."""
        import re
        config_path = os.path.join(ROOT, "extension", "config.js")
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        match = re.search(r"CHECK_TIMEOUT_MS:\s*(\d+)", content)
        self.assertIsNotNone(match, "CHECK_TIMEOUT_MS must be defined in config.js")
        timeout_ms = int(match.group(1))
        self.assertGreaterEqual(timeout_ms, 8000, "CHECK_TIMEOUT_MS must be at least 8000ms for live SPA analysis")


if __name__ == "__main__":
    unittest.main()

