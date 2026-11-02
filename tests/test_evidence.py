"""Regression coverage for URL context, certificate parsing and inert evidence."""
import datetime as dt
import unittest
from unittest.mock import patch, MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from phishguard import intel
from phishguard.feature_display import describe_features
from phishguard.predictor import PhishGuard
from phishguard.urlfeatures import is_cosmetic_redirect

HTML = '<html><head><title>Account</title></head><body><form action="/login"><input type="password"><input type="submit"></form></body></html>'
OSINT = {'whois': {'status': 'ok', 'age_days': 4000}, 'dns': {'status': 'ok', 'resolves': True}, 'tls': {'status': 'ok', 'valid': True}, 'threat_intel': []}


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.guard = PhishGuard()

    def test_offline_variants_have_identical_risk(self):
        for host in ('bookkr.co', 'maheslcm.manipal.edu'):
            results = [self.guard.assess(f'{scheme}://{prefix}{host}', live=False)
                       for scheme in ('http', 'https') for prefix in ('', 'www.')]
            self.assertEqual(len({r['final_score'] for r in results}), 1)
            self.assertEqual(len({r['verdict'] for r in results}), 1)

    def test_http_redirect_uses_final_scheme_and_preserves_threat_hit(self):
        page = {'html': HTML, 'status': 200, 'content_type': 'text/html', 'final_url': 'https://www.example.com/', 'n_redirects': 1}
        original = {**OSINT, 'threat_intel': [{'source': 'Test', 'status': 'listed'}]}
        with patch('phishguard.content.safe_fetch', return_value=page), patch.object(intel, 'enrich', side_effect=[original, OSINT]):
            result = self.guard.assess('http://example.com/')
        self.assertNotIn('password_over_http', [s['name'] for s in result['signals']])
        self.assertEqual(result['verdict'], 'PHISHING')
        self.assertEqual(result['page']['dom'], HTML)
        self.assertTrue(result['url_context']['redirected'])

    def test_playwright_dom_is_returned_and_bounded(self):
        shell = '<html><div id="root"></div><script src="/app.js"></script></html>'
        rendered = HTML + '<!--' + 'x' * 110000 + '-->'
        page = {'html': shell, 'status': 200, 'content_type': 'text/html', 'final_url': 'https://example.com/'}
        with patch('phishguard.content.safe_fetch', return_value=page), patch.object(intel, 'enrich', return_value=OSINT), patch('phishguard.content.render_with_playwright', return_value={'ok': True, 'html': rendered, 'final_url': 'https://example.com/'}):
            result = self.guard.assess('https://example.com/')
        self.assertEqual(result['page']['inspection_method'], 'playwright_rendered')
        self.assertEqual(len(result['page']['dom']), 100000)
        self.assertTrue(result['page']['dom_truncated'])

    def test_feature_guidance_does_not_invent_cutoffs(self):
        result = describe_features({'has_userinfo': 1, 'typosquat': 0, 'host_entropy': 4.7, 'HasPasswordField': 1})
        self.assertEqual(result['has_userinfo']['status'], 'bad')
        self.assertEqual(result['typosquat']['status'], 'good')
        self.assertEqual(result['host_entropy']['status'], 'neutral')
        self.assertEqual(result['HasPasswordField']['status'], 'neutral')

    def test_cosmetic_redirects_require_equivalent_observed_urls(self):
        self.assertTrue(is_cosmetic_redirect('http://bookkr.co', 'https://www.bookkr.co/'))
        for destination in ('https://evil.co/', 'http://www.bookkr.co/', 'https://www.bookkr.co/other', 'https://www.bookkr.co/?next=evil', 'https://www.bookkr.co:8080/'):
            self.assertFalse(is_cosmetic_redirect('https://bookkr.co', destination), destination)

    def test_canonical_redirect_count_does_not_change_content_risk(self):
        page = {'html': HTML, 'status': 200, 'content_type': 'text/html', 'final_url': 'https://www.bookkr.co/', 'n_substantive_redirects': 0}
        results = []
        for url, hops in [('https://bookkr.co/', 1), ('https://www.bookkr.co/', 0)]:
            with patch('phishguard.content.safe_fetch', return_value={**page, 'n_redirects': hops}), patch.object(intel, 'enrich', return_value=OSINT):
                results.append(self.guard.assess(url))
        self.assertEqual(results[0]['final_score'], results[1]['final_score'])
        self.assertEqual(results[0]['page']['redirects'], 1)
        self.assertEqual(results[0]['page']['content_features']['NoOfURLRedirect'], 0)

    def test_health_reports_presence_without_exposing_keys(self):
        import os
        import api
        with patch.dict(os.environ, {"GSB_API_KEY": "private-test-key"}):
            response = api.app.test_client().get('/api/health')
        self.assertTrue(response.json['integrations']['GSB_API_KEY'])
        self.assertNotIn('private-test-key', response.text)

    def test_redirect_does_not_inherit_destination_domain_age(self):
        page = {'html': HTML, 'status': 200, 'content_type': 'text/html', 'final_url': 'https://example.com/'}
        original = {**OSINT, 'whois': {'status': 'ok', 'age_days': 2}}
        with patch('phishguard.content.safe_fetch', return_value=page), patch.object(intel, 'enrich', side_effect=[original, OSINT]):
            result = self.guard.assess('https://paypal-account-verify.xyz/')
        self.assertEqual(result['osint']['whois']['age_days'], 2)
        self.assertEqual(result['host_features']['brand_in_sld_combo'], 1)
        self.assertIn('domain_very_new', [s['name'] for s in result['signals']])

    def test_unverified_certificate_still_has_details(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(123)
                .not_valid_before(now-dt.timedelta(days=1)).not_valid_after(now+dt.timedelta(days=5))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('example.com')]), critical=False).sign(key, hashes.SHA256()))
        tls = MagicMock()
        tls.__enter__.return_value = tls
        tls.getpeercert.return_value = cert.public_bytes(serialization.Encoding.DER)
        context = MagicMock()
        import ssl
        context.wrap_socket.side_effect = [ssl.SSLCertVerificationError(1, 'self signed'), tls]
        with patch.object(intel, 'assert_public_host'), patch.object(intel.socket, 'create_connection'), patch.object(intel.ssl, 'create_default_context', return_value=context):
            result = intel.tls_info('example.com')
        self.assertFalse(result['valid'])
        self.assertEqual(result['san'], ['example.com'])
        self.assertIn('BEGIN CERTIFICATE', result['pem'])
        self.assertEqual(len(result['sha256']), 64)


if __name__ == '__main__':
    unittest.main()
