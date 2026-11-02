"""Transport recovery must be general and must not erase source risk evidence."""
import unittest
from unittest.mock import patch
import requests

from phishguard import content, intel
from phishguard.predictor import PhishGuard

HTML = '<html><head><title>Site</title></head><body><form action="/login"><input type="text"><button>Continue</button></form></body></html>'


def response(url, **extra):
    return {'html': HTML, 'final_url': url, 'status': 200, 'content_type': 'text/html', 'tls_valid': True, **extra}


class RecoveryTests(unittest.TestCase):
    def test_candidates_preserve_path_query_and_functional_subdomains(self):
        self.assertEqual(content.fallback_urls('http://example.com/a?x=1'), ['https://example.com/a?x=1', 'https://www.example.com/a?x=1'])
        self.assertEqual(content.fallback_urls('https://www.example.com/a'), ['https://example.com/a'])
        self.assertEqual(content.fallback_urls('http://portal.example.com/a'), ['https://portal.example.com/a'])
        for url in ('https://portal.example.com/a', 'http://127.0.0.1/', 'http://user@example.com/', 'http://example.com:8080/'):
            self.assertEqual(content.fallback_urls(url), [])

    def test_failed_http_recovers_to_https_and_reports_failure(self):
        with patch.object(content, 'safe_fetch', side_effect=[requests.ReadTimeout('timeout'), response('https://example.com/')]) as fetch:
            page = content.fetch_with_fallback('http://example.com/')
        self.assertTrue(page['fallback_used'])
        self.assertEqual(page['fetch_attempts'][0]['reason'], 'ReadTimeout')
        self.assertEqual(fetch.call_args_list[1].args[0], 'https://example.com/')
        self.assertEqual(page.get('n_redirects', 0), 0)

    def test_www_recovery_only_after_connection_failure(self):
        with patch.object(content, 'safe_fetch', side_effect=[requests.ConnectionError(), response('https://www.example.com/')]):
            page = content.fetch_with_fallback('https://example.com/')
        self.assertEqual(page['fetch_url'], 'https://www.example.com/')
        with patch.object(content, 'safe_fetch', return_value=response('https://example.com/', status=403)) as fetch:
            page = content.fetch_with_fallback('https://example.com/')
        self.assertFalse(page['fallback_used'])
        self.assertEqual(fetch.call_count, 1)

    def test_dns_failure_is_distinct_from_ssrf_block(self):
        with patch.object(content, 'safe_fetch', side_effect=[content.UnresolvableTarget('DNS failed'), response('https://www.example.com/')]):
            page = content.fetch_with_fallback('https://example.com/')
        self.assertTrue(page['fallback_used'])

    def test_no_alternatives_after_ssrf_block(self):
        with patch.object(content, 'safe_fetch', side_effect=content.UnsafeTarget('private IP')) as fetch:
            with self.assertRaises(content.UnsafeTarget):
                content.fetch_with_fallback('http://example.com/')
        self.assertEqual(fetch.call_count, 1)

    def test_bad_tls_or_downgrade_cannot_be_accepted_as_recovery(self):
        for rejected, exception in ((response('https://www.example.com/', tls_valid=False), requests.exceptions.SSLError), (response('http://www.example.com/'), requests.ReadTimeout)):
            with patch.object(content, 'safe_fetch', side_effect=[requests.ReadTimeout('original failed'), rejected]):
                with self.assertRaises(exception):
                    content.fetch_with_fallback('https://example.com/')

    def test_successful_original_is_never_replaced_with_alias(self):
        with patch.object(content, 'safe_fetch', return_value=response('https://example.com/')) as fetch:
            page = content.fetch_with_fallback('https://example.com/')
        self.assertFalse(page['fallback_used'])
        self.assertEqual(fetch.call_count, 1)

    def test_source_threat_hit_survives_recovery_and_prevents_navigation(self):
        guard = PhishGuard()
        clean = {'whois': {'status': 'not_found'}, 'dns': {'status': 'ok'}, 'tls': {'status': 'ok', 'valid': True}, 'threat_intel': []}
        source = {**clean, 'threat_intel': [{'source': 'Test feed', 'status': 'listed'}]}
        with patch.object(content, 'safe_fetch', side_effect=[requests.ReadTimeout(), response('https://example.com/')]), patch.object(content, 'render_static_preview', return_value=None), patch.object(intel, 'enrich', side_effect=[source, clean]):
            result = guard.assess('http://example.com/')
        self.assertEqual(result['verdict'], 'PHISHING')
        self.assertTrue(result['url_context']['fallback_used'])
        self.assertFalse(result['url_context']['redirected'])
        self.assertNotIn('navigation_url', result)

    def test_verified_recovery_can_offer_https_navigation(self):
        guard = PhishGuard()
        clean = {'whois': {'status': 'not_found'}, 'dns': {'status': 'ok'}, 'tls': {'status': 'ok', 'valid': True}, 'threat_intel': []}
        with patch.object(content, 'safe_fetch', side_effect=[requests.ReadTimeout(), response('https://www.example.com/')]), patch.object(content, 'render_static_preview', return_value=None), patch.object(intel, 'enrich', return_value=clean):
            result = guard.assess('http://example.com/')
        self.assertEqual(result['page']['inspection_status'], 'inspected')
        self.assertEqual(result['navigation_url'], 'https://www.example.com/')


if __name__ == '__main__':
    unittest.main()
