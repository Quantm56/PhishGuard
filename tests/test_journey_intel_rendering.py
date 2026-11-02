"""Regression tests for per-provider aggregation, inspection paths and DOM readiness."""
import unittest
from unittest.mock import patch, MagicMock

from phishguard import content, intel
from phishguard.journey import inspection_journey
from phishguard.predictor import PhishGuard


class IntelAndJourneyTests(unittest.TestCase):
    def test_live_enrichment_uses_two_sources_without_required_keys(self):
        import os
        self.assertEqual([feed.__name__ for feed in intel.THREAT_FEEDS], ['check_openphish', 'check_phishtank'])
        response = MagicMock()
        response.json.return_value = {'results': {'in_database': False}}
        with patch.dict(os.environ, {'PHISHTANK_APP_KEY': ''}), patch.object(intel, 'domain_age', return_value={'status': 'not_found'}), patch.object(intel, 'dns_info', return_value={'status': 'ok', 'resolves': True}), patch.object(intel, 'tls_info', return_value={'status': 'ok', 'valid': True}), patch.object(intel, '_load_openphish', return_value=set()), patch.object(intel.requests, 'post', return_value=response) as post:
            result = intel.enrich('https://example.com/')
        self.assertEqual([row['source'] for row in result['threat_intel']], ['OpenPhish', 'PhishTank'])
        self.assertTrue(all(row['status'] == 'clean' for row in result['threat_intel']))
        post.assert_called_once()
        self.assertEqual(post.call_args.args[0], 'https://checkurl.phishtank.com/checkurl/')
        self.assertNotIn('app_key', post.call_args.kwargs['data'])

    def test_duplicate_providers_become_one_row_with_per_url_evidence(self):
        rows = [{'source': 'OpenPhish', 'status': 'clean', 'detail': 'No match'}, {'source': 'PhishTank', 'status': 'unavailable', 'detail': 'Timeout'}]
        merged = intel.merge_threat_results([('http://example.com', rows), ('https://example.com/', rows)])
        self.assertEqual([r['source'] for r in merged], ['OpenPhish', 'PhishTank'])
        self.assertEqual(len(merged[0]['checks']), 2)
        self.assertEqual(merged[0]['status'], 'clean')

    def test_source_listing_is_not_lost_to_clean_destination(self):
        rows = intel.merge_threat_results([('http://example.com', [{'source': 'Feed', 'status': 'listed', 'detail': 'Hit'}]), ('https://example.com', [{'source': 'Feed', 'status': 'clean', 'detail': 'No hit'}])])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['status'], 'listed')
        self.assertEqual(len(rows[0]['checks']), 2)

    def test_missing_url_coverage_is_not_reported_clean(self):
        rows = intel.merge_threat_results([('http://example.com', [{'source': 'Feed', 'status': 'unavailable'}]), ('https://example.com', [{'source': 'Feed', 'status': 'clean'}])])
        self.assertEqual(rows[0]['status'], 'unavailable')

    def test_repeated_same_url_evidence_is_not_duplicated(self):
        row = {'source': 'Feed', 'status': 'clean', 'detail': 'No hit'}
        merged = intel.merge_threat_results([('https://example.com', [row, row])])
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0]['checks']), 1)

    def test_path_includes_recovery_http_and_client_navigation(self):
        page = {'fetch_url': 'https://example.com/', 'fallback_used': True,
                'fetch_attempts': [{'url': 'http://example.com/', 'status': 'failed', 'reason': 'ReadTimeout'}],
                'redirect_chain': [{'from': 'https://example.com/', 'to': 'https://www.example.com/', 'status': 301}],
                'browser_navigations': [{'from': 'https://www.example.com/', 'to': 'https://www.example.com/app', 'kind': 'browser_navigation'}],
                'final_url': 'https://www.example.com/app'}
        steps = inspection_journey('http://example.com/', page)
        self.assertEqual([s['kind'] for s in steps], ['submitted', 'failed_attempt', 'recovery', 'http_redirect', 'browser_navigation', 'final'])
        self.assertEqual(steps[-1]['url'], page['final_url'])

    def test_failure_path_keeps_redirect_before_failed_request(self):
        attempts = [{"url": "http://example.com/", "status": "failed", "reason": "ReadTimeout", "failed_url": "https://example.com/", "redirect_chain": [{"from": "http://example.com/", "to": "https://example.com/"}]}]
        steps = inspection_journey('http://example.com/', None, 'Page unreachable', attempts)
        self.assertEqual([s['kind'] for s in steps], ['submitted', 'http_redirect', 'failed_attempt', 'unavailable'])
        self.assertEqual(steps[2]['url'], 'https://example.com/')
        self.assertFalse(any(s['kind'] == 'final' for s in steps))

    def test_static_html_also_gets_browser_rendering(self):
        original = '<html><body><p>Content already present ' + 'hello ' * 25 + '</p><script src="/app.js"></script></body></html>'
        rendered = '<html><body><h1>Loaded application</h1><input type="email"><button>Continue</button></body></html>'
        page = {'html': original, 'status': 200, 'final_url': 'https://example.com/', 'content_type': 'text/html'}
        osint = {'whois': {'status': 'not_found'}, 'tls': {'status': 'ok', 'valid': True}, 'dns': {'status': 'ok'}, 'threat_intel': []}
        with patch.object(content, 'safe_fetch', return_value=page), patch.object(content, 'render_static_preview', return_value=None), patch.object(content, 'render_with_playwright', return_value={'ok': True, 'html': rendered, 'final_url': 'https://example.com/', 'readiness': {'state': 'settled'}}) as render, patch.object(intel, 'enrich', return_value=osint):
            result = PhishGuard().assess('https://example.com/')
        render.assert_called_once()
        self.assertEqual(result['page']['inspection_method'], 'playwright_rendered')
        self.assertIn('Loaded application', result['page']['dom'])
        self.assertEqual(result['page']['render_readiness']['state'], 'settled')


if __name__ == '__main__':
    unittest.main()
