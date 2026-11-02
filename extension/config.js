/**
 * PhishGuard Extension Configuration
 *
 * Configurable local API address and pre-visit scanning parameters.
 * Port 5000 is discovered from api.py (HOST=127.0.0.1, PORT=5000).
 */
export const CONFIG = {
  // Local PhishGuard API base endpoint
  API_BASE_URL: 'http://127.0.0.1:5000',

  // Endpoint paths
  ENDPOINTS: {
    PREDICT: '/api/predict',
    HEALTH: '/api/health'
  },

  // Request timeout in milliseconds for pre-visit checking (bounded at 6s for responsive browsing)
  CHECK_TIMEOUT_MS: 8000,

  // Temporary allow rule expiration in milliseconds (15s allows the navigation to complete smoothly)
  ALLOW_RULE_TTL_MS: 15000,

  // Cache duration in milliseconds (60 seconds short-lived cache for identical URLs)
  CACHE_TTL_MS: 60000,

  // Perform live OSINT and content inspection (set false for ultra-fast offline host-only model)
  // Note: when live is true, the server-side Python process fetches the page, not the user's browser.
  LIVE_CHECKS: true,

  // Declarative Net Request Rule IDs
  RULES: {
    ALLOW_LOCAL_IP: 1,
    ALLOW_LOCALHOST: 2,
    REDIRECT_MAIN_FRAME: 10,
    SESSION_ALLOW_BASE_ID: 1000
  },

  // Badge styles and texts matching the PhishGuard model thresholds:
  // SAFE: Legitimate (score < 0.40)
  // CHECK: Suspicious (0.40 <= score < 0.70)
  // RISK: Phishing (score >= 0.70)
  // ?: Scan failure or unreachable API
  BADGES: {
    CHECKING: { text: '...', color: '#4a5568' },
    SAFE: { text: 'SAFE', color: '#2f855a' },
    CHECK: { text: 'CHECK', color: '#d69e2e' },
    RISK: { text: 'RISK', color: '#e53e3e' },
    ERROR: { text: '?', color: '#718096' },
    UNSUPPORTED: { text: '', color: '#a0aec0' }
  }
};
