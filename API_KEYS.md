# Enable the optional intelligence tools

Keys belong on the Python server, never in the extension or website JavaScript.

1. In the project directory, run `cp .env.example .env` (only if `.env` does not already exist).
2. Fill in the values below in `.env`. Do not add quotes unless the value needs them.
3. Install the updated dependencies with `.venv/bin/pip install -r requirements.txt`.
4. Restart the server with `.venv/bin/python api.py`.
5. Open <http://127.0.0.1:5000/api/health>. The `integrations` object reports whether each key is present, without exposing its value. Presence is not proof that the key works. Run a live scan and inspect each provider's result to verify authentication.

The server now loads this project's `.env` automatically. Existing environment variables take precedence. `.env` is ignored by Git. Restart after editing keys. Never paste keys into screenshots or commit them.

| Tool | Variable | Setup |
| --- | --- | --- |
| Google Safe Browsing v4 | `GSB_API_KEY` | Create/select a project in [Google Cloud Console](https://console.cloud.google.com/), enable **Safe Browsing API** in APIs & Services → Library, then create an API key in Credentials. Restrict the key to Safe Browsing API. Because the Python server calls Google, do not configure browser referrer restrictions; use a server IP restriction if you have a stable outbound IP. [Official setup](https://developers.google.com/safe-browsing/v4/get-started). |
| VirusTotal v3 | `VT_API_KEY` | Create/sign in to a VirusTotal Community account, open your profile's API key page, and copy your key into `.env`. [Official setup](https://docs.virustotal.com/reference/getting-started). |
| URLhaus | `URLHAUS_AUTH_KEY` | Sign in at the [abuse.ch Authentication Portal](https://auth.abuse.ch/), generate an Auth-Key and paste it into `.env`. The backend sends it as an `Auth-Key` header for URL lookup. [Official lookup example](https://github.com/abusech/URLhaus/blob/master/lookup_url.py). |
| PhishTank | `PHISHTANK_APP_KEY` | If an account/application key is available, create an application and copy the key. It is optional; account registration availability may vary. [Developer information](https://phishtank.org/developer_info.php). |

RDAP registration age, DNS, TLS and the OpenPhish community feed need no key. A missing key is **skipped**; authentication failures, timeouts and quota limits are **unavailable**, not clean. VirusTotal URLs with no existing report are also unavailable, not clean. This app looks up existing VirusTotal reports; it does not submit new scan jobs.

Google Safe Browsing is for non-commercial use ([terms overview](https://developers.google.com/safe-browsing)). VirusTotal's public API allows 4 requests/minute and 500/day, with non-commercial restrictions ([limits](https://docs.virustotal.com/reference/public-vs-premium-api)). Rapid extension navigation can exceed this quota; test slowly or use a suitable paid plan. URLhaus community access is subject to its [fair-use rules](https://urlhaus.abuse.ch/api/).

# DOM and certificate display

For dynamic rendering install the browser once: `.venv/bin/python -m playwright install chromium`.
The renderer runs when static HTML is detected as a JavaScript shell. Challenge/error pages can remain unavailable. The website and extension show visual snapshots of static HTML (JavaScript disabled) and the Playwright-rendered DOM. A static snapshot of a JavaScript-only shell can be blank; its rendered DOM snapshot shows the hydrated page. The previews are non-interactive images. Source code remains available separately, limited to 100,000 characters. Target scripts never execute inside the dashboard or extension.

Certificate details include verification result, subject, issuer, covered hostnames, validity dates, expiry countdown, serial number, SHA-256 fingerprint, TLS version, and leaf certificate PEM. Failed verification is shown even when the leaf certificate can be read. This is the leaf certificate, not a full certificate-chain viewer. HTTP pages have no TLS certificate unless an observed redirect ends at HTTPS.

After changing extension files, reload PhishGuard on `chrome://extensions` and reopen the popup. The popup displays the last completed scan's evidence, including for lower-risk pages. Warning pages also expose the evidence.

# Why URL variations can differ

The host model already strips one leading `www.` and ignores the URL scheme. Plain HTTP is now an explicit transport warning with zero phishing-score adjustment on its own. Password collection over HTTP remains a risk signal. Content rules use the **observed final URL** so an HTTP-to-HTTPS redirect does not incorrectly trigger password-over-HTTP warnings. Infrastructure is refreshed when an observed redirect changes origin, while threat-feed hits on the submitted URL are retained.

`www` and bare hosts are not assumed to be interchangeable: different DNS, certificates, page content, access-denied responses, or threat-feed matches can legitimately produce different scores. The UI shows the submitted URL, observed destination, inspection method, model and evidence to make those differences inspectable. It never silently rewrites a URL to HTTPS or removes a subdomain before fetching. No retraining or universal false-positive fix is implied by these changes.

Observed redirects that only add `www`, upgrade HTTP to HTTPS, or add a root slash are excluded from the model redirect-count feature. Actual redirect counts and chains remain in the API evidence. Other redirects still count. SPA rendering polls for usable, stable HTML for a bounded period instead of assuming 300 ms is enough.


## Scoring policy and numbers

The deployed classifier is the existing trained 30-feature host model. The legacy 52-feature full model is retired: it learned unreliable layout shortcuts (e.g. zero navigation links implies phishing). No new model was trained as part of this repair. Page inspection still runs and its security rules still affect verdicts, including credential submission to external domains, passwords over HTTP, and title-brand impersonation. Missing titles, images or social links no longer change the model estimate. RDAP lookup failure is unknown information with zero score adjustment. No per-site allowlist or score override is used.

The score table starts with the model estimate and shows each sequential rule's actual percentage-point change and resulting score. Rules update log-odds: `p_after = sigmoid(logit(p_before) + delta_log_odds)`. These table changes add up; raw heuristic weights do not. The final score is not described as a validated real-world probability. Feature what-if checks separately replace one feature with a training baseline; they overlap and must never be added together. For example a 99.3% model estimate plus 0.2 log-odds becomes about 99.4%, not 103.3%.

Training now produces only the deployed host model. The archived full-model file is never loaded by the API. Historic full-model test metrics remain archival; they do not certify the current live pipeline. A future learned content model requires representative labelled live-page data and independent evaluation before deployment.

## Recovery when HTTP or an apex/www host cannot connect

The fetcher first requests the submitted address. After a timeout, connection failure or DNS failure, it can try HTTPS on the same host, then the HTTPS apex/www alternative for a bare domain or its `www` alias. It preserves paths and queries and does not add `www` to functional subdomains such as `portal.example.com`. It never downgrades HTTPS to HTTP and does not try aliases after a private-address block or certificate failure. A successfully returned HTTP error page is retained rather than replaced with another host's response.

The URL context records the actual request attempts. An alternate response is labelled address recovery, not a redirect from the failed original URL. Threat hits and hostname signals from the submitted URL are preserved. Only an inspected, lower-risk, same-domain HTTPS result with verified TLS can be offered to the extension as a recovered navigation address. See [TEST_URLS.md](TEST_URLS.md) for ten manual test URLs.

## Inspection path and rendering readiness

The website and extension show an ordered URL inspection path, including the entered URL, failed attempts, disclosed HTTPS/host recovery, observed HTTP redirect hops and status codes, browser/client navigation, and the final inspected address. When intermediate steps are unknown, the final address is labelled as an observation rather than an inferred redirect.

Threat intelligence has one summary row per provider. Expand its checked addresses to see results for the submitted and final URLs. Any listed address keeps the provider listed; an unavailable lookup is never hidden by a clean lookup on a different address.

Eligible HTML pages now receive browser rendering even when the initial HTML already contains text. Rendering waits for stable visible content and controls and for visible loading indicators to clear, within a bounded time. Visible images, backgrounds and fonts are allowed to load before capture. A rendering timeout or incomplete visual assets is explicitly labelled; external site failures and bot challenges can still prevent complete capture. The DOM capture and URL path are sampled together, so later background navigation cannot change an already captured path.
