# PhishGuard configuration

The project runs without required API keys. RDAP registration age, DNS, TLS and the OpenPhish community feed require no key. PhishTank lookups are attempted without an application key unless an optional key is configured. Network access and provider availability are still required for live checks.

## Local settings

Copy `.env.example` to `.env` only if you want to customise the defaults. The server automatically loads this file; existing environment variables take precedence. Restart the server after editing it.

| Setting | Default | Purpose |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | Local server bind address. |
| `PORT` | `5000` | API and dashboard port. |
| `PHISHTANK_APP_KEY` | Empty | Optional PhishTank application key; no setup is required to start. |

The `.env` file is ignored by Git. Never place an optional credential in website or extension JavaScript or commit it. If an application key is available, store it on the Python server. See [PhishTank developer information](https://phishtank.org/developer_info.php) for the provider's documentation.

## Included intelligence sources

- **OpenPhish:** checks the community URL/host feed, cached locally for one hour. No API key is needed.
- **PhishTank:** queries its URL-check service. An application key is optional in this implementation; provider access and rate limits can still prevent a lookup.
- **RDAP / optional WHOIS:** registration age when a record is available.
- **DNS:** resolution results and addresses.
- **TLS:** certificate verification and certificate details for the inspected HTTPS address.

Each threat provider appears once, with per-address results beneath it. A failed lookup is **unavailable**, not clean, and a clean result is not a guarantee of safety.

Open [the health endpoint](http://127.0.0.1:5000/api/health) to check server status. Its `integrations` object reports only whether the optional PhishTank key is present, without revealing its value. A presence flag does not validate the credential. Run a live scan to check actual provider availability.

# DOM and certificate display

For dynamic rendering install the browser once: `.venv/bin/python -m playwright install chromium`.
The renderer runs for eligible HTML pages, including pages whose initial HTML already contains text. Challenge/error pages can remain unavailable. The website and extension show visual snapshots of static HTML (JavaScript disabled) and the Playwright-rendered DOM. A static snapshot of a JavaScript-only shell can be blank; its rendered DOM snapshot shows the hydrated page. The previews are non-interactive images. Source code remains available separately, limited to 100,000 characters. Target scripts never execute inside the dashboard or extension.

Certificate details include verification result, subject, issuer, covered hostnames, validity dates, expiry countdown, serial number, SHA-256 fingerprint, TLS version, and leaf certificate PEM. Failed verification is shown even when the leaf certificate can be read. This is the leaf certificate, not a full certificate-chain viewer. TLS is checked for the HTTPS address actually inspected, including a disclosed recovery address.

After changing extension files, reload PhishGuard on `chrome://extensions` and reopen the popup. The popup displays the last completed scan's evidence, including for lower-risk pages. Warning pages also expose the evidence.

# Why URL variations can differ

The host model already strips one leading `www.` and ignores the URL scheme. Plain HTTP is now an explicit transport warning with zero phishing-score adjustment on its own. Password collection over HTTP remains a risk signal. Content rules use the **observed final URL** so an HTTP-to-HTTPS redirect does not incorrectly trigger password-over-HTTP warnings. Infrastructure is refreshed when an observed redirect changes origin, while threat-feed hits on the submitted URL are retained.

`www` and bare hosts are not assumed to be interchangeable: different DNS, certificates, page content, access-denied responses, or threat-feed matches can legitimately produce different scores. The UI shows the submitted URL, observed destination, inspection method, model and evidence to make those differences inspectable. It never silently rewrites a URL to HTTPS or removes a subdomain before fetching. No retraining or universal false-positive fix is implied by these changes.

Actual redirect counts and chains remain in the API evidence. A separate non-cosmetic redirect count excludes changes that only add `www`, upgrade HTTP to HTTPS or add a root slash; the deployed host model does not learn from redirect counts. SPA rendering polls for usable, stable HTML for a bounded period instead of assuming 300 ms is enough.


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
