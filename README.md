> **Current scoring policy:** Deployed verdicts use the trained host classifier plus inspected content/security rules. The legacy full classifier is retired because layout counts (especially internal-link count) caused false positives on ordinary login pages. Historical full-model benchmark numbers below do not describe the current live pipeline. The training script now trains only the deployed host model. No website-specific score overrides are used.

# PhishGuard 🛡️

[![CI](https://github.com/Quantm56/PhishGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Quantm56/PhishGuard/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Framework: Flask](https://img.shields.io/badge/framework-Flask-lightgrey.svg)](https://flask.palletsprojects.com/)
[![ML: scikit-learn](https://img.shields.io/badge/ML-scikit--learn-orange.svg)](https://scikit-learn.org/)

**PhishGuard** is an end-to-end, multi-signal phishing detection system and threat intelligence pipeline. It bridges the gap between theoretical machine learning text-classification and real-world security engineering. 

Rather than treating phishing detection as a naive string-classification task, PhishGuard decouples **lexical host/domain features**, **safe static page content parsing**, **OSINT enrichment** (RDAP domain age, DNS resolution, TLS certificates), and **multi-source threat intelligence feeds** (OpenPhish, PhishTank, URLhaus, Google Safe Browsing, VirusTotal) into an explainable, risk-weighted verdict.

---

## 📌 Table of Contents
- [Architecture & Detection Pipeline](#-architecture--detection-pipeline)
- [Key Features](#-key-features)
- [Critical Finding: The Dataset Shortcut Artifact](#-critical-finding-the-dataset-shortcut-artifact)
- [Model Evaluation & Benchmarks](#-model-evaluation--benchmarks)
- [Project Directory Structure](#-project-directory-structure)
- [Quick Start](#-quick-start)
- [Chrome Browser Extension](#-chrome-browser-extension)
- [REST API Reference](#-rest-api-reference)
- [Web Dashboard Preview](#-web-dashboard-preview)
- [Threat Intelligence & Environment Variables](#-threat-intelligence--environment-variables)
- [Running Unit Tests](#-running-unit-tests)
- [Security & SSRF Safeguards](#-security--ssrf-safeguards)
- [Limitations](#-limitations)
- [License & Citation](#-license--citation)

---

## 🏗️ Architecture & Detection Pipeline

```
                              ┌────────────────────────────────────────┐
                              │            Submitted URL               │
                              └───────────────────┬────────────────────┘
                                                  │
            ┌─────────────────────────────────────┼─────────────────────────────────────┐
            │                                     │                                     │
            ▼                                     ▼                                     ▼
 ┌──────────────────────┐              ┌──────────────────────┐              ┌──────────────────────┐
 │ Host / Domain Engine │              │ Static Content Engine│              │  Threat Intelligence │
 │   (30 Features)      │              │ (24 Features, SSRF)  │              │    & OSINT Engine    │
 └──────────┬───────────┘              └──────────┬───────────┘              └──────────┬───────────┘
            │                                     │                                     │
            │  Host Lexical, Entropy,             │  HTML Structure, Forms,             │  RDAP Age, DNS, TLS,
            │  Punycode, Typosquats               │  Password over HTTP,                │  OpenPhish, PhishTank,
            │                                     │  Anchor Mismatch                    │  URLhaus, GSB, VT
            │                                     │                                     │
            └──────────────────┬──────────────────┘                                     │
                               │                                                        │
                               ▼                                                        │
                 ┌───────────────────────────┐                                          │
                 │   Dual ML Inference       │                                          │
                 │ ───────────────────────── │                                          │
                 │ • Full Model (54 feat.)   │                                          │
                 │ • Host-Only (fallback)    │                                          │
                 └─────────────┬─────────────┘                                          │
                               │ ML Probability                                         │ Feeds & Rules
                               ▼                                                        ▼
                 ┌─────────────────────────────────────────────────────────────────────────────┐
                 │                          Transparent Decision Engine                        │
                 │  • Rule-based risk adjustments (+/- points)                                 │
                 │  • Brand allow-list overrides (prevents false positives)                    │
                 │  • Active threat-feed listing triggers immediate PHISHING flag             │
                 └──────────────────────────────────────┬──────────────────────────────────────┘
                                                        │
                                                        ▼
                                    ┌──────────────────────────────────────┐
                                    │ Final Verdict & Detailed Explanation │
                                    │ (Score, Feature Contributions, OSINT)│
                                    └──────────────────────────────────────┘
```

---

## ✨ Key Features

- **Dual-Model ML Architecture**:
  - `model_full.joblib` (54 features): Used when live HTML content is successfully fetched.
  - `model_host.joblib` (30 features): Automatic fallback when the target page is offline, unreachable, or non-HTML.
- **SSRF-Guarded Content Extraction**:
  - Resolves host IPs and blocks private, loopback, and link-local ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`).
  - Enforces strict response size limits (2MB) and connection timeouts (4s) without running client-side JavaScript.
- **Heuristic Rule Engine**:
  - Catches sneaky tricks that evade traditional models: embedded `@` redirect syntax, URL embedded in path, suspicious keyword stuffing, executable file downloads, brand name spoofing in subdomains.
- **Multi-Source Threat Intelligence**:
  - Automated queries to **OpenPhish**, **PhishTank**, **URLhaus**, **Google Safe Browsing**, and **VirusTotal**.
  - Any verified listing forces an immediate **PHISHING** verdict, bypassing ML false negatives.
- **Explainable Predictions**:
  - Every prediction includes a human-readable breakdown of the contributing risk factors (e.g., *domain registered < 30 days ago (+0.20)*, *password field over plain HTTP (+0.20)*).
- **Interactive Flask Dashboard & REST API**:
  - Real-time URL evaluation interface with full metrics viewer and evaluation charts.

---

## 🔬 Critical Finding: The Dataset Shortcut Artifact

Standard phishing datasets (such as PhiUSIIL with 235k samples) contain subtle data collection artifacts that mislead models trained naively on raw URL strings:

| Artifact in Dataset | Measured Evidence |
|---|---|
| **Legitimate URLs lack paths** | **100%** of legitimate URLs in PhiUSIIL are `https://www.<domain>` with no path; **28%** of phishing URLs have paths. |
| **Subdomain distribution** | Only **~6%** of legitimate hosts have subdomains (vs. **~55%** of phishing hosts). 0% of legitimate hosts are on free-hosting platforms (vs. 25% of phishing). |

### The Consequence
A naive URL-string model (length, presence of `www`, `https`, paths) scores **99.8%** on standard random test splits. However, when tested against **30 real-world legitimate URLs** (`github.com/pallets/flask/issues/...`, `mail.google.com`, `manipal.edu/mit/...`), the naive model flags **100% of them as phishing**!

### How PhishGuard Solves This
1. **Host-Level Feature Isolation**: The ML models strictly ingest host-level lexical/statistical features and page content. Schema (`http` vs `https`) and path parameters are never passed directly to the classifier.
2. **Path & Query Rules**: Path indicators (e.g., `@` tricks, `.exe` downloads) are evaluated as documented, transparent heuristic rules with fixed weights.
3. **Data Augmentation**: The legitimate training partition is augmented with synthetic realistic subdomains (`mail.`, `docs.`, `accounts.`, `portal.`). Validation and test sets are never augmented.
4. **Domain-Grouped Holdout Split**: Train/val/test splits (70/15/15) are strictly partitioned by **registered domain** (`GroupShuffleSplit`), guaranteeing that no domain appears in both training and test sets.

> **Result**: After these mitigations, PhishGuard's host model achieves only a **3% (1/30)** false-positive rate on real deep-link legitimate URLs while maintaining **100% (12/12)** recall on hand-written phishing URLs.

---

## 📊 Model Evaluation & Benchmarks

Evaluated on a domain-grouped hold-out test set consisting of **34,634 URLs** (unseen domains):

| Feature Set | Classifier | Accuracy | Precision | Recall | F1 Score | ROC-AUC |
|---|---|---|---|---|---|---|
| **Host / Domain (30 features)** | **HistGradientBoosting** | **76.42%** | **93.88%** | **45.78%** | **61.54%** | **0.8021** |
| Host / Domain (30 features) | Random Forest | 77.01% | 91.56% | 47.99% | 62.65% | 0.7973 |
| Host / Domain (30 features) | Logistic Regression | 74.65% | 91.13% | 42.10% | 57.20% | 0.7482 |
| Host / Domain (30 features) | Linear SVM (Calibrated) | 73.97% | 91.80% | 39.80% | 55.04% | 0.7540 |
| **Host + Page Content (54 features)** | **HistGradientBoosting** | **99.66%** | **99.78%** | **99.40%** | **99.59%** | **1.0000** |
| Host + Page Content (54 features) | Linear SVM (Calibrated) | 99.51% | 99.55% | 99.25% | 99.40% | 0.9998 |
| Host + Page Content (54 features) | Logistic Regression | 99.47% | 99.51% | 99.22% | 0.9936 | 0.9997 |
| Host + Page Content (54 features) | Random Forest | 99.39% | 99.39% | 99.13% | 0.9926 | 0.9999 |
| *Ablation: Naive URL-String* | *Random Forest* | *99.82%* | *99.85%* | *99.73%* | *99.79%* | *0.9986\** |

*\*Note: While the naive URL-string model achieves 99.8% on dataset splits, it fails completely on real-world legitimate deep links due to dataset shortcut bias.*

---

## 📂 Project Directory Structure

```
PhishGuard/
├── .github/
│   └── workflows/
│       └── ci.yml               # Automated multi-OS GitHub Actions CI
├── data/
│   ├── .gitkeep                 # Ensures data directory exists
│   └── README.md                # Guide to obtaining PhiUSIIL dataset
├── models/
│   ├── model_full.joblib        # Pre-trained host + content classifier
│   └── model_host.joblib        # Pre-trained host-only fallback classifier
├── phishguard/
│   ├── __init__.py              # Package entrypoint
│   ├── brands.py                # Brand lists, high-risk TLDs, typosquat detection
│   ├── content.py               # Safe HTML fetching & SSRF-guarded feature extraction
│   ├── intel.py                 # OSINT (RDAP age, DNS, TLS) & threat feed integrations
│   ├── predictor.py             # Inference pipeline, rule engine & score aggregator
│   └── urlfeatures.py           # Lexical, structural & entropy feature extractors
├── results/
│   ├── metrics.json             # Full benchmark evaluation metrics
│   ├── roc_importance.png       # ROC curves and feature importance plots
│   └── train_log.txt            # Training run log output
├── templates/
│   └── index.html               # Responsive web UI dashboard
├── tests/
│   └── test_pipeline.py         # 30 comprehensive unit & regression tests
├── .env.example                 # Environment configuration template
├── .gitattributes               # Cross-platform line ending normalization
├── .gitignore                   # Standard Python, dataset, and OS ignore rules
├── api.py                       # Flask REST API server and dashboard handler
├── CONTRIBUTING.md               # Contribution guidelines
├── LICENSE                      # MIT Open Source License
├── pyproject.toml               # Python package configuration
├── README.md                    # Project documentation
├── requirements.txt             # Core runtime dependencies
└── train.py                     # Model training & ablation evaluation script
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13
- Git

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Quantm56/PhishGuard.git
   cd PhishGuard
   ```

2. **Create and activate a virtual environment:**
   - **Linux / macOS:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```
   - **Windows (PowerShell):**
     ```powershell
     python -m venv .venv
     .venv\Scripts\Activate.ps1
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Application:**
   *(Pre-trained models are already included in `models/`, no training required!)*
   ```bash
   python api.py
   ```
   Open your browser at `http://127.0.0.1:5000` to interact with the dashboard!

---

## 🧩 Chrome Browser Extension (Pre-Visit Checking Flow)

PhishGuard includes a Manifest V3 Google Chrome extension located in the `extension/` directory. Rather than inspecting pages after they load, this version implements a **synchronous pre-visit interception flow**:

```
[User clicks link / enters URL]
               │
               ▼
   [Chrome DNR Interception] (Priority 1: regexFilter: ^https?://.+)
               │
               ▼
[Redirects to extension checking.html?url=...] (Browser socket held)
               │
               ▼
     [POST /api/predict] ─── (Local Python server at 127.0.0.1:5000)
               │
      ┌────────┴───────────────────────────┬────────────────────────────────┐
      ▼                                    ▼                                ▼
 [LEGITIMATE]                    [SUSPICIOUS / PHISHING]             [API OFFLINE / ERROR]
 (score < 40%)                     (score >= 40%)                     (timeout / 500 / net down)
      │                                    │                                │
      ▼                                    ▼                                ▼
Add session allow rule            Display Warning Screen            Display Verification Error
(tabId, cleanUrl, priority 2)     (RISK / CHECK badges, score,      (Never auto-clears safe)
      │                           reasons, signals)                 Choices:
      ▼                                    │                        - Go back (Recommended)
Navigate to original URL          Choices:                          - Retry verification
      │                           - Go back (Recommended)           - Proceed at own risk
      ▼                           - Proceed anyway (Confirmation)
Page loads safely                          │
      │                                    ▼
Navigation complete:              Add session allow rule & proceed
Auto-remove allow rule                     │
(Repeat visits re-checked!)                ▼
                                  Auto-remove allow rule on load
```

### 1. Why `tabs.onUpdated` Cannot Prevent Page Loading

In Manifest V3, `chrome.tabs.onUpdated` is an **asynchronous notification event**, not an interceptor. By the time `onUpdated` fires:
- Chrome's network stack has already resolved DNS, negotiated TLS, and sent the HTTP request.
- The destination server may have already transmitted HTTP headers, Set-Cookie directives, tracking pixels, or exploit payloads.
- Redirecting inside `onUpdated` via `chrome.tabs.update()` is inherently prone to race conditions where the destination webpage executes scripts or partially renders before the tab is redirected.
- Ordinary Manifest V3 `chrome.webRequest` listeners are non-blocking and cannot pause network requests while an asynchronous API call completes.

To guarantee true pre-visit protection without enterprise policies or deprecated Manifest V2 APIs, PhishGuard utilizes **Declarative Net Request (DNR)** rules to redirect `main_frame` navigations synchronously before any destination network connection is established.

### 2. Declarative Net Request Rules & Navigation Loop Prevention

To prevent infinite redirection loops while ensuring thorough security, PhishGuard employs a tiered priority rule system:

1. **Rule 1 & 2 (Priority 3 - Allow Localhost & API)**:
   - Direct visits to `http://127.0.0.1:5000` (the PhishGuard dashboard) or `http://localhost` are explicitly allowed and never redirected.
2. **Rule 10 (Priority 1 - Intercept Main Frame)**:
   - All other top-level HTTP/HTTPS navigations are intercepted and rewritten to `chrome-extension://<id>/checking.html?url=\0`.
3. **Session-Scoped Allow Rules (Priority 2 - Scoped Pass-Through)**:
   - When a URL receives a `LEGITIMATE` verdict (or when the user explicitly confirms "Proceed anyway"), the background worker dynamically registers a temporary session rule:
     - Priority: `2` (higher than Rule 10's redirect, lower than Rule 1's local allow).
     - Scoped strictly to that specific `tabId` and exact `cleanUrl` (`condition.tabIds: [tabId]`, `condition.urlFilter: |<cleanUrl>`).
     - Resource type restricted to `main_frame`.
   - The checking page then executes `window.location.replace(targetUrl)`.
   - Chrome matches the priority 2 allow rule and allows the page through.
   - **Automatic Rule Revocation**: As soon as the tab finishes loading (`chrome.tabs.onUpdated` with `status: 'complete'`) or after a 15-second TTL safety backstop, the temporary session rule is revoked.
   - **Repeat Visit Protection**: Navigating back to or reloading that URL subsequently triggers a fresh pre-visit check.
   - **Redirect Chain Protection**: If domain A redirects (HTTP 301/302) to domain B, domain B is evaluated as a new navigation and redirected to `checking.html?url=B`.

### 3. Server-Side Scan vs Browser Navigation

> **Important Security Architecture Note**:
> When `LIVE_CHECKS` is enabled (`live: true`), the local PhishGuard server (running in Python) performs an SSRF-guarded static fetch and OSINT queries (RDAP, DNS, TLS) to inspect the website. 
> The **user's web browser** remains on the internal extension page and has **not** connected to the destination server, submitted cookies, executed JavaScript, or loaded remote DOM assets.

### 4. Permissions Explained

- `declarativeNetRequest`: Used to declare dynamic redirect rules for top-level `main_frame` navigations and session-scoped temporary allow rules.
- `tabs`: Enables the extension to read `tab.url`, track navigation completion, and clean up temporary rules when tabs close or navigate away.
- `storage`: Enables `chrome.storage.session` for transient in-memory per-tab status and caching without logging permanent browsing history.
- `host_permissions` (`*://*/*`, `http://127.0.0.1:5000/*`, `http://localhost:5000/*`): Required by Chrome Declarative Net Request to match and redirect external HTTP/HTTPS requests to `checking.html`, and to query the local Flask API.

### 5. Starting the PhishGuard API (Windows PowerShell)

Ensure the local API server is running before testing the extension:

```powershell
# Step 1: Open Windows PowerShell and navigate to the project directory
cd "c:\Users\Chinmay Vyas\OneDrive\Desktop\BTECH SEM 5\ISL API Extension\PhishGuard"

# Step 2: Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# Step 3: Launch the API server
python api.py
```

The API starts on `http://127.0.0.1:5000` with CORS preflight and headers enabled for extension communication.

### 6. Loading the Extension in Google Chrome

1. Open Google Chrome and navigate to:
   ```
   chrome://extensions
   ```
2. In the top-right corner, toggle on **Developer mode**.
3. In the top-left toolbar, click **Load unpacked**.
4. In the folder picker dialog, select the `extension/` directory:
   ```
   c:\Users\Chinmay Vyas\OneDrive\Desktop\BTECH SEM 5\ISL API Extension\PhishGuard\extension
   ```
5. Click **Select Folder**. The **PhishGuard Pre-Visit URL Scanner** extension will appear in your installed extensions list.
6. Pin the extension to your Chrome toolbar.

### 7. Pre-Visit Flow & UI Experience

| Outcome | Screen Shown | Badge | Behavior |
|---|---|---|---|
| **Checking** | `checking.html` (Spinner + Target URL) | `...` | Navigation paused. Inspecting features via local API. |
| **Legitimate** | Green Confirmation &rarr; Auto-forward | `SAFE` | Verified clean (score < 40%). Continues automatically. |
| **Suspicious** | Warning Screen (Amber Banner) | `CHECK` | Score 40%–69%. Shows signals. Offers "Go back" & "Proceed anyway". |
| **Phishing** | Warning Screen (Red Banner) | `RISK` | Score &ge; 70%. Shows risk breakdown. Offers "Go back" & "Proceed anyway". |
| **API Offline** | Error Screen ("Unable to verify") | `?` | Server stopped or timeout. Never auto-clears. Explicit user choice. |

### 8. Reproducible Manual Test Checklist (Using Controlled Test Pages)

Follow these steps to demonstrate every flow safely in Google Chrome:

1. **Legitimate URL Auto-Forward Test**:
   - In Chrome's address bar, type or navigate to: `https://github.com/pallets/flask`
   - Observe immediate redirection to the PhishGuard "Checking this website..." page.
   - Within 1–2 seconds, observe the green checkmark ("Website Verified as Legitimate") and automatic forwarding to GitHub.
   - Check the extension badge: shows green **`SAFE`**.
2. **Suspicious / Phishing Warning Screen Test**:
   - In the address bar, type: `http://secure-login-update-paypal.com` or `http://verify-account-bank-login.xyz`
   - Observe immediate interception to the PhishGuard checking page.
   - Observe the page halt on the Warning Screen with a red/amber banner, **`RISK`** or **`CHECK`** badge, risk percentage, and plain-text signals (e.g. *brand name in sld combo*).
   - Click **"Go back to safety (Recommended)"**: verify it navigates back or closes the tab.
3. **"Proceed Anyway" Override Test**:
   - Re-visit `http://secure-login-update-paypal.com`.
   - On the warning screen, click **"Proceed anyway (Unsafe)"**.
   - Observe the confirmation prompt ("Are you sure you want to proceed?"). Click **"Yes, proceed to website"**.
   - Verify that the temporary allow rule admits navigation without looping back to `checking.html`.
4. **Repeat Visit Re-Verification Test**:
   - After proceeding to the test URL in step 3, refresh the page or open the same URL in a new tab.
   - Verify that the temporary session rule was already revoked and the checking screen appears again (no persistent bypass).
5. **API Offline / Timeout Error Test**:
   - In your PowerShell terminal, stop the Flask API server using `Ctrl+C`.
   - In Chrome, navigate to `https://en.wikipedia.org/wiki/Computer_security`.
   - Observe the checking page display **"Unable to verify this site"** with clear explanation that the scanner at `127.0.0.1:5000` is offline.
   - Verify that it does **not** assume safe. Test **"Retry verification"** after restarting `python api.py`.
6. **Local API Dashboard Exemption Test**:
   - Navigate to `http://127.0.0.1:5000/`.
   - Verify that the PhishGuard web dashboard opens immediately without being redirected to `checking.html`.

---

## 🌐 REST API Reference

### 1. Predict URL Safety
**`POST /api/predict`**

#### Request Payload:
```json
{
  "url": "http://secure-login-update-paypal.com",
  "live": true,
  "fetch_page": true
}
```
- `url` *(string, required)*: The URL to evaluate (max 4096 characters).
- `live` *(boolean, optional, default: true)*: Perform live OSINT (RDAP, DNS, TLS, threat feeds).
- `fetch_page` *(boolean, optional, default: true)*: Attempt live static HTML extraction.

#### Example Request:
```bash
curl -X POST http://127.0.0.1:5000/api/predict \
     -H "Content-Type: application/json" \
     -d '{"url": "http://secure-login-update-paypal.com", "live": false}'
```

#### Sample Response:
```json
{
  "url": "http://secure-login-update-paypal.com",
  "verdict": "PHISHING",
  "final_score": 0.88,
  "ml_probability": 0.85,
  "model_used": "host_only",
  "rule_signals": [
    {
      "name": "brand_spoof_sld",
      "weight": 0.15,
      "detail": "sld contains brand name combo: paypal"
    }
  ],
  "feature_explanation": [
    { "feature": "brand_in_sld_combo", "value": 1, "note": "brand imitation" },
    { "feature": "host_len", "value": 30, "note": "long host name" }
  ],
  "threat_intel": [],
  "osint": {
    "domain_age_days": null,
    "dns_resolves": null
  }
}
```

### 2. Service Health Check
**`GET /api/health`**
```json
{
  "status": "ok"
}
```

### 3. Model Evaluation Metrics
**`GET /api/metrics`**
Returns the entire evaluation report, including cross-validation scores, ROC coordinates, and permutation importances.

---

## 🖥️ Web Dashboard Preview

The embedded dashboard provides:
1. **Live URL Scanner**: Input any URL to view instant verdicts, confidence gauges, risk factor breakdowns, and OSINT threat intel badges.
2. **Model Evaluation Tab**: Side-by-side comparison of Logistic Regression, Linear SVM, Random Forest, and Gradient Boosting.
3. **Dataset Insights**: Interactive visualization of feature distributions and dataset artifacts.

---

## 🔑 Threat Intelligence & Environment Variables

PhishGuard works fully out-of-the-box without any API keys (RDAP, DNS, TLS, and OpenPhish operate without keys).

To enable commercial and rate-limited threat intelligence providers, copy `.env.example` to `.env` or set the following environment variables:

| Variable | Provider | Purpose | Free Tier Availability |
|---|---|---|---|
| `GSB_API_KEY` | Google Safe Browsing v4 | Checks URL against Google's malware and phishing list | Available via Google Cloud Console |
| `VT_API_KEY` | VirusTotal API v3 | Queries multi-engine URL analysis reports | 4 requests/min free tier |
| `URLHAUS_AUTH_KEY` | abuse.ch URLhaus | Checks malware distribution URLs | Free key at auth.abuse.ch |
| `PHISHTANK_APP_KEY` | PhishTank | Queries community-verified phishing reports | Free developer key |

> **Graceful Degradation**: If an API key is omitted or a third-party service fails/times out, PhishGuard records the source as `unavailable` or `skipped` and **never** assumes the URL is clean.

---

## 🧪 Running Unit Tests

The test suite covers API endpoints, SSRF protection guards, brand impersonation detection, OSINT parsing, and edge-case handling across 30 automated tests:

```bash
python -m unittest discover -s tests -v
```

Output:
```
Ran 30 tests in 5.235s
OK
```

---

## 🛡️ Security & SSRF Safeguards

When analyzing potentially hostile URLs in live mode, PhishGuard implements defense-in-depth:
- **Private IP Blocking**: Resolves destination hostnames and blocks private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), and link-local (`169.254.0.0/16`) addresses on initial request and every subsequent redirect hop.
- **Resource Limits**: Caps response bodies at 2 MB and enforces strict socket timeouts (4 seconds).
- **Execution Sandboxing**: No JavaScript engine or headless browser is executed; only raw HTML DOM elements are parsed via BeautifulSoup.

---

## ⚠️ Limitations

- **Heuristic Rule Weights**: Rule weights (e.g., `+0.20` for domains younger than 30 days) are expert-configured heuristics, as the underlying PhiUSIIL dataset does not contain WHOIS timestamps.
- **Dynamic Content**: PhishGuard evaluates static HTML. Heavily obfuscated single-page applications (SPAs) that render entirely client-side via JavaScript are inspected through the host-level model and threat feeds.
- **Brand Allow-List Scope**: The default brand directory comprises ~60 commonly targeted institutions (PayPal, Microsoft, Google, etc.). Attackers leveraging compromised subdomains on trusted domains are checked via threat intelligence feeds.

---

## 📄 License & Citation

### License
This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.

### Dataset Citation
If you utilize this benchmark or repository in your research, please cite the PhiUSIIL dataset:
```bibtex
@article{prasad2023phiusiil,
  title={PhiUSIIL: A Novel Dataset for Phishing URL Detection Using Machine Learning Techniques},
  author={Prasad, Arvind and Rohokale, Rajesh},
  journal={Computers \& Security},
  volume={132},
  pages={103348},
  year={2023},
  publisher={Elsevier}
}
```

## API keys and inspection evidence

See [API_KEYS.md](API_KEYS.md) for server key setup, provider limits, DOM and certificate display, and URL-variation behaviour.
