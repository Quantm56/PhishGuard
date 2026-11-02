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
- **Dynamic Content**: PhishGuard evaluates static HTML. Heavily obfuscated single-page applications (SPAs) that render entirely client-side via JavaScript are inspected through the host-level model and threat feeds. The optional dynamic-scan worker (see below) addresses this limitation.
- **Brand Allow-List Scope**: The default brand directory comprises ~60 commonly targeted institutions (PayPal, Microsoft, Google, etc.). Attackers leveraging compromised subdomains on trusted domains are checked via threat intelligence feeds.

---

## 🐳 Dynamic Webpage Analysis (Playwright + Docker)

PhishGuard's static scanner cannot see page elements created by JavaScript. The optional **dynamic-scan worker** fixes this by opening the URL in headless Chromium (Playwright), inside a disposable Docker container, and returning the fully rendered DOM, a screenshot, the redirect chain, and cookie metadata.

### Architecture

```
POST /api/dynamic_scan
        │
        ▼
phishguard/dynamic_scan.py   (main-app bridge)
        │  stdin JSON payload
        ▼
docker run --rm phishguard-worker  (ephemeral container)
        │
        ├── entrypoint.sh  →  iptables egress rules (hard network boundary)
        └── worker.py      →  Playwright headless Chromium
                │
                ├── Screenshot (PNG)
                ├── Rendered DOM (HTML after JS)
                ├── Redirect chain
                └── Cookie metadata (no values)
        │
        ▼  stdout JSON result
phishguard/dynamic_scan.py
        │
        ├── Saves artifacts → results/dynamic/
        └── Runs extract_content_features() on rendered DOM
```

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Docker Desktop | ≥ 4.x | Must be running. Windows: use Linux containers mode. |
| Python | 3.10–3.14 | Already required by PhishGuard |
| Free disk space | ~2 GB | Playwright base image |

### Build the Worker Image (PowerShell)

```powershell
# From the PhishGuard project root:
cd "c:\...\PhishGuard"

# Build the dynamic-scan worker image (~2 GB download on first run)
docker build -t phishguard-worker:latest .\dynamic_worker\

# Verify
docker images phishguard-worker
```

### Run the Application (with dynamic scan support)

```powershell
# Option A – plain Python (recommended for development)
.venv\Scripts\Activate.ps1
python api.py
# Flask starts at http://127.0.0.1:5000

# Option B – docker compose (app + worker image in one command)
docker compose build
docker compose up app
```

### Trigger a Dynamic Scan

**PowerShell / curl:**
```powershell
curl.exe -X POST http://127.0.0.1:5000/api/dynamic_scan `
  -H "Content-Type: application/json" `
  -d '{"url": "https://example.com", "timeout": 25}'
```

**Python requests:**
```python
import requests
r = requests.post("http://127.0.0.1:5000/api/dynamic_scan",
                  json={"url": "https://example.com", "timeout": 25})
print(r.json())
```

### Example Response

```json
{
  "status": "ok",
  "error": null,
  "final_url": "https://www.iana.org/domains/reserved",
  "redirect_chain": ["https://example.com/", "https://www.iana.org/domains/reserved"],
  "cookies": [
    {"name": "session", "domain": "example.com", "httpOnly": true, "secure": true, "sameSite": "Strict"}
  ],
  "page_title": "IANA — Example Domains",
  "navigation_errors": [],
  "content_features": {
    "HasTitle": 1.0, "HasPasswordField": 0.0, "HasSubmitButton": 0.0,
    "NoOfJS": 3.0, "NoOfExternalRef": 5.0
  },
  "content_signals": [],
  "artifacts": {
    "screenshot_path": "results/dynamic/screenshot_a3f2b1….png",
    "rendered_html_path": "results/dynamic/rendered_a3f2b1….html"
  },
  "scanned_at": "2026-11-02T07:05:00+00:00",
  "_note": "content_features were computed by re-using the static extractor on rendered DOM. The full-model 99.66% accuracy claim does NOT apply to these rendered-DOM features; retraining or recalibration is required for production use."
}
```

### Expected Artifacts

After a successful scan, two files appear under `results/dynamic/`:

| File | Contents | Max size |
|---|---|---|
| `screenshot_<scan_id>.png` | Full-page screenshot | 1 MB |
| `rendered_<scan_id>.html` | DOM after JavaScript ran | 500 KB |

> **Note**: Cookie *values* are never stored. Only name, domain, httpOnly flag, secure flag, and sameSite policy are forwarded to the main app. Raw DOM content is base64-encoded inside the container and decoded by the bridge; no content is logged.

### Test Without Visiting Live URLs

```powershell
# All tests except test_dynamic_worker_sees_js_form run without Docker
.venv\Scripts\Activate.ps1
python -m unittest tests.test_dynamic -v

# With Docker running, the full suite including Playwright runs:
python -m unittest tests.test_dynamic -v
# Expected: 17 tests, 0 failures, 0 errors (1 skipped when Docker is off)
```

### Resource Requirements

| Resource | Limit (per scan) | Configurable via |
|---|---|---|
| Memory | 512 MB | `PHISHGUARD_DOCKER_MEM` env var |
| CPU | 1.0 core | `PHISHGUARD_DOCKER_CPUS` env var |
| Processes | 64 | `PHISHGUARD_DOCKER_PIDS` env var |
| Scan timeout | 25 s (default) | `timeout` field in request, 5–60 s |
| Output (DOM+PNG) | 3 MB total | Hard-coded cap in `dynamic_scan.py` |
| Container lifetime | Ephemeral (`--rm`) | Not configurable |

---

## 🔒 Security Limitations of Dynamic Scanning

> **This section documents what IS and is NOT protected. Read it before using dynamic scanning in any production or semi-public deployment.**

### Implemented controls ✅

| Control | Where |
|---|---|
| Private IP / loopback blocking (RFC 1918, 127/8, 169.254/16, cloud metadata) | `worker.py` (Playwright route intercept) AND `entrypoint.sh` (iptables) |
| Blocked URL schemes (file://, ftp://, etc.) | `worker.py` pre-flight check |
| Fresh browser context per scan (no reused cookies/profile) | `worker.py` (`browser.new_context()`) |
| No form submission or page interaction | `worker.py` (read-only: screenshot + DOM only) |
| Cookie values stripped before forwarding | `worker.py` (only name/domain/flags forwarded) |
| DOM and screenshot size capped | `worker.py` (500 KB / 1 MB) |
| Artifact filenames chosen by worker (UUID-based), not by page | `dynamic_scan.py` |
| Non-root container user (uid 1001, `pwuser`) | `Dockerfile` |
| Ephemeral container (`--rm`) | `dynamic_scan.py` docker command |
| No host filesystem mounts | `docker compose` / `dynamic_scan.py` |
| No application API keys forwarded to worker | `dynamic_scan.py` |
| Failed/timeout scans never reported as "safe" | `dynamic_scan.py` |
| Hard OS-level SIGALRM timeout | `worker.py` |

### Remaining limitations ⚠️

| Limitation | Details | Production remediation |
|---|---|---|
| **iptables requires NET_ADMIN** | Without `--cap-add NET_ADMIN`, the iptables egress rules in `entrypoint.sh` fail silently. Only the Playwright-layer filtering applies. On some hosted/managed container platforms, NET_ADMIN is not available. | Use a dedicated Docker network with explicit deny-all egress rules set at the host level, or run on infrastructure where NET_ADMIN is available. |
| **DNS rebinding not blocked** | A malicious page could serve a public IP at DNS resolution time, then rebind to a private IP after the Playwright connection is established. | Run the container in an isolated network namespace with a DNS resolver that validates response IPs, or use a forward proxy that enforces IP ranges. |
| **No JavaScript sandbox escape protection** | Playwright provides no protection against browser 0-day exploits. A hostile page could theoretically exploit a Chromium vulnerability to escape the browser. | Use a hardware VM (e.g., Firecracker microVM) for full kernel isolation. Never run dynamic scans as root or with elevated host privileges. |
| **No per-domain rate limiting** | The API does not limit how often the same URL or domain can be dynamically scanned. | Add a Redis-backed rate limiter keyed on target registered domain. |
| **Rendered DOM may differ from training data** | `content_features` on rendered HTML uses the same extractor trained on statically fetched PhiUSIIL data. The 99.66% accuracy figure does NOT apply. | Retrain `model_full` on a dataset of Playwright-rendered pages. The current rendered-DOM features are informational only. |
| **No egress proxy** | The worker can reach any public IP not blocked by iptables. | Route all container egress through a forward proxy (e.g., Squid) that enforces an allowlist or additional filters. |

---

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
