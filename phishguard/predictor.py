"""End-to-end assessment of a URL.

Pipeline:
  1. URL normalisation & host/domain feature extraction (30 features) -> model_host
  2. Page content retrieval (live):
     - Fast static fetch (requests) with SSRF & TLS verification.
     - Evaluates page usability (detects bot-protection challenge pages & HTTP errors).
     - If JavaScript shell detected: Playwright headless Chromium renders dynamic DOM
       inside an isolated, SSRF-route-filtered environment.
     - If usable content obtained: 22 page observations extracted -> explicit content security rules
     - If content unavailable: model_host fallback with clear, documented explanation
       (NEVER penalises uninspected pages as malicious).
  3. OSINT enrichment (live): RDAP / WHOIS domain age, DNS resolution, TLS certificates,
     multi-source threat intelligence feeds.
  4. Probabilistic evidence combination:
     - Trained host-model estimate (not claimed to be a calibrated live-site probability).
     - Bayesian log-odds likelihood updates from empirical OSINT, path, and content signals.
     - Active threat-feed listing triggers an immediate PHISHING verdict.
  5. Explainable verdict:
     - Feature contributions against typical legitimate baseline (occlusion).
     - Clear human-readable reason distinguishing evidence from missing data.
"""
from __future__ import annotations

import math
import os
import warnings
from concurrent.futures import ThreadPoolExecutor

import joblib
import numpy as np
import pandas as pd

from . import content, intel
from .urlfeatures import HOST_FEATURES, host_features, is_free_hosting, normalize_url, parse, path_signals, registered_domain

warnings.filterwarnings("ignore")
MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

# Verdict thresholds on the final evidence-adjusted risk score (0..1)
T_PHISH, T_SUSPICIOUS = 0.70, 0.40

FEATURE_HELP = {
    "n_subdomains": "number of subdomain levels", "subdomain_len": "length of the subdomain part", "host_len": "hostname length",
    "n_dots_host": "dots in hostname", "sld_len": "length of the main domain label", "tld_len": "TLD length",
    "n_hyphen_host": "hyphens in hostname", "n_digit_host": "digits in hostname", "sld_entropy": "randomness of the domain name",
    "host_entropy": "randomness of the hostname", "sub_entropy": "randomness of the subdomain", "host_is_ip": "host is a raw IP",
    "tld_abused": "TLD frequently abused in phishing", "brand_in_subdomain": "brand name in subdomain",
    "brand_in_sld_combo": "brand name combined with extra words", "typosquat": "look-alike spelling of a known brand",
    "homoglyph": "digit/letter look-alike of a known brand", "any_brand_abuse": "brand impersonation pattern",
    "n_suspicious_kw_host": "suspicious keywords in hostname", "has_punycode": "punycode (IDN) hostname",
    "HasTitle": "page has a title", "HasFavicon": "page has a favicon", "HasDescription": "page has meta description",
    "IsResponsive": "mobile responsive viewport tag", "HasPasswordField": "password field present on page",
    "HasExternalFormSubmit": "form posts data to an untrusted external domain", "HasSocialNet": "links to social networks",
    "HasCopyrightInfo": "copyright notice in page", "HasSubmitButton": "form submit button present",
    "HasHiddenFields": "hidden form input fields", "NoOfiFrame": "number of embedded iframes",
    "NoOfPopup": "window popup/alert calls", "NoOfEmptyRef": "empty or dummy (#) links",
    "NoOfImage": "number of images", "NoOfCSS": "number of stylesheets", "NoOfJS": "number of scripts",
    "NoOfSelfRef": "internal links within same site", "NoOfExternalRef": "links to external domains",
    "Bank": "banking terminology on page", "Pay": "payment terminology on page", "Crypto": "cryptocurrency terminology on page",
    "NoOfURLRedirect": "number of redirect hops followed",
}


class PhishGuard:
    def __init__(self, model_dir: str = MODEL_DIR):
        self.m_host = joblib.load(os.path.join(model_dir, "model_host.joblib"))
        # The legacy full model learned layout/collection shortcuts (e.g. zero
        # navigation links => phishing). Never use it for deployed verdicts.
        # Content is still inspected and contributes explicit security evidence.

    # -------------------------------------------------------------- ML
    @staticmethod
    def _proba(bundle, feats: dict) -> float:
        cols = bundle["features"]
        X = pd.DataFrame([feats])[cols]
        return float(bundle["model"].predict_proba(X)[0, 1])

    @staticmethod
    def _explain(bundle, feats: dict, top: int = 6) -> list[dict]:
        """Occlusion: swap each feature for the typical-legitimate baseline and measure change in risk."""
        cols = bundle["features"]
        base = bundle["baseline"]
        row = pd.DataFrame([{c: feats[c] for c in cols}])
        variants = [row] + [row.assign(**{c: base[c]}) for c in cols]
        P = bundle["model"].predict_proba(pd.concat(variants, ignore_index=True))[:, 1]
        deltas = P[0] - P[1:]
        order = np.argsort(-np.abs(deltas))[:top]
        out = []
        for i in order:
            if abs(deltas[i]) < 0.005:
                continue
            c = cols[i]
            out.append({
                "feature": c,
                "meaning": FEATURE_HELP.get(c, c),
                "value": round(float(feats[c]), 3),
                "typical_legit": round(float(base[c]), 3),
                "effect": round(float(deltas[i]), 3),
                "counterfactual_probability": round(float(P[i + 1]), 6),
                "effect_pp": round(float(deltas[i]) * 100, 4),
                "direction": "raises phishing risk" if deltas[i] > 0 else "lowers phishing risk"
            })
        return out

    # -------------------------------------------------------------- Main Assessment
    def assess(self, url: str, live: bool = True, fetch_page: bool = True) -> dict:
        url = normalize_url(url)
        sp, host = parse(url)
        if not host:
            raise ValueError("Could not find a hostname in the URL")
        _, sld, suffix = registered_domain(host[4:] if host.startswith("www.") else host)
        reg = f"{sld}.{suffix}" if suffix else sld

        hf = host_features(url)
        result: dict = {"url": url, "host": host, "registered_domain": reg, "live_checks": live}

        # ---- Live: Page content retrieval & OSINT in parallel
        page, page_err, osint = None, None, None
        if live:
            with ThreadPoolExecutor(max_workers=2) as ex:
                f_osint = ex.submit(intel.enrich, url)
                f_page = ex.submit(content.fetch_with_fallback, url) if fetch_page else None
                osint = f_osint.result()
                if f_page:
                    try:
                        page = f_page.result()
                    except content.UnsafeTarget as e:
                        page_err = f"blocked by SSRF guard: {e}"
                    except Exception as e:  # noqa: BLE001
                        page_err = f"page unreachable: {str(e)[:100]}"

        # ---- Content Inspection & Usability Assessment
        feats_all = dict(hf)
        is_html = bool(page) and ("html" in page.get("content_type", "").lower() or page.get("html", "").lstrip()[:1] == "<")
        usable, unusable_reason = (content.page_usable(page) if is_html else (False, page_err or "no HTML content returned"))
        inspection_method = page.get("inspection_method", "static_http") if page else "none"

        # If static HTML was a JavaScript shell, attempt Playwright DOM rendering fallback
        static_html = page.get("html", "") if page else ""
        static_preview, rendered_preview = None, None
        if page and not usable and "headless rendering needed" in unusable_reason:
            try:
                pw_res = content.render_with_playwright(page.get("final_url", url), timeout=5.0, static_html=static_html)
                if pw_res.get("ok"):
                    static_preview = pw_res.get("static_preview")
                    rendered_preview = pw_res.get("rendered_preview")
                    page["html"] = pw_res["html"]
                    page["final_url"] = pw_res.get("final_url", url)
                    page["status"] = pw_res.get("status", 200)
                    inspection_method = "playwright_rendered"
                    is_html = True
                    usable, unusable_reason = content.page_usable(page)
                    if not usable:
                        unusable_reason = "Rendered DOM unavailable for analysis: " + unusable_reason
                else:
                    unusable_reason = pw_res.get("error", unusable_reason)
            except Exception as e:
                unusable_reason = f"Rendering fallback failed: {str(e)[:80]}"

        # Use the observed destination for content context, never invent www/HTTPS aliases.
        effective_url = page.get("final_url", url) if page else url
        effective_sp, effective_host = parse(effective_url)
        result["effective_url"] = effective_url
        result["url_context"] = {
            "submitted_url": url, "effective_url": effective_url,
            "redirected": bool(page and not page.get("fallback_used") and page.get("n_redirects", 0)),
            "fallback_used": bool(page and page.get("fallback_used")),
            "fetch_url": page.get("fetch_url", url) if page else url,
            "fetch_attempts": page.get("fetch_attempts", []) if page else [],
            "submitted_transport": sp.scheme,
            "transport": effective_sp.scheme,
            "note": "The host model ignores a leading www. If the submitted address cannot connect, HTTPS and apex/www alternatives may be inspected; recovery attempts are shown separately from redirects."
        }
        # Refresh destination infrastructure after an observed origin change, retaining
        # threat hits on the submitted URL as well as on the destination.
        if live and (effective_sp.scheme, effective_sp.netloc) != (sp.scheme, sp.netloc):
            destination_osint = intel.enrich(effective_url)
            destination_osint = dict(destination_osint)
            destination_osint["threat_intel"] = (osint or {}).get("threat_intel", []) + destination_osint.get("threat_intel", [])
            # A malicious source redirecting to an established site must not inherit
            # that site's registration reputation or erase its own host features.
            if registered_domain(effective_host)[1:] != registered_domain(host)[1:]:
                destination_osint["whois"] = (osint or {}).get("whois", {})
                destination_osint["dns"] = (osint or {}).get("dns", {})
            osint = destination_osint
        cf = None
        title = ""
        if is_html and usable:
            cf = content.extract_content_features(page["html"], page["final_url"], page.get("n_substantive_redirects", page.get("n_redirects", 0)))
            feats_all.update(cf)
            bundle, model_used = self.m_host, "host ML + inspected page security evidence"
            inspection_status = "inspected"
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(page["html"], "html.parser")
            title = soup.title.get_text().strip() if soup.title else ""
            result["page"] = {
                "status": page.get("status", 200),
                "inspection_status": inspection_status,
                "inspection_method": inspection_method,
                "final_url": page.get("final_url", url),
                "redirects": page.get("n_redirects", 0),
                "redirect_chain": page.get("redirect_chain", []),
                "model_redirects": page.get("n_substantive_redirects", page.get("n_redirects", 0)),
                "title": title,
                "content_features": {k: cf[k] for k in content.CONTENT_FEATURES}
            }
        else:
            bundle, model_used = self.m_host, "host-only (page not analysed)"
            inspection_status = "unavailable"
            if fetch_page and live:
                result["page"] = {
                    "status": page.get("status", 0) if page else 0,
                    "inspection_status": inspection_status,
                    "inspection_method": inspection_method,
                    "reason": page_err or unusable_reason or "Page content unavailable"
                }

        if page and "page" in result:
            if static_preview is None and live:
                static_preview = content.render_static_preview(static_html, page.get("final_url", url))
            result["page"]["previews"] = {
                "static_html": static_preview, "rendered_dom": rendered_preview,
                "format": "jpeg_base64", "interactive": False,
                "note": "Visual snapshots: static HTML with JavaScript off; DOM after Playwright execution. Inputs and links are inactive."
            }
            result["page"]["fetch_url"] = page.get("fetch_url", url)
            result["page"]["fallback_used"] = bool(page.get("fallback_used"))
            dom = page.get("html", "")
            result["page"].update({
                "final_url": effective_url,
                "dom": dom[:100_000],
                "dom_truncated": len(dom) > 100_000,
                "dom_characters": len(dom),
                "dom_kind": "rendered DOM" if inspection_method == "playwright_rendered" else "static HTML",
            })
        from .feature_display import describe_features
        result["feature_assessments"] = {
            "host": describe_features(hf),
            "content": describe_features(cf or {}),
        }
        ml_prob = self._proba(bundle, feats_all)
        result.update({
            "model_used": model_used,
            "model_name": bundle["name"],
            "ml_probability": round(ml_prob, 4),
            "host_features": hf,
            "explanation": self._explain(bundle, feats_all)
        })

        # ---- Rule Signals & Log-Odds Calibration
        # Signals contribute log-odds adjustments: Delta L = ln(odds_after / odds_before)
        signals: list[dict] = []
        log_odds_deltas: list[float] = []

        def add_signal(name: str, weight: float, delta_lo: float, detail: str):
            signals.append({"name": name, "weight": weight, "delta_lo": delta_lo, "detail": detail})
            log_odds_deltas.append(delta_lo)

        # 1. Path / URI Heuristics
        for s in path_signals(url):
            w = s["weight"]
            # Map linear weight to balanced log-odds delta
            d_lo = round(w * 4.0, 2)
            add_signal(s["name"], w, d_lo, s["detail"])

        if effective_url != url:
            existing = {s["name"] for s in signals}
            for s in path_signals(effective_url):
                if s["name"] not in existing:
                    add_signal(s["name"], s["weight"], round(s["weight"] * 4, 2), s["detail"])

        # 2. Content Heuristics (only when content was inspected)
        if cf:
            for s in content.content_signals(cf, effective_sp.scheme, title, effective_host):
                w = s["weight"]
                d_lo = round(w * 5.0, 2)
                add_signal(s["name"], w, d_lo, s["detail"])

        # 3. OSINT Infrastructure & Domain Context
        listed = []
        is_established_domain = False
        domain_age_days = None

        if osint:
            # WHOIS / RDAP Registration Age
            age_info = osint.get("whois", {})
            if age_info.get("status") == "ok":
                d = age_info.get("age_days", 0)
                domain_age_days = d
                if d < 14:
                    add_signal("domain_very_new", 0.18, +1.2, f"Domain registered only {d} days ago (ephemeral infrastructure)")
                elif d < 60:
                    add_signal("domain_new", 0.08, +0.5, f"Domain registered {d} days ago")
                elif d > 3650:
                    is_established_domain = True
                    add_signal("domain_highly_established", -0.15, -1.2, f"Domain is highly established ({d // 365} years old)")
                elif d > 1825:
                    is_established_domain = True
                    add_signal("domain_established", -0.10, -0.8, f"Domain is established ({d // 365} years old)")
                elif d > 730:
                    is_established_domain = True
                    add_signal("domain_established", -0.05, -0.4, f"Domain is {d // 365} years old")
            elif age_info.get("status") == "not_found":
                add_signal("no_whois_record", 0.0, 0.0, "RDAP returned no record; registration age is unknown, not evidence of phishing")

            # DNS Resolution
            dns = osint.get("dns", {})
            if dns.get("status") == "ok" and not dns.get("resolves"):
                add_signal("dns_unresolved", 0.0, 0.0, "Domain does not currently resolve (may be inactive or taken down)")

            # TLS Certificate Validity vs Age
            tls = osint.get("tls", {})
            if tls.get("status") == "ok":
                if not tls.get("valid"):
                    add_signal("tls_invalid", 0.15, +0.8, f"TLS certificate failed verification: {tls.get('error') or 'untrusted/expired'}")
                else:
                    cert_age = tls.get("age_days", 999)
                    # NOTE: Legitimate domains routinely renew 90-day certificates (Let's Encrypt / Google Trust).
                    # ONLY penalise certificate age if the DOMAIN itself is brand new (< 90 days)!
                    if cert_age < 7 and domain_age_days is not None and domain_age_days < 90:
                        add_signal("tls_new_cert_on_new_domain", 0.05, +0.3, f"Certificate issued {cert_age} days ago on a young domain")

            # Active Threat Intelligence Feeds
            listed = [t for t in osint.get("threat_intel", []) if t.get("status") == "listed"]

        # Content context verification
        if cf:
            has_pw = bool(cf.get("HasPasswordField", 0))
            ext_form = bool(cf.get("HasExternalFormSubmit", 0))
            if has_pw and not ext_form and effective_sp.scheme == "https" and is_established_domain:
                if not any(s["name"] == "title_brand_mismatch" for s in signals):
                    add_signal("legitimate_internal_auth", -0.08, -0.6,
                               "Authenticated login form submits securely within established domain origin")

        # ---- Risk Aggregation Architecture
        # 1. Threat Feed Hit: Hard override (confirmed malicious blacklist hit)
        if listed:
            final = 0.99
            verdict = "PHISHING"
            reason = "Confirmed active phishing listing by threat-intelligence source(s): " + ", ".join(t["source"] for t in listed)
        else:
            # 2. Calibrated Evidence Fusion via Log-Odds
            p_prior = float(np.clip(ml_prob, 0.005, 0.995))

            l_prior = math.log(p_prior / (1.0 - p_prior))
            delta_l = sum(log_odds_deltas)
            l_final = l_prior + delta_l
            final = float(1.0 / (1.0 + math.exp(-l_final)))

            # Free hosting cap when page content was not inspected and host has no brand abuse
            free_host_cap = is_free_hosting(host) and cf is None and not hf.get("any_brand_abuse", 0)
            if free_host_cap:
                final = min(final, T_PHISH - 0.05)

            # Assign Verdict
            if final >= T_PHISH:
                verdict = "PHISHING"
                reason = "Combined model score and security risk indicators exceed the phishing threshold."
            elif final >= T_SUSPICIOUS:
                verdict = "SUSPICIOUS"
                if inspection_status == "unavailable" and not is_established_domain:
                    reason = ("Page content could not be inspected and domain is not established. "
                              "Exercise caution before entering sensitive information.")
                elif free_host_cap:
                    reason = ("Hosted on a free/developer platform without verified content. "
                              "Host signals alone cannot confirm legitimacy.")
                else:
                    reason = "Borderline risk signals detected. Verification recommended."
            else:
                verdict = "LEGITIMATE"
                if inspection_status == "unavailable" and is_established_domain:
                    reason = ("Page content could not be inspected (server protection or error), but domain reputation, "
                              "established age, and threat intelligence indicate legitimate infrastructure.")
                else:
                    reason = "No strong phishing indicators found in the inspected evidence. A lower-risk result is not a guarantee of safety."

        # Make the displayed arithmetic additive in percentage points. Each step
        # applies a rule in log-odds, then reports its actual probability change.
        p_running = float(np.clip(ml_prob, 0.005, 0.995))
        steps = [{"label": "Model estimate", "score": ml_prob, "change_pp": 0.0}]
        if p_running != ml_prob:
            steps.append({"label": "Numerical clipping", "score": p_running, "change_pp": (p_running - ml_prob) * 100})
        for signal in signals:
            odds = math.log(p_running / (1 - p_running)) + signal["delta_lo"]
            after = 1 / (1 + math.exp(-odds))
            signal["change_pp"] = round((after - p_running) * 100, 6)
            signal["odds_multiplier"] = round(math.exp(signal["delta_lo"]), 4)
            steps.append({"label": signal["detail"], "score": after, "change_pp": (after - p_running) * 100})
            p_running = after
        if abs(final - p_running) > 1e-10:
            steps.append({"label": "Threat-feed override" if listed else "Uninspected free-hosting limit", "score": final, "change_pp": (final - p_running) * 100})
        steps.append({"label": "Final risk score", "score": final, "change_pp": 0.0})
        adj = sum(s["weight"] for s in signals)
        result.update({
            "signals": signals,
            "rule_adjustment": round(adj, 3),  # legacy heuristic weights, not probability points
            "score_breakdown": {"method": "log_odds_rules", "model_score": ml_prob,
                                "final_score": final, "net_change_pp": (final - ml_prob) * 100,
                                "steps": steps,
                                "note": "Feature what-if effects overlap and must not be added. Rule steps below are sequential and additive in percentage points."},
            "model_policy": "Trained host model with explicit content security rules. Legacy layout-based full model retired.",
            "final_score": round(final, 4),
            "verdict": verdict,
            "reason": reason,
            "osint": osint,
            "thresholds": {"phishing": T_PHISH, "suspicious": T_SUSPICIOUS}
        })
        # Navigation recovery is offered only after inspection and verified TLS,
        # within the same registered domain, and never for a warned/listed URL.
        if (page and page.get("fallback_used") and verdict == "LEGITIMATE"
                and inspection_status == "inspected" and effective_sp.scheme == "https"
                and osint and osint.get("tls", {}).get("valid")
                and registered_domain(effective_host)[1:] == registered_domain(host)[1:]):
            result["navigation_url"] = effective_url
        return result
