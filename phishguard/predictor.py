"""End-to-end assessment of a URL.

Pipeline
  1. host features (always)                -> model_host
  2. fetch page + content features (live)  -> model_full   (falls back to model_host if the page is unreachable)
  3. OSINT enrichment (live): RDAP age, DNS, TLS, threat-intel feeds
  4. risk combination: ML probability + documented rule adjustments + threat-intel override
  5. explanation: which features pushed the score (occlusion against a "typical legitimate" baseline)

The final verdict is decision support, not ground truth.
"""
from __future__ import annotations

import os
import warnings
from concurrent.futures import ThreadPoolExecutor

import joblib
import numpy as np
import pandas as pd

from . import content, intel
from .brands import BRANDS
from .urlfeatures import HOST_FEATURES, host_features, is_free_hosting, normalize_url, parse, path_signals, registered_domain

warnings.filterwarnings("ignore")
MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

# Verdict thresholds on the final risk score (0..1)
T_PHISH, T_SUSPICIOUS = 0.70, 0.40

FEATURE_HELP = {
    "n_subdomains": "number of subdomain levels", "subdomain_len": "length of the subdomain part", "host_len": "hostname length",
    "n_dots_host": "dots in hostname", "sld_len": "length of the main domain label", "tld_len": "TLD length",
    "n_hyphen_host": "hyphens in hostname", "n_digit_host": "digits in hostname", "sld_entropy": "randomness of the domain name",
    "host_entropy": "randomness of the hostname", "sub_entropy": "randomness of the subdomain", "host_is_ip": "host is a raw IP",
    "tld_abused": "TLD frequently abused", "brand_in_subdomain": "brand name in subdomain",
    "brand_in_sld_combo": "brand name combined with extra words", "typosquat": "look-alike spelling of a brand",
    "homoglyph": "digit/letter look-alike of a brand", "any_brand_abuse": "brand impersonation pattern",
    "n_suspicious_kw_host": "suspicious keywords in hostname", "has_punycode": "punycode (IDN) hostname",
    "HasTitle": "page has a title", "HasFavicon": "page has a favicon", "HasDescription": "page has meta description",
    "LineOfCode": "page length (lines of HTML)", "NoOfJS": "number of scripts", "NoOfExternalRef": "links to other sites",
    "NoOfSelfRef": "links within the same site", "NoOfImage": "number of images", "NoOfCSS": "number of stylesheets",
    "HasPasswordField": "password field present", "HasExternalFormSubmit": "form posts to another domain",
    "HasSocialNet": "links to social networks", "HasCopyrightInfo": "copyright notice present",
    "HasSubmitButton": "submit button present", "HasHiddenFields": "hidden form fields", "IsResponsive": "mobile viewport tag",
    "NoOfiFrame": "number of iframes", "NoOfPopup": "popup/alert calls", "NoOfEmptyRef": "empty / dummy links",
    "LargestLineLength": "longest HTML line", "Bank": "bank terms on page", "Pay": "payment terms on page",
    "Crypto": "crypto terms on page", "NoOfURLRedirect": "redirects followed",
}


class PhishGuard:
    def __init__(self, model_dir: str = MODEL_DIR):
        self.m_host = joblib.load(os.path.join(model_dir, "model_host.joblib"))
        self.m_full = joblib.load(os.path.join(model_dir, "model_full.joblib"))
        self._owned = {d for ds in BRANDS.values() for d in ds}

    # -------------------------------------------------------------- ML
    @staticmethod
    def _proba(bundle, feats: dict) -> float:
        X = pd.DataFrame([feats])[bundle["features"]]
        return float(bundle["model"].predict_proba(X)[0, 1])

    @staticmethod
    def _explain(bundle, feats: dict, top: int = 6) -> list[dict]:
        """Occlusion: swap each feature for the typical-legitimate value and see how far the score falls."""
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
            out.append({"feature": c, "meaning": FEATURE_HELP.get(c, c), "value": round(float(feats[c]), 3),
                        "typical_legit": round(float(base[c]), 3), "effect": round(float(deltas[i]), 3),
                        "direction": "raises phishing risk" if deltas[i] > 0 else "lowers phishing risk"})
        return out

    # -------------------------------------------------------------- main entry
    def assess(self, url: str, live: bool = True, fetch_page: bool = True) -> dict:
        url = normalize_url(url)
        sp, host = parse(url)
        if not host:
            raise ValueError("Could not find a hostname in the URL")
        _, sld, suffix = registered_domain(host[4:] if host.startswith("www.") else host)
        reg = f"{sld}.{suffix}" if suffix else sld

        hf = host_features(url)
        result: dict = {"url": url, "host": host, "registered_domain": reg, "live_checks": live}

        # ---- live: page + OSINT in parallel
        page, page_err, osint = None, None, None
        if live:
            with ThreadPoolExecutor(max_workers=2) as ex:
                f_osint = ex.submit(intel.enrich, url)
                f_page = ex.submit(content.safe_fetch, url) if fetch_page else None
                osint = f_osint.result()
                if f_page:
                    try:
                        page = f_page.result()
                    except content.UnsafeTarget as e:
                        page_err = f"blocked by safety guard: {e}"
                    except Exception as e:  # noqa: BLE001
                        page_err = f"page not reachable: {str(e)[:100]}"

        # ---- ML
        feats_all = dict(hf)
        is_html = bool(page) and ("html" in page["content_type"].lower() or page["html"].lstrip()[:1] == "<")
        usable, unusable_reason = (content.page_usable(page) if is_html else (False, "no HTML content returned"))
        page_blocked = bool(page) and not (is_html and usable)    # fetched, but not the site's real content
        if is_html and usable:
            cf = content.extract_content_features(page["html"], page["final_url"], page["n_redirects"])
            feats_all.update(cf)
            bundle, model_used = self.m_full, "full (host + page content)"
            result["page"] = {"final_url": page["final_url"], "status": page["status"], "redirects": page["n_redirects"],
                              "content_features": {k: cf[k] for k in content.CONTENT_FEATURES}}
        else:
            bundle, model_used = self.m_host, "host-only (page not analysed)"
            cf = None
            if fetch_page and live:
                result["page"] = {"error": page_err or unusable_reason}
                if page and not usable:
                    result["page"]["status"] = page["status"]
        ml_prob = self._proba(bundle, feats_all)
        result.update({"model_used": model_used, "model_name": bundle["name"], "ml_probability": round(ml_prob, 4),
                       "host_features": hf, "explanation": self._explain(bundle, feats_all)})

        # ---- rule signals (positive = riskier, negative = safer)
        signals = path_signals(url)
        if cf:
            signals += content.content_signals(cf, sp.scheme)
        if page_blocked:
            signals.append({"name": "page_not_viewable", "weight": 0.10,
                            "detail": "Page could not be inspected (" + (unusable_reason or "blocked") + "). Showing scanners a "
                                      "block/error page is also a known phishing cloaking tactic, so this cannot count as evidence of safety"})
        allow_listed = reg in self._owned and not is_free_hosting(host)
        if allow_listed:
            signals.append({"name": "known_brand_domain", "weight": 0.0,
                            "detail": f"{reg} is an official domain of a well-known brand (allow-list): score capped at 0.25 "
                                      "unless a threat-intel source lists it"})
        if osint:
            age = osint["whois"]
            if age.get("status") == "ok":
                d = age["age_days"]
                if d < 30:
                    signals.append({"name": "domain_very_new", "weight": 0.20, "detail": f"domain registered only {d} days ago"})
                elif d < 180:
                    signals.append({"name": "domain_new", "weight": 0.08, "detail": f"domain registered {d} days ago"})
                elif d > 1825:
                    signals.append({"name": "domain_established", "weight": -0.08, "detail": f"domain is {d // 365} years old"})
            elif age.get("status") == "not_found":
                signals.append({"name": "no_whois_record", "weight": 0.05, "detail": age.get("detail", "")})
            dns = osint["dns"]
            if dns.get("status") == "ok" and not dns["resolves"]:
                signals.append({"name": "dns_unresolved", "weight": 0.0, "detail": "domain does not resolve (site may already be taken down)"})
            tls = osint["tls"]
            if tls.get("status") == "ok":
                if not tls.get("valid"):
                    signals.append({"name": "tls_invalid", "weight": 0.12, "detail": f"TLS certificate failed verification: {tls.get('error') or 'unknown'}"})
                elif tls.get("age_days", 999) < 7:
                    signals.append({"name": "tls_brand_new", "weight": 0.04, "detail": f"certificate issued {tls['age_days']} days ago"})
            listed = [t for t in osint["threat_intel"] if t["status"] == "listed"]
        else:
            listed = []

        adj = sum(s["weight"] for s in signals)
        final = float(np.clip(ml_prob + adj, 0.0, 1.0))
        free_host_cap = (is_free_hosting(host) and bundle is self.m_host and not hf["any_brand_abuse"] and not listed)
        if free_host_cap:       # host features alone cannot tell a harmless blog from a phishing kit on the same platform
            final = min(final, T_PHISH - 0.05)
        established = bool(osint) and osint["whois"].get("status") == "ok" and osint["whois"].get("age_days", 0) > 365
        blocked_floor = page_blocked and not allow_listed and not listed and not established
        if blocked_floor:       # unseen page + young/unknown domain: never clear it automatically
            final = max(final, T_SUSPICIOUS)
        if allow_listed:
            final = min(final, 0.25)
        if listed:
            final = max(final, 0.99)
        verdict = "PHISHING" if final >= T_PHISH else "SUSPICIOUS" if final >= T_SUSPICIOUS else "LEGITIMATE"
        if listed:
            reason = "Listed by threat-intelligence source(s): " + ", ".join(t["source"] for t in listed)
        elif blocked_floor and verdict == "SUSPICIOUS":
            reason = ("The page could not be inspected (blocked or unreadable) and the domain is not established, so it cannot be "
                      "cleared automatically. Verify manually, ideally in a sandbox.")
        elif verdict == "LEGITIMATE" and page_blocked:
            reason = ("The page could not be inspected, so this verdict rests only on the domain, its age and the threat feeds. "
                      "It is not a guarantee of safety.")
        elif verdict == "LEGITIMATE":
            reason = "No strong phishing indicators found. This is not a guarantee of safety."
        elif free_host_cap and verdict == "SUSPICIOUS":
            reason = ("Site is on a free hosting platform; host features alone cannot confirm phishing. "
                      "Enable live checks so the page content can be analysed.")
        else:
            reason = "Model score plus rule-based signals exceed the risk threshold."
        result.update({"signals": signals, "rule_adjustment": round(adj, 3), "final_score": round(final, 4),
                       "verdict": verdict, "reason": reason, "osint": osint,
                       "thresholds": {"phishing": T_PHISH, "suspicious": T_SUSPICIOUS}})
        return result
