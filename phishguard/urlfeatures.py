"""URL parsing + feature extraction.

Two kinds of output, deliberately kept apart:

1. ``host_features(url)``  - numeric features about the *origin* (host / domain) of the URL.
   These are the lexical + host-based + domain-based features fed to the ML model.

2. ``path_signals(url)``   - rule-based signals about the path / query / scheme.
   These are NOT fed to the model. In the PhiUSIIL training data every legitimate URL is a bare
   ``https://www.<domain>`` with no path, so any path-based feature would only teach the model
   "has a path => phishing" (a dataset artifact that would flag e.g. github.com/user/repo).
   The signals are therefore applied as transparent, weighted rules in the final risk score.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit, unquote

from .brands import (ABUSED_TLDS, AMBIGUOUS_BRANDS, BRANDS, FREE_HOSTING_DOMAINS, MULTI_PART_SUFFIXES,
                     SUSPICIOUS_KEYWORDS, URL_SHORTENERS)

_VOWELS = set("aeiou")
_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-"
_HOMOGLYPHS = [("vv", "w"), ("rn", "m"), ("0", "o"), ("1", "l"), ("3", "e"), ("4", "a"), ("5", "s")]
_EXEC_EXT = (".exe", ".apk", ".scr", ".msi", ".bat", ".cmd", ".jar", ".iso", ".dmg", ".js", ".vbs", ".ps1", ".zip", ".rar")


# --------------------------------------------------------------------------- parsing helpers
def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url
    return url


def parse(url: str):
    """Return (SplitResult, host) where host is lower-cased, without port / userinfo."""
    sp = urlsplit(normalize_url(url))
    host = (sp.hostname or "").lower().rstrip(".")
    return sp, host


def registered_domain(host: str) -> tuple[str, str, str]:
    """Split host into (subdomain, sld, suffix) using an embedded mini public-suffix list."""
    labels = [l for l in host.split(".") if l]
    if len(labels) < 2:
        return "", host, ""
    last2 = ".".join(labels[-2:])
    if last2 in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[:-3]), labels[-3], last2
    return ".".join(labels[:-2]), labels[-2], labels[-1]


def is_ip_host(host: str) -> bool:
    if not host:
        return False
    host = host.lower()
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    # decimal / hex / octal obfuscated IPv4:  http://3232235777  http://0xC0A80001
    if re.fullmatch(r"\d{8,10}", host) or re.fullmatch(r"0x[0-9a-f]{6,8}", host):
        return True
    if re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){3}", host):
        return True
    return False


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _max_consonant_run(s: str) -> int:
    best = run = 0
    for ch in s:
        if ch.isalpha() and ch not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def _edit1_variants(word: str) -> set[str]:
    splits = [(word[:i], word[i:]) for i in range(len(word) + 1)]
    out = set()
    for a, b in splits:
        if b:
            out.add(a + b[1:])                                        # deletion
            for c in _ALPHABET:
                out.add(a + c + b[1:])                                # substitution
        if len(b) > 1:
            out.add(a + b[1] + b[0] + b[2:])                          # transposition
        for c in _ALPHABET:
            out.add(a + c + b)                                        # insertion
    out.discard(word)
    return out


_TYPO_TABLE: dict[str, str] = {}
for _b in BRANDS:
    if len(_b) >= 5:
        for _v in _edit1_variants(_b):
            _TYPO_TABLE.setdefault(_v, _b)


def _demorph(s: str) -> str:
    for a, b in _HOMOGLYPHS:
        s = s.replace(a, b)
    return s


def _owned(reg_domain: str, brand: str) -> bool:
    return reg_domain in BRANDS[brand]


def brand_analysis(host: str) -> dict:
    """Detect brand impersonation in the host. Returns flags + the brand that triggered them."""
    sub, sld, suffix = registered_domain(host)
    reg = f"{sld}.{suffix}" if suffix else sld
    sub_labels = [l for l in re.split(r"[.\-_]", sub) if l]
    sld_tokens = [t for t in re.split(r"[\-_]", sld) if t]
    res = {"brand_in_subdomain": 0, "brand_in_sld_combo": 0, "typosquat": 0, "homoglyph": 0, "brand": ""}
    for brand in BRANDS:
        if _owned(reg, brand):
            continue
        amb = brand in AMBIGUOUS_BRANDS
        in_sub = brand in sub_labels or (not amb and brand in sub)
        if in_sub and not res["brand_in_subdomain"]:
            res["brand_in_subdomain"], res["brand"] = 1, res["brand"] or brand
        combo = (brand in sld_tokens and sld != brand) or (not amb and brand in sld and sld != brand)
        if combo and not res["brand_in_sld_combo"]:
            res["brand_in_sld_combo"], res["brand"] = 1, res["brand"] or brand
    if sld in _TYPO_TABLE and not _owned(reg, _TYPO_TABLE[sld]):
        res["typosquat"], res["brand"] = 1, res["brand"] or _TYPO_TABLE[sld]
    dm = _demorph(sld)
    if dm != sld and len(dm) >= 4:
        for brand in BRANDS:
            if dm == brand and not _owned(reg, brand):
                res["homoglyph"], res["brand"] = 1, res["brand"] or brand
    return res


# --------------------------------------------------------------------------- 1. learned host features
HOST_FEATURES = [
    "host_len", "n_dots_host", "n_subdomains", "subdomain_len", "sld_len", "tld_len", "longest_label",
    "n_hyphen_host", "n_digit_host", "digit_ratio_host", "n_hyphen_sld", "n_digit_sld", "sld_digit_ratio",
    "host_entropy", "sld_entropy", "sub_entropy", "sld_max_consonant_run", "sld_vowel_ratio",
    "host_is_ip", "has_userinfo", "nonstd_port", "has_punycode", "is_shortener", "tld_abused",
    "n_suspicious_kw_host", "brand_in_subdomain", "brand_in_sld_combo", "typosquat",
    "homoglyph", "any_brand_abuse",
]


def host_features(url: str) -> dict[str, float]:
    sp, host = parse(url)
    h = host[4:] if host.startswith("www.") else host        # "www." is stripped: it is a dataset artifact
    sub, sld, suffix = registered_domain(h)
    reg = f"{sld}.{suffix}" if suffix else sld
    tld = suffix.split(".")[-1] if suffix else ""
    is_ip = is_ip_host(host)
    sub_labels = [l for l in sub.split(".") if l]
    labels = [l for l in h.split(".") if l]
    n_digit_h = sum(c.isdigit() for c in h)
    n_digit_sld = sum(c.isdigit() for c in sld)
    letters = [c for c in sld if c.isalpha()]
    ba = brand_analysis(h) if not is_ip else {"brand_in_subdomain": 0, "brand_in_sld_combo": 0, "typosquat": 0, "homoglyph": 0}
    port = sp.port if _safe_port(sp) else None
    f = {
        "host_len": len(h),
        "n_dots_host": h.count("."),
        "n_subdomains": 0 if is_ip else len(sub_labels),
        "subdomain_len": len(sub),
        "sld_len": len(sld),
        "tld_len": len(tld),
        "longest_label": max((len(l) for l in labels), default=0),
        "n_hyphen_host": h.count("-"),
        "n_digit_host": n_digit_h,
        "digit_ratio_host": n_digit_h / len(h) if h else 0.0,
        "n_hyphen_sld": sld.count("-"),
        "n_digit_sld": n_digit_sld,
        "sld_digit_ratio": n_digit_sld / len(sld) if sld else 0.0,
        "host_entropy": shannon_entropy(h),
        "sld_entropy": shannon_entropy(sld),
        "sub_entropy": shannon_entropy(sub.replace(".", "")),
        "sld_max_consonant_run": _max_consonant_run(sld),
        "sld_vowel_ratio": (sum(c in _VOWELS for c in letters) / len(letters)) if letters else 0.0,
        "host_is_ip": int(is_ip),
        "has_userinfo": int("@" in (sp.netloc or "")),
        "nonstd_port": int(port is not None and port not in (80, 443)),
        "has_punycode": int("xn--" in h),
        "is_shortener": int(reg in URL_SHORTENERS),
        "tld_abused": int(tld in ABUSED_TLDS),
        "n_suspicious_kw_host": sum(k in h for k in SUSPICIOUS_KEYWORDS),
        "brand_in_subdomain": ba["brand_in_subdomain"],
        "brand_in_sld_combo": ba["brand_in_sld_combo"],
        "typosquat": ba["typosquat"],
        "homoglyph": ba["homoglyph"],
    }
    f["any_brand_abuse"] = int(f["brand_in_subdomain"] or f["brand_in_sld_combo"] or f["typosquat"] or f["homoglyph"])
    return {k: float(f[k]) for k in HOST_FEATURES}


def is_free_hosting(host: str) -> bool:
    """Host sits on a free hosting / dev platform that phishing kits often abuse. Used as a *rule*, not a learned
    feature: in PhiUSIIL 25% of phishing but 0% of legitimate hosts are on such platforms, so a model would treat
    every WordPress / Firebase / GitHub-Pages site as phishing."""
    return any(host == d or host.endswith("." + d) for d in FREE_HOSTING_DOMAINS)


def _safe_port(sp) -> bool:
    try:
        sp.port
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- 2. rule-based path signals
def path_signals(url: str) -> list[dict]:
    """Rule-based signals about scheme / path / query. Returns [{name, weight, detail}]."""
    sp, host = parse(url)
    raw = normalize_url(url)
    path_q = unquote((sp.path or "") + ("?" + sp.query if sp.query else ""))
    low = path_q.lower()
    out: list[dict] = []

    def add(name, weight, detail):
        out.append({"name": name, "weight": weight, "detail": detail})

    if is_free_hosting(host):
        add("free_hosting", 0.12, "Hosted on a free/dev platform that phishing kits frequently abuse - judge by content and age")
    if sp.scheme == "http":
        add("no_tls", 0.0, "Plain HTTP: connection is not encrypted; this alone is not evidence of phishing")
    if "@" in (sp.netloc or ""):
        add("userinfo_in_url", 0.20, "'user@host' trick: text before '@' is ignored by the browser, real host is after it")
    if re.search(r"https?://", path_q, re.I) or "//" in (sp.path or "")[1:]:
        add("embedded_url", 0.10, "Another URL / double slash is embedded in the path or query (redirect chaining)")
    kw = sorted({k for k in SUSPICIOUS_KEYWORDS if k in low})
    if len(kw) >= 2:
        add("path_keywords", 0.10, "Sensitive keywords in path/query: " + ", ".join(kw[:5]))
    ba = brand_analysis(host[4:] if host.startswith("www.") else host)
    if not ba["brand"]:
        _, sld, suffix = registered_domain(host)
        reg = f"{sld}.{suffix}" if suffix else sld
        for brand in BRANDS:
            if not _owned(reg, brand) and brand not in AMBIGUOUS_BRANDS and len(brand) >= 5 and brand in low:
                add("brand_in_path", 0.12, f"Brand '{brand}' appears in the path but the domain is not theirs")
                break
    if low.split("?")[0].endswith(_EXEC_EXT):
        add("executable_download", 0.12, "Path points to an executable/archive download")
    if len(raw) > 150:
        add("very_long_url", 0.04, f"Very long URL ({len(raw)} characters)")
    if len(re.findall(r"%[0-9a-fA-F]{2}", raw)) > 6:
        add("heavy_encoding", 0.05, "Many percent-encoded characters (obfuscation)")
    if sp.scheme not in ("http", "https"):
        add("odd_scheme", 0.20, f"Unusual scheme '{sp.scheme}'")
    return out


def is_cosmetic_redirect(source: str, destination: str) -> bool:
    """An observed www alias, HTTPS upgrade or root slash changes no page identity."""
    a, ah = parse(source)
    b, bh = parse(destination)
    strip_www = lambda h: h[4:] if h.startswith("www.") else h
    if strip_www(ah) != strip_www(bh):
        return False
    if (a.scheme, b.scheme) not in (("http", "http"), ("https", "https"), ("http", "https")):
        return False
    try:
        a_standard = a.port in (None, 80 if a.scheme == "http" else 443)
        b_standard = b.port in (None, 80 if b.scheme == "http" else 443)
        ports_match = (a_standard and b_standard) or (a.scheme == b.scheme and a.port == b.port)
    except ValueError:
        return False
    return ports_match and (a.path or "/") == (b.path or "/") and a.query == b.query and a.username == b.username
