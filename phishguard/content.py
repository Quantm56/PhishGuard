"""Page-content features.

The PhiUSIIL dataset ships pre-computed HTML features (HasTitle, NoOfJS, ...). We reproduce the
subset whose definition is unambiguous so the *same* features can be computed for a live URL at
inference time. NOTE: definitions are re-implemented, not copied from the dataset authors' code,
so small train/serve differences are possible (see README, "Limitations").

Fetching a suspicious URL is itself risky, so ``safe_fetch``:
  * resolves the host and refuses private / loopback / link-local / reserved addresses (SSRF guard),
    re-checking every redirect hop;
  * never executes JavaScript, never stores cookies, caps response size and time;
  * only follows http/https.
Run the tool inside a VM/container if you plan to scan live malicious URLs.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urljoin, urlsplit

import requests

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None

UA = "Mozilla/5.0 (compatible; PhishGuard-Scanner/1.0; academic research)"
MAX_BYTES = 2_000_000
MAX_REDIRECTS = 5

CONTENT_FEATURES = [
    "HasTitle", "HasFavicon", "HasDescription", "IsResponsive", "HasPasswordField", "HasSubmitButton",
    "HasHiddenFields", "HasExternalFormSubmit", "HasSocialNet", "HasCopyrightInfo", "NoOfiFrame",
    "NoOfPopup", "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
    "LineOfCode", "LargestLineLength", "Bank", "Pay", "Crypto", "NoOfURLRedirect",
]

_SOCIAL = ("facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com", "youtube.com",
           "pinterest.com", "tiktok.com", "whatsapp.com", "t.me", "telegram.me")


class UnsafeTarget(Exception):
    pass


def assert_public_host(host: str) -> list[str]:
    """Resolve ``host`` and raise UnsafeTarget if any address is non-public. Returns the IPs."""
    if not host:
        raise UnsafeTarget("empty host")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise UnsafeTarget(f"DNS resolution failed: {e}") from e
    ips = sorted({i[4][0] for i in infos})
    for ip in ips:
        a = ipaddress.ip_address(ip.split("%")[0])
        if not a.is_global:
            raise UnsafeTarget(f"{host} resolves to non-public address {ip}")
    return ips


def safe_fetch(url: str, timeout: float = 6.0):
    """Fetch HTML safely. Returns dict(html, final_url, n_redirects, status) or raises UnsafeTarget/RequestException."""
    session = requests.Session()
    session.headers["User-Agent"] = UA
    cur, hops = url, 0
    while True:
        sp = urlsplit(cur)
        if sp.scheme not in ("http", "https"):
            raise UnsafeTarget(f"scheme {sp.scheme!r} not allowed")
        assert_public_host(sp.hostname or "")
        r = session.get(cur, timeout=timeout, allow_redirects=False, stream=True, verify=False)
        if r.is_redirect and r.headers.get("location") and hops < MAX_REDIRECTS:
            cur = urljoin(cur, r.headers["location"])
            hops += 1
            r.close()
            continue
        raw = b""
        for chunk in r.iter_content(65536):
            raw += chunk
            if len(raw) >= MAX_BYTES:
                break
        r.close()
        enc = r.encoding or "utf-8"
        try:
            html = raw.decode(enc, errors="replace")
        except LookupError:
            html = raw.decode("utf-8", errors="replace")
        return {"html": html, "final_url": cur, "n_redirects": hops, "status": r.status_code,
                "content_type": r.headers.get("content-type", "")}


def _host_of(u: str) -> str:
    h = (urlsplit(u).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def extract_content_features(html: str, page_url: str, n_redirects: int = 0) -> dict[str, float]:
    """Compute CONTENT_FEATURES from raw HTML."""
    if BeautifulSoup is None:  # pragma: no cover
        raise RuntimeError("beautifulsoup4 is required for content features")
    soup = BeautifulSoup(html, "html.parser")
    my_host = _host_of(page_url)
    lines = html.splitlines() or [""]
    text_low = html.lower()

    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    icon = soup.find("link", rel=lambda r: r and "icon" in " ".join(r).lower() if isinstance(r, list) else r and "icon" in r.lower())
    desc = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
    viewport = soup.find("meta", attrs={"name": re.compile(r"^viewport$", re.I)})

    forms = soup.find_all("form")
    ext_form = 0
    for fm in forms:
        act = (fm.get("action") or "").strip()
        if act.lower().startswith(("http://", "https://", "//")):
            ah = _host_of(urljoin(page_url, act))
            if ah and ah != my_host:
                ext_form = 1
    inputs = soup.find_all("input")
    pw = int(any((i.get("type") or "").lower() == "password" for i in inputs))
    hidden = int(any((i.get("type") or "").lower() == "hidden" for i in inputs))
    submit = int(any((i.get("type") or "").lower() in ("submit", "image") for i in inputs)
                 or any((b.get("type") or "submit").lower() == "submit" for b in soup.find_all("button")))

    anchors = soup.find_all("a", href=True)
    self_ref = empty_ref = ext_ref = 0
    social = 0
    for a in anchors:
        href = a["href"].strip()
        if href in ("", "#") or href.lower().startswith(("javascript:void", "javascript:;", "javascript:")) and len(href) < 14:
            empty_ref += 1
            continue
        if href.startswith(("#", "/", "?", "./", "../")) or not re.match(r"^[a-z]+:|^//", href, re.I):
            self_ref += 1
            continue
        if href.lower().startswith(("mailto:", "tel:")):
            continue
        hh = _host_of(urljoin(page_url, href))
        if hh == my_host:
            self_ref += 1
        else:
            ext_ref += 1
            if any(hh == s or hh.endswith("." + s) for s in _SOCIAL):
                social = 1

    scripts = soup.find_all("script")
    popups = len(re.findall(r"window\.open\s*\(|alert\s*\(|prompt\s*\(", text_low))
    css = len(soup.find_all("link", rel=lambda r: r and "stylesheet" in (" ".join(r).lower() if isinstance(r, list) else r.lower())))
    css += len(soup.find_all("style"))
    visible = soup.get_text(" ", strip=True).lower()

    feats = {
        "HasTitle": int(bool(title)),
        "HasFavicon": int(icon is not None),
        "HasDescription": int(bool(desc and (desc.get("content") or "").strip())),
        "IsResponsive": int(viewport is not None),
        "HasPasswordField": pw,
        "HasSubmitButton": submit,
        "HasHiddenFields": hidden,
        "HasExternalFormSubmit": ext_form,
        "HasSocialNet": social,
        "HasCopyrightInfo": int("©" in html or "&copy;" in text_low or "copyright" in visible),
        "NoOfiFrame": len(soup.find_all("iframe")),
        "NoOfPopup": popups,
        "NoOfImage": len(soup.find_all("img")),
        "NoOfCSS": css,
        "NoOfJS": len(scripts),
        "NoOfSelfRef": self_ref,
        "NoOfEmptyRef": empty_ref,
        "NoOfExternalRef": ext_ref,
        "LineOfCode": len(lines),
        "LargestLineLength": max(len(l) for l in lines),
        "Bank": int(bool(re.search(r"\b(bank|banking)\b", visible))),
        "Pay": int(bool(re.search(r"\b(pay|payment|paypal|checkout)\b", visible))),
        "Crypto": int(bool(re.search(r"\b(crypto|bitcoin|btc|ethereum|wallet|metamask)\b", visible))),
        "NoOfURLRedirect": int(n_redirects),
    }
    return {k: float(feats[k]) for k in CONTENT_FEATURES}


_CHALLENGE_MARKERS = ("just a moment", "cf-browser-verification", "challenge-platform", "_cf_chl", "attention required",
                      "checking your browser", "ddos protection by", "enable javascript and cookies", "px-captcha",
                      "access denied", "request blocked")


def page_usable(page: dict) -> tuple[bool, str]:
    """Is the fetched page the site's real content? Block pages, errors and JS-only shells would otherwise look like
    'tiny bare page' to the model, which is exactly what phishing pages look like in the training data."""
    status = page.get("status", 200)
    if status >= 400:
        return False, f"HTTP {status}: the server refused or errored (often bot protection), so the real page was not seen"
    html = page.get("html", "")
    low = html.lower()
    if len(html) < 30000 and any(m in low for m in _CHALLENGE_MARKERS):
        return False, "the site returned a bot-protection / challenge page instead of its real content"
    if BeautifulSoup is not None:
        soup = BeautifulSoup(html, "html.parser")
        text_len = len(soup.get_text(" ", strip=True))
        has_form = bool(soup.find("form") or soup.find("input"))
        if text_len < 80 and not has_form and soup.find("script"):
            return False, "page is a JavaScript-rendered shell: static HTML has no content (a headless browser would be needed)"
    return True, ""


def content_signals(cf: dict[str, float], scheme: str) -> list[dict]:
    """Human-readable, rule-based observations about the page (used in the report; weights are small)."""
    out = []
    if cf["HasPasswordField"] and scheme == "http":
        out.append({"name": "password_over_http", "weight": 0.20, "detail": "Page asks for a password over unencrypted HTTP"})
    if cf["HasExternalFormSubmit"]:
        out.append({"name": "external_form_submit", "weight": 0.15, "detail": "A form on the page submits data to a different domain"})
    if cf["HasPasswordField"] and not cf["HasFavicon"] and not cf["HasDescription"]:
        out.append({"name": "bare_login_page", "weight": 0.05, "detail": "Login form on a page with no favicon or meta description"})
    return out
