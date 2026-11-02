"""Page-content features, safe fetching, SSRF guards, and Playwright DOM rendering fallback.

Inspection Strategy:
  1. safe_fetch retrieves HTML via requests with strict SSRF protection and TLS verification.
  2. page_usable determines whether the response contains real, meaningful content.
  3. If static HTML is a JavaScript shell, render_with_playwright executes JavaScript in an
     isolated, SSRF-guarded browser context to obtain the rendered DOM.
  4. If rendering succeeds, features are extracted from the rendered DOM.
  5. If inspection fails (bot protection, HTTP error, timeout), the pipeline falls back gracefully
     to host-only analysis and records the exact reason without penalising the site as phishing.
"""
from __future__ import annotations

import base64
import ipaddress
import re
import socket
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None

from .brands import LEGIT_EXTERNAL_DESTINATIONS, check_title_brand_mismatch
from .urlfeatures import registered_domain, is_cosmetic_redirect, is_ip_host

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
MAX_BYTES = 2_000_000
MAX_REDIRECTS = 5

# Robust 22 content features (LineOfCode and LargestLineLength removed to prevent dataset shortcut bias)
CONTENT_FEATURES = [
    "HasTitle", "HasFavicon", "HasDescription", "IsResponsive", "HasPasswordField", "HasSubmitButton",
    "HasHiddenFields", "HasExternalFormSubmit", "HasSocialNet", "HasCopyrightInfo", "NoOfiFrame",
    "NoOfPopup", "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
    "Bank", "Pay", "Crypto", "NoOfURLRedirect",
]

_SOCIAL = ("facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com", "youtube.com",
           "pinterest.com", "tiktok.com", "whatsapp.com", "t.me", "telegram.me")

_CHALLENGE_MARKERS = (
    "just a moment", "cf-browser-verification", "challenge-platform", "_cf_chl", "attention required",
    "checking your browser", "ddos protection by", "enable javascript and cookies", "px-captcha",
    "access denied", "request blocked", "sgcaptcha", "security check", ".well-known/sgcaptcha",
    "cloudflare ray id", "incident id", "human verification", "verify you are human"
)


class UnsafeTarget(Exception):
    pass


class UnresolvableTarget(UnsafeTarget):
    """DNS failed; distinct from a destination blocked for non-public addresses."""


def assert_public_host(host: str) -> list[str]:
    """Resolve ``host`` and raise UnsafeTarget if any address is non-public. Returns the IPs."""
    if not host:
        raise UnsafeTarget("empty host")
    host_clean = host.strip("[]")
    try:
        infos = socket.getaddrinfo(host_clean, None)
    except socket.gaierror as e:
        raise UnresolvableTarget(f"DNS resolution failed: {e}") from e
    ips = sorted({i[4][0] for i in infos})
    for ip in ips:
        a = ipaddress.ip_address(ip.split("%")[0])
        if not a.is_global:
            raise UnsafeTarget(f"{host} resolves to non-public address {ip}")
    return ips


def _host_of(u: str) -> str:
    h = (urlsplit(u).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def _reg_of(u: str) -> str:
    h = _host_of(u)
    _, sld, suf = registered_domain(h)
    return f"{sld}.{suf}" if suf else sld


def safe_fetch(url: str, timeout: float = 6.0) -> dict:
    """Fetch HTML safely. Returns dict(html, final_url, n_redirects, status, content_type, tls_valid)."""
    session = requests.Session()
    session.headers["User-Agent"] = UA
    cur, hops = url, 0
    substantive_hops = 0
    redirect_chain = []
    tls_valid = True
    tls_error = None

    while True:
        sp = urlsplit(cur)
        if sp.scheme not in ("http", "https"):
            raise UnsafeTarget(f"scheme {sp.scheme!r} not allowed")
        assert_public_host(sp.hostname or "")

        try:
            r = session.get(cur, timeout=timeout, allow_redirects=False, stream=True, verify=True)
        except requests.exceptions.SSLError as e:
            # Handle verification failures explicitly rather than silently ignoring
            tls_valid = False
            tls_error = str(e)[:120]
            # Fetch unverified to inspect the payload, but keep record that TLS failed
            r = session.get(cur, timeout=timeout, allow_redirects=False, stream=True, verify=False)

        except requests.RequestException as error:
            error.redirect_chain = list(redirect_chain)
            error.failed_url = cur
            raise

        if r.is_redirect and r.headers.get("location") and hops < MAX_REDIRECTS:
            destination = urljoin(cur, r.headers["location"])
            substantive_hops += int(not is_cosmetic_redirect(cur, destination))
            redirect_chain.append({"from": cur, "to": destination, "status": r.status_code})
            cur = destination
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

        return {
            "html": html,
            "final_url": cur,
            "n_redirects": hops,
            "n_substantive_redirects": substantive_hops,
            "redirect_chain": redirect_chain,
            "status": r.status_code,
            "content_type": r.headers.get("content-type", ""),
            "tls_valid": tls_valid,
            "tls_error": tls_error,
            "inspection_method": "static_http",
        }



def fallback_urls(url: str) -> list[str]:
    """HTTPS-first alternatives, only for standard-port public website names.

    Never add www to a functional subdomain, strip userinfo, or downgrade HTTPS.
    These are recovery attempts, not claims that two hosts are equivalent.
    """
    sp = urlsplit(url)
    host = (sp.hostname or "").lower().rstrip(".")
    try:
        standard_port = sp.port in (None, 80 if sp.scheme == "http" else 443)
    except ValueError:
        return []
    if sp.scheme not in ("http", "https") or not standard_port or sp.username or sp.password or is_ip_host(host):
        return []
    sub, _, _ = registered_domain(host)
    candidates = []
    if sp.scheme == "http":
        candidates.append(urlunsplit(("https", host, sp.path, sp.query, sp.fragment)))
    if sub in ("", "www"):
        alternative = host[4:] if sub == "www" else "www." + host
        candidates.append(urlunsplit(("https", alternative, sp.path, sp.query, sp.fragment)))
    return [u for u in candidates if u != url]


def fetch_with_fallback(url: str, timeout: float = 6.0) -> dict:
    """Recover from transport failure, preserving evidence of the submitted failure.

    No alternative is tried after an SSRF block or an HTTP error response. A
    failing site is not made safe by choosing a different site's response.
    """
    attempts = []
    try:
        page = safe_fetch(url, timeout=timeout)
        page["fetch_attempts"] = [{"url": url, "status": "response", "http_status": page.get("status")}]
        page["fetch_url"] = url
        page["fallback_used"] = False
        return page
    except UnresolvableTarget as error:
        attempts.append({"url": url, "status": "failed", "reason": "DNS resolution failed"})
        original_error = error
    except UnsafeTarget:
        raise
    except requests.exceptions.SSLError:
        raise
    except (requests.Timeout, requests.ConnectionError) as error:
        attempts.append({"url": url, "status": "failed", "reason": type(error).__name__,
                         "redirect_chain": getattr(error, "redirect_chain", []), "failed_url": getattr(error, "failed_url", url)})
        original_error = error
    for alternative in fallback_urls(url):
        try:
            page = safe_fetch(alternative, timeout=timeout)
            if urlsplit(page.get("final_url", alternative)).scheme != "https":
                attempts.append({"url": alternative, "status": "rejected", "reason": "HTTPS alternative downgraded to HTTP"})
                continue
            if not page.get("tls_valid", True):
                raise requests.exceptions.SSLError("HTTPS recovery certificate verification failed")
            if page.get("status", 200) >= 400:
                attempts.append({"url": alternative, "status": "failed", "reason": f"HTTP {page['status']}"})
                continue
            attempts.append({"url": alternative, "status": "response", "http_status": page.get("status")})
            page["fetch_attempts"] = attempts
            page["fetch_url"] = alternative
            page["fallback_used"] = True
            return page
        except UnresolvableTarget:
            attempts.append({"url": alternative, "status": "failed", "reason": "DNS resolution failed"})
        except UnsafeTarget:
            # Stop; do not turn blocked resources into a reason to probe more names.
            raise
        except requests.exceptions.SSLError:
            raise
        except requests.RequestException as error:
            attempts.append({"url": alternative, "status": "failed", "reason": type(error).__name__,
                             "redirect_chain": getattr(error, "redirect_chain", []), "failed_url": getattr(error, "failed_url", alternative)})
    original_error.fetch_attempts = attempts
    raise original_error

def page_usable(page: dict) -> tuple[bool, str]:
    """Is the fetched page the site's real content?

    Distinguishes bot-protection challenge pages, HTTP errors, and JavaScript shells.
    """
    if not page:
        return False, "no page content returned"
    status = page.get("status", 200)
    if status >= 400:
        return False, f"HTTP {status}: the server returned an error page"
    html = page.get("html", "")
    low = html.lower()

    # Detect challenge / anti-bot / captcha refresh pages
    if any(m in low for m in _CHALLENGE_MARKERS):
        return False, "the site returned a bot-protection or captcha challenge page"
    if status == 202 and ("sgcaptcha" in low or "refresh" in low):
        return False, "the site returned an anti-bot challenge (HTTP 202)"

    # Detect JavaScript-rendered shells
    if BeautifulSoup is not None:
        soup = BeautifulSoup(html, "html.parser")
        text_len = len(soup.get_text(" ", strip=True))
        has_form = bool(soup.find("form") or soup.find("input"))
        has_script = bool(soup.find("script"))
        is_spa_mount = bool(soup.find(id=re.compile(r"^(root|app|__next)$", re.I)))

        if (text_len < 80 and not has_form and has_script) or (text_len < 40 and is_spa_mount):
            return False, "page is a JavaScript-rendered shell: static HTML has insufficient content (headless rendering needed)"

    return True, ""


def render_with_playwright(url: str, timeout: float = 6.0, static_html: str | None = None) -> dict:
    """Render page with Playwright headless Chromium with strict SSRF protection.

    Every subresource and redirect destination is intercepted and validated against private IP ranges.
    """
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        return {"ok": False, "error": "Playwright is not installed"}

    def is_safe_destination(dest_url: str) -> bool:
        sp = urlsplit(dest_url)
        if sp.scheme not in ("http", "https"):
            return False
        h = sp.hostname or ""
        if not h:
            return False
        try:
            assert_public_host(h)
            return True
        except UnsafeTarget:
            return False

    # Check root navigation target first
    if not is_safe_destination(url):
        return {"ok": False, "error": "Target destination blocked by SSRF protection"}

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
            )
            context = browser.new_context(
                java_script_enabled=True,
                service_workers="block",
                bypass_csp=False,
                viewport={"width": 1280, "height": 800},
                user_agent=UA,
            )

            # Strict SSRF route interception on every request and subresource
            def route_filter(route):
                req_url = route.request.url
                if not is_safe_destination(req_url):
                    route.abort("accessdenied")
                else:
                    route.continue_()

            page = context.new_page()
            browser_navigations = []
            document_status = {"value": None}
            last_navigation = {"url": url}
            def observe_request(req):
                try:
                    if req.is_navigation_request() and req.frame == page.main_frame and req.redirected_from:
                        previous_url = req.redirected_from.url
                        browser_navigations.append({"kind": "browser_http_redirect", "from": previous_url, "to": req.url, "detail": "HTTP redirect observed during browser rendering"})
                        last_navigation["url"] = req.url
                except Exception:
                    pass
            def observe_frame(frame):
                if frame == page.main_frame and frame.url not in ("about:blank", last_navigation["url"]):
                    browser_navigations.append({"kind": "browser_navigation", "from": last_navigation["url"], "to": frame.url, "detail": "Browser / client-side navigation"})
                    last_navigation["url"] = frame.url
            def observe_response(response):
                try:
                    if response.request.is_navigation_request() and response.request.frame == page.main_frame:
                        document_status["value"] = response.status
                except Exception:
                    pass
            page.on("response", observe_response)
            page.on("request", observe_request)
            page.on("framenavigated", observe_frame)
            context.route("**/*", route_filter)
            page.set_default_navigation_timeout(int(timeout * 1000))
            page.set_default_timeout(int(timeout * 1000))

            try:
                started = time.monotonic()
                resp = page.goto(url, wait_until="domcontentloaded")
                # Ignore script nonces/timestamps; stabilise the visible UI instead.
                # A hard deadline handles sites with perpetual analytics or spinners.
                page.wait_for_timeout(300)
                previous = None
                stable_samples = 0
                settled = False
                usable = False
                for _ in range(40):
                    snapshot = page.content()
                    visual_state = _visible_render_state(page)
                    current = (page.url, visual_state.get("fingerprint", snapshot))
                    usable, _reason = page_usable({"status": document_status["value"] or (resp.status if resp else 200), "html": snapshot})
                    stable_samples = stable_samples + 1 if current == previous else 0
                    if (usable and not visual_state.get("busy", False) and stable_samples >= 3
                            and time.monotonic() - started >= min(1.2, timeout / 2)):
                        settled = True
                        break
                    if time.monotonic() - started >= timeout - 0.2:
                        break
                    previous = current
                    page.wait_for_timeout(200)

                assets_ready = _wait_for_preview_assets(page)
                # Assets can trigger late app navigation; sample URL and DOM together.
                final_url = page.url
                status = document_status["value"] or (resp.status if resp else 200)
                rendered_html = page.content()
                captured_navigations = list(browser_navigations)
                try:
                    dom_preview = base64.b64encode(page.screenshot(type="jpeg", quality=75, timeout=2000)).decode("ascii")
                except Exception:
                    dom_preview = None
                static_preview = _static_snapshot(browser, static_html, url) if static_html is not None else None
            finally:
                context.close()
                browser.close()

            return {
                "ok": True,
                "html": rendered_html,
                "rendered_preview": dom_preview,
                "browser_navigations": captured_navigations,
                "readiness": {"state": "settled" if settled else "time_limit", "content_usable": usable,
                              "assets_ready": assets_ready, "waited_ms": round((time.monotonic() - started) * 1000)},
                "static_preview": static_preview,
                "final_url": final_url,
                "status": status,
                "content_type": "text/html",
                "inspection_method": "playwright_rendered",
            }
    except Exception as e:
        return {"ok": False, "error": f"Rendering failed: {str(e)[:100]}"}





def _visible_render_state(page) -> dict:
    """A stable UI signature unaffected by analytics script text or random nonces."""
    try:
        result = page.evaluate(r"""() => {
          const body = document.body;
          const text = (body?.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 30000);
          const controls = Array.from(document.querySelectorAll('input,button,select,textarea,a[href]')).map(e => [e.tagName,e.getAttribute('type'),e.getAttribute('href'),e.textContent?.trim().slice(0,80)]);
          const busy = Array.from(document.querySelectorAll('[aria-busy="true"],[role="progressbar"],.spinner,.loading,.skeleton')).some(e => e.getClientRects().length && getComputedStyle(e).visibility !== 'hidden' && getComputedStyle(e).display !== 'none');
          return {fingerprint: JSON.stringify([location.href,text,controls,document.images.length]),busy};
        }""")
        return result if isinstance(result, dict) else {}
    except Exception:
        return {}

def _wait_for_preview_assets(page):
    """Allow visible images and CSS backgrounds to decode; never wait indefinitely."""
    try:
        result = page.evaluate(r"""async () => {
          const visible = el => {const r=el.getBoundingClientRect(); return r.width>0 && r.height>0 && r.bottom>0 && r.right>0 && r.top<innerHeight && r.left<innerWidth && getComputedStyle(el).visibility!=='hidden'};
          const jobs = Array.from(document.images).filter(visible).map(i => i.decode().catch(() => {}));
          if (document.fonts) jobs.push(document.fonts.ready);
          const urls = new Set();
          for (const el of Array.from(document.querySelectorAll('*')).slice(0, 600).filter(visible)) {
            for (const match of getComputedStyle(el).backgroundImage.matchAll(/url\(["']?(.*?)["']?\)/g)) urls.add(match[1]);
          }
          for (const url of urls) {
            const img = new Image(); img.src = url;
            jobs.push(img.decode().catch(() => {}));
          }
          return await Promise.race([Promise.allSettled(jobs).then(() => true), new Promise(resolve => setTimeout(() => resolve(false), 4000))]);
        }""")
        return result if isinstance(result, bool) else False
    except Exception:
        return False

def _static_snapshot(browser, html: str, url: str) -> str | None:
    """Render the fetched source with JavaScript off; only return a JPEG snapshot."""
    context = None
    try:
        context = browser.new_context(java_script_enabled=False, service_workers="block", viewport={"width": 1280, "height": 800})
        page = context.new_page()
        page.set_default_timeout(2500)
        def guard_resource(route):
            target = urlsplit(route.request.url)
            try:
                if target.scheme not in ("http", "https"):
                    return route.abort()
                assert_public_host(target.hostname or "")
                route.continue_()
            except Exception:
                route.abort()
        context.route("**/*", guard_resource)
        soup = BeautifulSoup(html, "html.parser")
        for base in soup.find_all("base"):
            base.decompose()
        base = soup.new_tag("base", href=url)
        if soup.head:
            soup.head.insert(0, base)
        else:
            soup.insert(0, base)
        for refresh in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
            refresh.decompose()
        page.set_content(str(soup), wait_until="domcontentloaded", timeout=2500)
        page.wait_for_timeout(300)
        _wait_for_preview_assets(page)
        return base64.b64encode(page.screenshot(type="jpeg", quality=75, timeout=2000)).decode("ascii")
    except Exception:
        return None
    finally:
        if context:
            context.close()


def render_static_preview(html: str, url: str) -> str | None:
    """Visualise static HTML even when no JavaScript rendering fallback was needed."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            try:
                return _static_snapshot(browser, html, url)
            finally:
                browser.close()
    except Exception:
        return None

def extract_content_features(html: str, page_url: str, n_redirects: int = 0) -> dict[str, float]:
    """Compute CONTENT_FEATURES from HTML."""
    if BeautifulSoup is None:  # pragma: no cover
        raise RuntimeError("beautifulsoup4 is required for content features")
    soup = BeautifulSoup(html, "html.parser")
    my_reg = _reg_of(page_url)
    text_low = html.lower()

    title = soup.title.get_text().strip() if soup.title else ""
    icon = soup.find("link", rel=lambda r: r and "icon" in (" ".join(r).lower() if isinstance(r, list) else r.lower()))
    desc = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
    viewport = soup.find("meta", attrs={"name": re.compile(r"^viewport$", re.I)})

    forms = soup.find_all("form")
    inputs = soup.find_all("input")
    pw = int(any((i.get("type") or "").lower() == "password" for i in inputs))
    hidden = int(any((i.get("type") or "").lower() == "hidden" for i in inputs))
    submit = int(any((i.get("type") or "").lower() in ("submit", "image") for i in inputs)
                 or any((b.get("type") or "submit").lower() == "submit" for b in soup.find_all("button")))

    ext_form = 0
    for fm in forms:
        act = (fm.get("action") or "").strip()
        if act.lower().startswith(("http://", "https://", "//")):
            dest_host = _host_of(urljoin(page_url, act))
            dest_reg = _reg_of(urljoin(page_url, act))
            # Same registered domain is internal, not external
            if dest_reg and dest_reg != my_reg:
                # Legitimate external identity/payment providers are allowed
                if dest_reg not in LEGIT_EXTERNAL_DESTINATIONS and dest_host not in LEGIT_EXTERNAL_DESTINATIONS:
                    # Form must collect input to be considered a credential submission
                    fm_inputs = fm.find_all("input")
                    if any((i.get("type") or "text").lower() in ("password", "text", "email") for i in fm_inputs):
                        ext_form = 1

    anchors = soup.find_all("a", href=True)
    self_ref = empty_ref = ext_ref = 0
    social = 0
    my_host = _host_of(page_url)

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
        hr = _reg_of(urljoin(page_url, href))
        if hh == my_host or hr == my_reg:
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
        "Bank": int(bool(re.search(r"\b(bank|banking)\b", visible))),
        "Pay": int(bool(re.search(r"\b(pay|payment|paypal|checkout)\b", visible))),
        "Crypto": int(bool(re.search(r"\b(crypto|bitcoin|btc|ethereum|wallet|metamask)\b", visible))),
        "NoOfURLRedirect": int(n_redirects),
    }
    return {k: float(feats[k]) for k in CONTENT_FEATURES}


def content_signals(cf: dict[str, float], scheme: str, title: str = "", host: str = "") -> list[dict]:
    """Empirical rule-based observations about the page content."""
    out = []
    if cf.get("HasPasswordField") and scheme == "http":
        out.append({"name": "password_over_http", "weight": 0.20,
                    "detail": "Password input requested over insecure, unencrypted HTTP connection"})
    if cf.get("HasExternalFormSubmit") and cf.get("HasPasswordField"):
        out.append({"name": "external_form_submit_password", "weight": 0.20,
                    "detail": "Form with password field submits credentials to an untrusted external domain"})
    elif cf.get("HasExternalFormSubmit"):
        out.append({"name": "external_form_submit", "weight": 0.08,
                    "detail": "Form submits data to a different external domain"})

    # Title brand impersonation check
    if title and host:
        _, sld, suf = registered_domain(host)
        reg = f"{sld}.{suf}" if suf else sld
        tm = check_title_brand_mismatch(title, reg)
        if tm.get("mismatch"):
            out.append({"name": "title_brand_mismatch", "weight": 0.25,
                        "detail": f"Page title claims official '{tm['brand']}' identity, but the registered domain ({reg}) does not belong to that brand"})

    return out
