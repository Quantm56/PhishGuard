"""Live OSINT enrichment: domain age (RDAP/WHOIS), DNS, TLS certificate and threat-intelligence lookups.

Design rules
  * Every lookup is independent, time-boxed and fail-soft: a failure yields status "unavailable"
    and is NEVER treated as "clean".
  * No API key is required for: RDAP, DNS, TLS, OpenPhish feed. Optional keys (environment variables):
        PHISHTANK_APP_KEY   PhishTank "checkurl" API (registration is often closed - the key is optional)
  * These signals describe the *current* state of a domain, so they are applied as explicit, documented
    risk adjustments (see predictor.py) rather than learned features: PhiUSIIL has no registration dates.
"""
from __future__ import annotations

import base64
import hashlib
import concurrent.futures as cf
import datetime as dt
import os
import socket
import ssl
import time

import requests

from .urlfeatures import is_ip_host, parse, registered_domain
from .content import assert_public_host

TIMEOUT = 6
HEADERS = {"User-Agent": "PhishGuard/1.0 (academic project)"}
FEED_CACHE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "openphish_feed.txt")
FEED_TTL = 3600


def _now():
    return dt.datetime.now(dt.timezone.utc)


# ----------------------------------------------------------------------------- domain age
def domain_age(host: str) -> dict:
    """Registration date via RDAP (JSON, no key). Falls back to python-whois if installed."""
    if is_ip_host(host):
        return {"status": "skipped", "detail": "host is an IP address"}
    sub, sld, suffix = registered_domain(host)
    domain = f"{sld}.{suffix}" if suffix else host
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=TIMEOUT, headers=HEADERS)
        if r.status_code == 200:
            data = r.json()
            created = registrar = None
            for ev in data.get("events", []):
                if ev.get("eventAction") == "registration":
                    created = ev.get("eventDate")
            for ent in data.get("entities", []):
                if "registrar" in ent.get("roles", []):
                    for item in (ent.get("vcardArray") or [None, []])[1]:
                        if item[0] == "fn":
                            registrar = item[3]
            if created:
                d = dt.datetime.fromisoformat(created.replace("Z", "+00:00"))
                if d.tzinfo is None:
                    d = d.replace(tzinfo=dt.timezone.utc)
                return {"status": "ok", "domain": domain, "created": d.date().isoformat(),
                        "age_days": (_now() - d).days, "registrar": registrar, "source": "RDAP"}
        elif r.status_code == 404:
            return {"status": "not_found", "domain": domain, "detail": "no RDAP record; registration age unknown (registry coverage can be incomplete)"}
    except Exception as e:  # noqa: BLE001
        err = str(e)[:120]
    else:
        err = f"HTTP {r.status_code}"
    try:  # optional fallback
        import whois  # type: ignore
        w = whois.whois(domain)
        created = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=dt.timezone.utc)
            return {"status": "ok", "domain": domain, "created": created.date().isoformat(),
                    "age_days": (_now() - created).days, "registrar": getattr(w, "registrar", None), "source": "WHOIS"}
    except Exception:  # noqa: BLE001
        pass
    return {"status": "unavailable", "detail": err}


# ----------------------------------------------------------------------------- DNS
def dns_info(host: str) -> dict:
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        return {"status": "ok", "resolves": True, "ips": ips[:6]}
    except socket.gaierror:
        return {"status": "ok", "resolves": False, "ips": []}
    except Exception as e:  # noqa: BLE001
        return {"status": "unavailable", "detail": str(e)[:100]}


# ----------------------------------------------------------------------------- TLS certificate
def tls_info(host: str, port: int = 443) -> dict:
    """Fetch the certificate (verification on first; if that fails, retry unverified to describe it)."""
    if is_ip_host(host):
        return {"status": "skipped", "detail": "host is an IP address"}
    try:
        assert_public_host(host)
    except Exception as e:
        return {"status": "unavailable", "detail": str(e)[:100]}
    verified, verify_err = True, None
    for verify in (True, False):
        try:
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    from cryptography import x509
                    from cryptography.hazmat.primitives import serialization
                    from cryptography.x509.oid import NameOID
                    der = s.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(der)
                    nb = cert.not_valid_before_utc
                    na = cert.not_valid_after_utc
                    def label(name):
                        for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
                            values = name.get_attributes_for_oid(oid)
                            if values:
                                return values[0].value
                        return name.rfc4514_string()
                    try:
                        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
                    except x509.ExtensionNotFound:
                        sans = []
                    return {"status": "ok", "valid": verified, "error": verify_err,
                            "host": host, "port": port,
                            "issuer": label(cert.issuer), "subject": cert.subject.rfc4514_string(),
                            "issuer_dn": cert.issuer.rfc4514_string(),
                            "san": sans, "serial_number": format(cert.serial_number, "X"),
                            "sha256": hashlib.sha256(der).hexdigest(),
                            "not_before": nb.isoformat(), "not_after": na.isoformat(),
                            "pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                            "tls_version": s.version(),
                            "self_signed": cert.issuer == cert.subject,
                            "age_days": (_now() - nb).days,
                            "expires_in_days": (na - _now()).days}
        except ssl.SSLCertVerificationError as e:
            verified, verify_err = False, getattr(e, "verify_message", str(e))
            continue
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return {"status": "unavailable", "detail": f"no TLS on port {port}: {str(e)[:80]}"}
        except Exception as e:  # noqa: BLE001
            return {"status": "unavailable", "detail": str(e)[:100]}
    return {"status": "unavailable", "detail": "could not read certificate"}


# ----------------------------------------------------------------------------- threat intelligence
def _norm(u: str) -> str:
    return u.strip().rstrip("/").lower()


def _load_openphish() -> set[str]:
    fresh = os.path.exists(FEED_CACHE) and time.time() - os.path.getmtime(FEED_CACHE) < FEED_TTL
    if not fresh:
        r = requests.get("https://openphish.com/feed.txt", timeout=TIMEOUT * 2, headers=HEADERS)
        r.raise_for_status()
        os.makedirs(os.path.dirname(FEED_CACHE), exist_ok=True)
        with open(FEED_CACHE, "w") as f:
            f.write(r.text)
    with open(FEED_CACHE) as f:
        return {_norm(l) for l in f if l.strip()}


def check_openphish(url: str) -> dict:
    try:
        feed = _load_openphish()
        host = parse(url)[1]
        if _norm(url) in feed:
            return {"source": "OpenPhish", "status": "listed", "detail": "exact URL in OpenPhish community feed"}
        if any(parse(u)[1] == host for u in feed):
            return {"source": "OpenPhish", "status": "listed", "detail": "host appears in OpenPhish community feed"}
        return {"source": "OpenPhish", "status": "clean", "detail": f"not in feed ({len(feed)} entries)"}
    except Exception as e:  # noqa: BLE001
        return {"source": "OpenPhish", "status": "unavailable", "detail": str(e)[:100]}


def check_phishtank(url: str) -> dict:
    try:
        key = os.getenv("PHISHTANK_APP_KEY", "")
        data = {"url": base64.b64encode(url.encode()).decode(), "format": "json"}
        if key:
            data["app_key"] = key
        r = requests.post("https://checkurl.phishtank.com/checkurl/", data=data, timeout=TIMEOUT,
                          headers={"User-Agent": "phishtank/phishguard"})
        r.raise_for_status()
        res = r.json().get("results", {})
        if res.get("in_database"):
            valid = res.get("valid")
            return {"source": "PhishTank", "status": "listed" if valid else "clean",
                    "detail": "verified phish in PhishTank" if valid else "in PhishTank but not (yet) verified valid"}
        return {"source": "PhishTank", "status": "clean", "detail": "not in PhishTank database"}
    except Exception as e:  # noqa: BLE001
        return {"source": "PhishTank", "status": "unavailable", "detail": str(e)[:100]}


THREAT_FEEDS = [check_openphish, check_phishtank]


# ----------------------------------------------------------------------------- orchestrator
def enrich(url: str) -> dict:
    """Run all lookups in parallel. Returns {'whois':…, 'dns':…, 'tls':…, 'threat_intel':[…]}."""
    sp, host = parse(url)
    with cf.ThreadPoolExecutor(max_workers=5) as ex:
        f_age = ex.submit(domain_age, host)
        f_dns = ex.submit(dns_info, host)
        f_tls = ex.submit(tls_info, host, sp.port or 443) if sp.scheme == "https" else None
        f_ti = [ex.submit(fn, url) for fn in THREAT_FEEDS]
        out = {
            "whois": f_age.result(),
            "dns": f_dns.result(),
            "tls": f_tls.result() if f_tls else {"status": "skipped", "detail": "URL is not HTTPS"},
            "threat_intel": [f.result() for f in f_ti],
        }
    return out


def merge_threat_results(groups: list[tuple[str, list[dict]]]) -> list[dict]:
    """One provider row, retaining URL-specific evidence and any source threat hit.

    Missing coverage cannot become 'clean' just because another URL was clean.
    """
    providers = {}
    priority = {"listed": 4, "unavailable": 3, "clean": 2, "skipped": 1}
    for url, rows in groups:
        for row in rows:
            source = row.get("source", "Unknown provider")
            checks = providers.setdefault(source, [])
            for check in row.get("checks") or [{"url": url, "status": row.get("status", "unavailable"), "detail": row.get("detail", "")}]:
                if check not in checks:
                    checks.append(dict(check))
    output = []
    for source, checks in providers.items():
        strongest = max(checks, key=lambda c: priority.get(c["status"], 3))
        details = list(dict.fromkeys(c.get("detail", "") for c in checks))
        output.append({"source": source, "status": strongest["status"],
                       "detail": details[0] if len(details) == 1 else f"{len(checks)} URL checks; see per-address results",
                       "checks": checks})
    return output
