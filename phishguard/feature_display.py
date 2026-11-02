"""Conservative, human-readable feature guidance; not another scoring model."""

# Presence of these signals calls for review; absence is a favourable observation.
RISK_FLAGS = {
    "host_is_ip", "has_userinfo", "nonstd_port", "has_punycode", "is_shortener",
    "tld_abused", "brand_in_subdomain", "brand_in_sld_combo", "typosquat",
    "homoglyph", "any_brand_abuse", "HasExternalFormSubmit",
}
POSITIVE_FLAGS = {"HasTitle", "HasFavicon", "HasDescription", "IsResponsive", "HasCopyrightInfo"}


def describe_features(features: dict) -> dict:
    out = {}
    for name, value in features.items():
        if name in RISK_FLAGS:
            status = "bad" if value else "good"
            detail = "Indicator present; review in context." if value else "Indicator absent; favourable observation."
        elif name in POSITIVE_FLAGS:
            status = "good" if value else "neutral"
            detail = "Common site quality signal present; not proof of safety." if value else "Absent; not evidence of phishing."
        elif name == "n_suspicious_kw_host":
            status = "bad" if value else "good"
            detail = "Sensitive keywords found; review in context." if value else "No suspicious hostname keywords found."
        else:
            status = "neutral"
            detail = "Context dependent; no universal good/bad cutoff. See model risk drivers for its effect on this scan."
        out[name] = {"status": status, "detail": detail}
    return out
