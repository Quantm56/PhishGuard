"""Build an honest inspection path: recovery is distinct from observed redirects."""


def inspection_journey(submitted: str, page: dict | None, error: str | None = None, attempts=None) -> list[dict]:
    steps = [{"kind": "submitted", "url": submitted, "detail": "Entered URL"}]
    if not page:
        for attempt in attempts or []:
            for hop in attempt.get("redirect_chain", []):
                steps.append({"kind": "http_redirect", "from": hop["from"], "url": hop["to"], "detail": "HTTP redirect before connection failure"})
            steps.append({"kind": "failed_attempt", "url": attempt.get("failed_url", attempt["url"]), "detail": attempt.get("reason", attempt.get("status", "Failed"))})
        steps.append({"kind": "unavailable", "url": submitted, "detail": error or "Page inspection was not requested"})
        return steps
    fetch_url = page.get("fetch_url", submitted)
    for attempt in page.get("fetch_attempts", []):
        if attempt.get("status") != "response":
            for hop in attempt.get("redirect_chain", []):
                steps.append({"kind": "http_redirect", "from": hop["from"], "url": hop["to"], "detail": "HTTP redirect before connection failure"})
            steps.append({"kind": "failed_attempt", "url": attempt.get("failed_url", attempt["url"]), "detail": attempt.get("reason", attempt["status"])})
    if page.get("fallback_used"):
        steps.append({"kind": "recovery", "url": fetch_url, "detail": "HTTPS / host alternative requested after connection failure (not a redirect)"})
    for hop in page.get("redirect_chain", []):
        steps.append({"kind": "http_redirect", "from": hop["from"], "url": hop["to"], "detail": f"HTTP redirect{(' ' + str(hop['status'])) if hop.get('status') else ''}"})
    for hop in page.get("browser_navigations", []):
        steps.append({"kind": hop.get("kind", "browser_navigation"), "from": hop["from"], "url": hop["to"], "detail": hop.get("detail", "Browser navigation")})
    final_url = page.get("final_url", fetch_url)
    if steps[-1]["url"] != final_url:
        steps.append({"kind": "observed_destination", "url": final_url, "detail": "Final browser URL observed; intermediate steps not reported"})
    steps.append({"kind": "final", "url": final_url, "detail": "Final inspected address"})
    return steps
