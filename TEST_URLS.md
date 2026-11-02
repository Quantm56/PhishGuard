# Ten manual test URLs

Restart the API, reload the extension, then test with live enrichment enabled except row 9.

| # | URL | What to verify |
|---|---|---|
| 1 | `http://bookkr.co` | Inspect the working HTTPS page after an actual redirect or disclosed connection-recovery attempt. |
| 2 | `https://bookkr.co` | Match the other Bookkr variants when they reach the same content. |
| 3 | `http://www.bookkr.co` | Same inspection and verdict as the HTTPS version; recovery if HTTP cannot connect. |
| 4 | `https://www.bookkr.co` | Bookkr reference: page content and visual preview should be inspected. |
| 5 | `http://maheslcm.manipal.edu` | University login portal: reach HTTPS, inspect the page, no link-count-based false positive. |
| 6 | `https://maheslcm.manipal.edu` | Match row 5 when both reach the same login page. |
| 7 | `https://github.com/pallets/flask` | Legitimate deep link; a path alone must not imply phishing. |
| 8 | `https://docs.python.org/3/library/urllib.parse.html` | Legitimate functional subdomain and deep documentation path. |
| 9 | `https://login-microsoftonline.com.account-verify.example/` | **Disable live enrichment.** Synthetic impersonation fixture, not an active phishing website. Expect a phishing warning from lexical/brand signals. |
| 10 | `http://127.0.0.1/` | **Enable live enrichment.** Page fetch must be blocked by the private-address guard. No preview or alternate address should be fetched. The API can still return a host-model estimate; verify the inspection error, not a particular overall verdict. |

The latest live check of all four Bookkr forms produced LEGITIMATE at 13.9%, with the rendered page inspected. This is an observation, not an expected score hardcoded into the app. The separate recovery test deliberately simulated an HTTP timeout and fetched the real HTTPS page to check the intermittent failure case.

For each scan record: submitted URL, inspected address, attempted addresses, inspection status/method, TLS status, verdict and score. A challenge page or timeout should say unavailable; it must not be recorded as successful inspection. Repeated visits can legitimately have different evidence if the page, certificate or threat listings change.

This is a regression smoke test, not an accuracy benchmark. The synthetic row tests a hostname pattern, not malware execution or threat-feed coverage. Evaluate accuracy separately on labelled, previously unseen domains.
