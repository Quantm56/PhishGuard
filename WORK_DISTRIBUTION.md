# Information-security work distribution

This allocation gives each of three members one-third of the project responsibility. Each owns a security problem, its implementation, test evidence, a report section and a demonstration. Dashboard and API work is distributed with the security feature it presents, rather than assigning one member only interface work.

| Member | Information-security responsibility | Implementation scope | Security validation |
| --- | --- | --- | --- |
| **Member 1** | **Phishing detection, impersonation and risk analysis** | Host/domain feature extraction; typosquatting, homoglyphs and deceptive URL patterns; classifier training and evaluation; rule aggregation, thresholds and score explanations; model benchmark and risk-result displays. | Evaluate legitimate and impersonation examples; measure false positives and false negatives; check domain separation in evaluation; demonstrate why scheme/path shortcuts and page-layout bias are unreliable; verify score arithmetic. |
| **Member 2** | **Secure web inspection and credential-theft analysis** | SSRF checks; private/loopback blocking; guarded fetching, HTTP/HTTPS and host recovery; redirect validation; Playwright resource controls and DOM capture; external credential-submission and password-over-HTTP checks; inspection-path and preview displays. | Test private-address targets, redirects to blocked addresses, recovery constraints, external password forms, rendering time limits and delayed page hydration; show that uninspected content is labelled unavailable. |
| **Member 3** | **Infrastructure trust, threat intelligence and preventive browser controls** | DNS resolution; RDAP/optional WHOIS domain age; TLS certificate verification/details; OpenPhish and PhishTank checks; provider de-duplication and retained threat hits; extension interception, temporary navigation allowances, warning/error states and evidence displays. | Test invalid certificates, unknown registration age, failed or conflicting feed checks, threat-hit overrides, repeat navigation, expired allowances and API-offline behaviour; verify untrusted evidence is displayed without executing captured page code. |

## Equal deliverables

Every member contributes:

1. **Threat analysis:** identify the attack techniques their module addresses and its coverage limits.
2. **Implementation:** own the corresponding security logic and its API/dashboard/extension presentation.
3. **Validation:** prepare reproducible test cases, expected outcomes and recorded results for their module.
4. **Documentation:** write the architecture, security decisions and evaluation for their module.
5. **Demonstration:** present their module for an equal share of the presentation time.
6. **Peer review:** review another member's security tests and integration changes.

## Shared integration

- Member 1 reviews Member 2's credential-theft test outcomes and their effect on risk scoring.
- Member 2 reviews Member 3's navigation controls and failure handling.
- Member 3 reviews Member 1's impersonation tests and presentation of model uncertainty.
- All three jointly complete the end-to-end testing checklist, final report introduction/conclusion and README review.

