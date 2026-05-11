# OWASP Top 10 (2021) Coverage Matrix

This table maps the rules implemented in `backend/app/services/scanner_engine.py`
to the OWASP Top 10 categories they help surface. Coverage is **partial and
pattern-based by design** — see *Limitations* below.

| OWASP Category | Implemented Rule(s) | Severity | CWE | Profile |
|---|---|---|---|---|
| A01:2021 – Broken Access Control | `BROKEN_ACCESS_CONTROL` | high | CWE-284 | standard |
| A02:2021 – Cryptographic Failures | `SENSITIVE_DATA_EXPOSURE`, `SECRET_DETECTION` | critical | CWE-200, CWE-798 | deep |
| A03:2021 – Injection | `SQLI`, `XSS` | high / medium | CWE-89, CWE-79 | quick |
| A04:2021 – Insecure Design | *Not covered by static rules — see future work* | — | — | — |
| A05:2021 – Security Misconfiguration | `INSECURE_CONFIG`, `CONFIG_AUDIT`, `INSECURE_HEADERS` | medium / high | CWE-16, CWE-693 | quick / standard |
| A06:2021 – Vulnerable and Outdated Components | *Planned — would require SBOM/dependency scanning* | — | — | — |
| A07:2021 – Identification and Authentication Failures | `INSECURE_AUTH`, `AUTH_MISCONFIG` | high | CWE-287, CWE-327 | quick / standard |
| A08:2021 – Software and Data Integrity Failures | *Partial via `CONFIG_AUDIT` (image tag pinning)* | high | CWE-16 | standard |
| A09:2021 – Security Logging and Monitoring Failures | *Out of scope for static input scanning* | — | — | — |
| A10:2021 – Server-Side Request Forgery | *Planned* | — | — | — |

## Severity scale

| Level | Meaning |
|---|---|
| `critical` | Hardcoded secret, exposed credential, or unambiguous high-impact pattern |
| `high` | Likely-exploitable pattern (injection, broken auth, broken access control) |
| `medium` | Configuration weakness or pattern that increases attack surface |
| `low` | *Reserved for future low-noise hygiene checks* |

## Detection profiles

- **quick** — fast, high-signal pattern matches for inline use in dev workflows.
- **standard** — adds configuration audit and access-control heuristics.
- **deep** — adds secret/sensitive-data scanning and full coverage.

## Limitations

- This scanner uses **static regex pattern matching only**. It will both
  miss attacks (false negatives) and flag benign input (false positives).
- Pattern-based scanners are not a substitute for SAST, DAST, IAST, manual
  code review, or professional penetration testing.
- A04 (Insecure Design) and A09 (Logging/Monitoring) cannot be meaningfully
  detected from a single input payload — they are architectural concerns.
- A06 (Vulnerable Components) requires dependency manifest parsing, which is
  tracked as future work.

## Future work

- SBOM ingestion + CVE lookup for A06.
- SSRF heuristics for A10 (URL pattern + private-IP awareness).
- Confidence calibration via labeled test corpus.
- Optional integration with `bandit` and `semgrep` to complement regex rules.
