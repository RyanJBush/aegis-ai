# Resume Bullets

Concise, ATS-friendly one-liners derived from real work in this repo. Pick the
3–5 strongest for your resume; keep the rest for cover letters, LinkedIn, or
recruiter conversations.

## Headline bullets (pick 3–5 for resume)

- Built a Python/FastAPI vulnerability scanner that detects SQL injection, XSS, secret leakage, and security misconfiguration with OWASP Top 10 mapping, severity scoring, and remediation guidance.
- Designed a rule-registry scanner engine with `quick / standard / deep` profiles, deterministic dedupe keys, and CWE-tagged findings — covering 7 of the OWASP Top 10 (2021) categories.
- Implemented JWT authentication with RBAC across 3+ roles, refresh-token rotation, password hashing, account lockout, and security-headers middleware (CSP, HSTS, X-Frame-Options).
- Built a CLI scanner (`scripts/scan.py`) with JSON output and a `--fail-on <severity>` policy gate suitable for CI/CD integration.
- Authored a GitHub Actions DevSecOps pipeline running `ruff`, `bandit`, `mypy`, and `pytest` on every PR, plus a frontend lint + build stage.
- Wrote pytest coverage for the scanner engine, auth/RBAC flows, scanning pipeline, and the CLI — including negative-case "clean input" fixtures.

## Topic-specific bullets

### OWASP Top 10
- Mapped each scanner rule to a 2021 OWASP Top 10 category and CWE ID, and documented coverage and limitations in `docs/owasp-mapping.md`.
- Implemented detection rules covering Injection (A03), Cryptographic Failures (A02), Security Misconfiguration (A05), Broken Access Control (A01), and Auth Failures (A07).

### Vulnerability scanning
- Built a modular rule registry with per-rule severity, confidence, OWASP/CWE tagging, profile gating, and stable dedupe keys.
- Generated SARIF- and JSON-format scan reports for integration into CI/CD security gates.

### Secure coding
- Used parameterized queries via SQLAlchemy, contextual output encoding patterns, and Pydantic schemas for strict input validation at API boundaries.
- Added security-headers middleware (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) and request-ID propagation for traceability.

### Authentication
- Implemented JWT access tokens with rotating refresh tokens, bcrypt password hashing, password policy enforcement, account lockout, and per-endpoint auth rate limiting.

### Authorization
- Enforced RBAC at the API dependency layer for `admin`, `security_analyst`, `developer`, and `viewer` roles, plus workspace-scoped tenancy with cross-workspace request blocking.

### DevSecOps
- Built a GitHub Actions pipeline running `ruff`, `bandit`, `mypy`, and `pytest` on every push and PR, with an optional policy-gate CLI for blocking high-severity findings.
- Added a `/scanning/<id>/policy-gate` endpoint and a CLI `--fail-on` flag to support fail-the-build behavior for CI/CD integration.

### Security testing
- Wrote 30+ pytest cases across scanner rules, auth flows, RBAC enforcement, and the CLI, including negative-case fixtures to guard against false positives.
- Authored intentionally insecure sample inputs in `data/samples/` to drive both demos and regression tests.

## Notes on phrasing

- Each bullet is action → artifact → measurable scope (rules, roles, files, tests).
- All numbers above are grounded in the repo. Don't pad with imagined metrics
  (user counts, uptime, "production" usage) — recruiters and engineers will
  ask, and the project is honestly framed as an educational portfolio build.
