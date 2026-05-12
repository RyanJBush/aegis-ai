# Resume Bullets — Obsidian

Concise, ATS-friendly one-liners derived from real work in this repo. Pick
the 5–8 strongest for your resume; keep the rest for cover letters,
LinkedIn, or recruiter conversations.

All claims below map to verifiable code or docs in this repository.

## Headline bullets (pick 5–8 for resume)

- Built a **Python/FastAPI vulnerability scanner** with a pluggable rule
  registry, three detection profiles (`quick / standard / deep`), and
  OWASP Top 10 (2021) + CWE tagging on every finding.
- Designed a **rule-registry scanner engine** with severity scoring,
  per-finding confidence, deterministic dedupe keys, and remediation
  guidance — covering parts of A01, A02, A03, A05, A07, and A08.
- Implemented **JWT authentication with rotating refresh tokens, RBAC across
  four roles**, bcrypt password hashing, password policy, account lockout,
  and per-endpoint auth rate limiting.
- Designed a **multi-tenant workspace model** with a JWT `wid` claim and
  cross-workspace request blocking enforced at the FastAPI dependency layer.
- Built a **CLI scanner with a `--fail-on <severity>` policy gate** plus a
  matching `/scanning/{id}/policy-gate` API endpoint, suitable for blocking
  PRs in CI/CD on high-severity findings.
- Generated **SARIF + JSON scan reports** and an auto-generated remediation
  checklist for developer-facing fix workflows.
- Authored a **GitHub Actions DevSecOps pipeline** running `ruff`, `bandit`,
  `mypy`, and `pytest` on every push and PR, plus a frontend lint + build
  stage.
- Implemented **security-headers middleware** (CSP, X-Frame-Options,
  X-Content-Type-Options, no-store cache control) and request-ID propagation
  for traceability.
- Wrote **pytest coverage** across scanner unit rules, auth/RBAC flows, the
  scanning pipeline, the API surface, and the CLI — including negative-case
  "clean input" fixtures.

## Topic-specific bullets

### OWASP Top 10
- Mapped each scanner rule to a 2021 OWASP Top 10 category and CWE ID, and
  documented coverage and explicit gaps in [`owasp-mapping.md`](owasp-mapping.md).
- Implemented detection rules touching Injection (A03), Cryptographic
  Failures (A02), Security Misconfiguration (A05), Broken Access Control
  (A01), Identification & Authentication Failures (A07), and Software & Data
  Integrity Failures (A08).

### Vulnerability scanning
- Built a modular rule registry with per-rule severity, confidence,
  OWASP/CWE tagging, profile gating, and stable dedupe keys.
- Generated **SARIF** and JSON-format scan reports for ingestion into CI/CD
  security gates and GitHub code-scanning style dashboards.

### Secure coding
- Used parameterized queries via SQLAlchemy, contextual output-encoding
  patterns, and Pydantic schemas for strict input validation at API
  boundaries.
- Added security-headers middleware (CSP, X-Frame-Options,
  X-Content-Type-Options, no-store) and request-ID propagation.

### Authentication
- Implemented JWT access tokens with rotating refresh tokens, bcrypt
  password hashing, password-policy enforcement, account lockout, and
  per-endpoint auth rate limiting.

### Authorization
- Enforced RBAC at the API dependency layer for `admin`, `security_analyst`,
  `developer`, and `viewer` roles, plus workspace-scoped tenancy with
  cross-workspace request blocking via a JWT `wid` claim.

### DevSecOps
- Built a GitHub Actions pipeline running `ruff`, `bandit`, `mypy`, and
  `pytest` on every push and PR, with a CLI `--fail-on` policy gate for
  blocking high-severity findings.
- Added `/scanning/{id}/policy-gate` plus a CLI flag to support
  fail-the-build behavior for CI/CD integration.

### Security testing
- Authored a pytest suite spanning scanner rules, auth flows, RBAC
  enforcement, and the CLI, including negative-case fixtures to guard
  against false positives.
- Wrote intentionally insecure sample inputs under `data/samples/` to drive
  both demos and regression tests.

### Observability & governance
- Added audit-log query, scan-metric summary, and scanner rule-change
  history endpoints (`/observability/*`) for AppSec operations and
  governance review.

## Notes on phrasing

- Each bullet is **action → artifact → measurable scope** (rules, roles,
  files, tests).
- All numbers above are grounded in this repo. Don't pad with imagined
  metrics (user counts, uptime, "production" usage) — this is an honest
  educational portfolio build, framed as such throughout.
- The scanner is **not** a substitute for professional SAST / DAST / IAST
  tools or authorized penetration testing — keep this distinction in mind
  when paraphrasing for a resume.
