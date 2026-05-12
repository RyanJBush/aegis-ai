# Obsidian API Surface

Base URL: `/api/v1`

The FastAPI app also serves interactive docs at `/docs` (Swagger UI) and
`/redoc`. Authenticated routes require a `Bearer` JWT obtained from
`POST /auth/login`. Most write/scan/list endpoints additionally honor the
RBAC role and workspace claim (`wid`) carried in the token.

## Auth

- `POST /auth/register` — create an account (role: `admin`,
  `security_analyst`, `developer`, or `viewer`).
- `POST /auth/login` — returns access + refresh tokens; the access token
  includes a workspace claim (`wid`).
- `POST /auth/refresh` — rotates the refresh token.
- `POST /auth/logout` — revokes the refresh token.
- `GET /auth/me` — returns the current user record.

## Scanning

- `GET /scanning` — workspace-scoped scan list with pagination.
- `POST /scanning/run` — run a scan against an inline payload/target.
- `POST /scanning/queue` — enqueue a background scan job.
- `GET /scanning/jobs/{job_id}` — poll a queued job.
- `PATCH /scanning/{scan_id}/status` — update a scan's lifecycle status.
- `POST /scanning/devsecops/snippet` — scan inline code/config snippets
  (developer/CI workflow).
- `POST /scanning/devsecops/upload` — scan uploaded snippet/config files.
- `GET /scanning/kpi/summary` — posture KPIs for the dashboard.
- `GET /scanning/history/trends` — trend series for the dashboard.
- `GET /scanning/{scan_id}/diff` — baseline diff for a scan.
- `POST /scanning/{scan_id}/policy-gate` — CI pass/fail evaluation.
- `GET /scanning/{scan_id}/suppressions` — baseline suppression export.
- `GET /scanning/{scan_id}/remediation-checklist` — developer-facing fix
  checklist derived from findings.
- `GET /scanning/{scan_id}/reports/json` — JSON report bundle.
- `GET /scanning/{scan_id}/reports/sarif` — SARIF report bundle.

## Vulnerabilities

- `GET /vulnerabilities` — workspace-scoped, paginated, sortable list.
- `GET /vulnerabilities/{vuln_id}` — single finding detail.
- `GET /vulnerabilities/reports/summary` — summary aggregations.
- `PATCH /vulnerabilities/{vuln_id}/workflow` — update workflow state /
  owner / notes.
- `POST /vulnerabilities/{vuln_id}/comments` — add a triage comment.
- `POST /vulnerabilities/{vuln_id}/risk-acceptance` — file a risk-acceptance
  record.
- `GET /vulnerabilities/{vuln_id}/timeline` — timeline events for the finding.

## AI Assistant

- `GET /ai/scans/{scan_id}/executive-summary` — scan-level executive
  summary, clustering findings by rule / OWASP / CWE.
- `GET /ai/findings/{vuln_id}/insight` — finding-level plain-language
  explanation with remediation and secure-recommendation context.

The AI assistant is **deterministic** and derives its output from scanner
evidence and OWASP/CWE mappings — no external LLM call is required.

## Observability

- `GET /observability/audit-logs` — workspace-scoped audit log retrieval
  with filtering and pagination.
- `GET /observability/scan-metrics` — scan performance metrics summary for
  dashboards and SLO tracking.
- `POST /observability/rule-history` — record a scanner rule change event.
- `GET /observability/rule-history` — query the scanner rule change history
  for governance and change review.

## Health

- `GET /health` — liveness.
- `GET /ready` — readiness with a live database probe.

## Multi-Tenant Workspace Enforcement

- Workspace model with tenant scoping on users, scans, and vulnerabilities.
- Workspace claim (`wid`) enforced in JWT dependency checks.
- Optional `X-Workspace-ID` header validated to prevent cross-tenant access.
- Pagination/sorting supported for vulnerability and scan listings.

## Conventions

- All authenticated endpoints expect `Authorization: Bearer <access_token>`.
- Errors follow FastAPI's default JSON shape (`{"detail": ...}`).
- Severity values used throughout: `critical`, `high`, `medium`, `low`.
- OWASP category strings follow the OWASP Top 10 (2021) labels — see
  [`owasp-mapping.md`](owasp-mapping.md).
