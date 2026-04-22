# API Surface

Base URL: `/api/v1`

## Auth
- `POST /auth/register`
- `POST /auth/login` (returns access + refresh token pair; access token includes workspace claim)
- `POST /auth/refresh` (rotates refresh token)
- `POST /auth/logout` (revokes refresh token)
- `GET /auth/me`

## Scanning
- `GET /scanning` (workspace-scoped scan list with pagination)
- `POST /scanning/devsecops/snippet` (scan inline code/config snippets)
- `POST /scanning/devsecops/upload` (scan uploaded snippet/config files)
- `POST /scanning/run`
- `POST /scanning/queue`
- `GET /scanning/jobs/{job_id}`
- `PATCH /scanning/{scan_id}/status`
- `GET /scanning/kpi/summary`
- `GET /scanning/history/trends`
- `GET /scanning/{scan_id}/diff`
- `POST /scanning/{scan_id}/policy-gate`
- `GET /scanning/{scan_id}/suppressions`
- `GET /scanning/{scan_id}/remediation-checklist`
- `GET /scanning/{scan_id}/reports/json`
- `GET /scanning/{scan_id}/reports/sarif`

## Vulnerabilities
- `GET /vulnerabilities` (workspace-scoped, paginated, sortable)
- `GET /vulnerabilities/{vuln_id}`
- `GET /vulnerabilities/reports/summary`
- `PATCH /vulnerabilities/{vuln_id}/workflow`
- `POST /vulnerabilities/{vuln_id}/comments`
- `POST /vulnerabilities/{vuln_id}/risk-acceptance`
- `GET /vulnerabilities/{vuln_id}/timeline`

## Health
- `GET /health`
- `GET /ready` (database readiness check)

## Phase 5 Platform Enhancements
- Workspace model with tenant scoping on users, scans, and vulnerabilities.
- Workspace claim (`wid`) enforced in JWT dependency checks.
- Optional `X-Workspace-ID` header validated for anti-cross-tenant access.
- Pagination/sorting support for vulnerability and scan listing endpoints.


## AI Assistant
- `GET /ai/scans/{scan_id}/executive-summary`
- `GET /ai/findings/{vuln_id}/insight`

## Phase 6 AI Enhancements
- Scan-level executive summaries with finding clustering by rule/OWASP/CWE.
- Finding-level plain-language explanation, remediation summary, secure recommendation.
- Explanation provenance tied to finding evidence and taxonomy metadata.


## Observability
- `GET /observability/audit-logs`
- `GET /observability/scan-metrics`
- `POST /observability/rule-history`
- `GET /observability/rule-history`

## Phase 7 Observability Enhancements
- Workspace-scoped audit log retrieval with filtering + pagination.
- Scan performance metrics summary for dashboards and SLO tracking.
- Scanner rule change history API for governance and change review.


## Phase 8 DevSecOps Enhancements
- DevSecOps scanning entrypoints for uploaded files and inline snippets.
- Expanded secret/token and config audit detection rules.
- Developer remediation checklist endpoint derived from scan findings.
