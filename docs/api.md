# Obsidian API Documentation

Base path: `/api/v1`

Interactive docs are available at `/docs` (Swagger UI) and `/redoc` when the backend is running.

## API safety and usage intent

These endpoints are intended for educational/local security workflows and authorized testing contexts only. Do not use this API to run scans against systems you do not own or explicitly control under written authorization.

## Authentication

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /auth/me`

Most endpoints require `Authorization: Bearer <access_token>`.

## Scanning

- `GET /scanning`
- `POST /scanning/run`
- `POST /scanning/queue`
- `GET /scanning/jobs/{job_id}`
- `PATCH /scanning/{scan_id}/status`
- `POST /scanning/devsecops/snippet`
- `POST /scanning/devsecops/upload`
- `GET /scanning/kpi/summary`
- `GET /scanning/history/trends`
- `GET /scanning/{scan_id}/diff`
- `POST /scanning/{scan_id}/policy-gate`
- `GET /scanning/{scan_id}/suppressions`
- `GET /scanning/{scan_id}/remediation-checklist`
- `GET /scanning/{scan_id}/reports/json`
- `GET /scanning/{scan_id}/reports/sarif`

### Scanner behavior notes

- Findings include severity labels and implemented rule mappings.
- OWASP/CWE tags are present where rule mappings exist.
- SARIF output is provided for integration workflows where supported.

## Vulnerability operations

- `GET /vulnerabilities`
- `GET /vulnerabilities/{vuln_id}`
- `GET /vulnerabilities/reports/summary`
- `PATCH /vulnerabilities/{vuln_id}/workflow`
- `POST /vulnerabilities/{vuln_id}/comments`
- `POST /vulnerabilities/{vuln_id}/risk-acceptance`
- `GET /vulnerabilities/{vuln_id}/timeline`

## Observability and governance

- `GET /observability/audit-logs`
- `GET /observability/scan-metrics`
- `POST /observability/rule-history`
- `GET /observability/rule-history`

## Health

- `GET /health`
- `GET /ready`

## CI/CD integration pattern

- Local/CI runner can call CLI with `--fail-on` for threshold gates.
- Backend policy-gate endpoint supports consistent pass/fail evaluation.

## Accuracy and assurance disclaimer

Obsidian API outputs are helpful for triage and developer feedback but are not complete security assurance artifacts by themselves. They should be used alongside broader AppSec practices and professional review processes.
