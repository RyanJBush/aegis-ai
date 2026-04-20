# API Surface

Base URL: `/api/v1`

## Auth
- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`

## App Data
- `GET /app/dashboard`

## Scanning
- `POST /scanning/run`
- `POST /scanning/start` (alias)
- `PATCH /scanning/{scan_id}/status` (`reviewed` transition)
- `GET /scanning/kpi/summary`

## Vulnerabilities
- `GET /vulnerabilities`
- `GET /vulnerabilities/{vuln_id}`
- `GET /vulnerabilities/reports/summary`
- `PATCH /vulnerabilities/{vuln_id}/workflow` (`open|triaged|fixed|accepted_risk|false_positive`)

## Phase 1 Scan/Finding Data Enhancements
- Scan request supports `profile` (`quick|standard|deep`), `baseline_scan_id`, and `suppression_keys`.
- Findings now include `confidence`, `reason_code`, `owasp_category`, `cwe_id`, `dedupe_key`, and suppression metadata.
- Scan lifecycle states include `queued`, `running`, `completed`, `failed`, `reviewed`.
- Audit log scaffolding captures auth, scan lifecycle, and finding workflow actions.
