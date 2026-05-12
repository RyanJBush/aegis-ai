# Obsidian Architecture

Obsidian is an educational secure-application platform and vulnerability scanner designed for **local and authorized testing contexts**.

## Purpose and boundaries

Obsidian demonstrates AppSec engineering patterns (authn/authz, scanner design, reporting, CI/CD integration) in a verifiable codebase. It does **not** claim complete vulnerability detection coverage and is **not** a replacement for SAST/DAST/IAST suites, penetration testing, or professional security review.

## High-level components

- **Frontend (`frontend/`)**: React + TypeScript dashboard for scan operations and findings triage.
- **Backend (`backend/`)**: FastAPI service exposing auth, scanning, reporting, and observability routes.
- **Scanner engine (`backend/app/services/scanner_engine.py`)**: Rule registry applying implemented pattern checks.
- **CLI (`scripts/scan.py`)**: Local scanner entrypoint for developer and CI use.
- **Data/docs**: Sample inputs and reference docs under `data/` and `docs/`.

## Data flow

1. User authenticates (JWT access/refresh flow).
2. Request passes RBAC + workspace checks.
3. Scan payload is evaluated by scanner rules that are enabled for a selected profile.
4. Findings are normalized with severity, OWASP, CWE, evidence, and dedupe keys.
5. Results are surfaced via API/UI and can be exported as SARIF/JSON.
6. CI/CD can evaluate scan outcomes via CLI `--fail-on` or policy-gate endpoint.

## Security model (implemented)

- JWT auth with refresh rotation.
- Role-based access control.
- Workspace scoping to reduce cross-tenant data access.
- Security header middleware.
- Audit/observability endpoints for operational traceability.

## OWASP/CWE mapping

OWASP/CWE tags are present only where implemented in scanner rules. Coverage and explicit non-coverage are documented in [`docs/owasp-mapping.md`](owasp-mapping.md).

## CI/CD integration model

- CLI gate: `python scripts/scan.py --fail-on high <target>`.
- API gate: `/scanning/{scan_id}/policy-gate`.
- Pipeline pattern: run scan stage, enforce threshold, fail build on policy breach.

## Safe-use architecture assumptions

- Intended for local, educational, owned, or explicitly authorized targets.
- Not intended for internet-wide reconnaissance or unapproved third-party scanning.
- Operators are responsible for authorization and legal scope validation.

## Known limitations

- Pattern-based detection yields false positives/negatives.
- No claim of complete OWASP or CWE coverage.
- No claim of full runtime behavior analysis typical of DAST/IAST.
- No claim of replacing expert-led penetration testing or formal assessments.
