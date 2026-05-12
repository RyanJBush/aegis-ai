# Obsidian Architecture

Obsidian is a full-stack educational AppSec platform: a FastAPI + React
application with JWT/RBAC, a rule-based vulnerability scanner mapped to
OWASP Top 10, and a CLI suitable for CI/CD policy gating. This document
describes how the pieces fit together. It is intentionally scoped to what is
actually implemented in this repository — see *Limitations* at the bottom.

## Monorepo Layout

- `backend/` — FastAPI API with auth, scan pipeline, detection rules, and reporting.
- `frontend/` — React + Vite + TypeScript dashboard for AppSec operations.
- `scripts/scan.py` — Standalone CLI wrapper around the scanner engine (no DB required).
- `data/samples/` — Intentionally insecure sample inputs for demos and tests.
- `data/reports/` — Frozen example scan output.
- `docs/` — Architecture, API, OWASP mapping, demo runbook, resume bullets.

## Request Flow (High-Level)

1. Client (React dashboard or `curl`) calls a FastAPI route with a `Bearer` JWT.
2. The dependency layer validates the JWT signature, expiry, role claim, and
   workspace claim (`wid`), then enforces the route's RBAC policy.
3. Scan-creating routes hand the payload to the **scanner engine**, which
   runs the active rule registry against the input and produces findings.
4. Findings are tagged with severity, confidence, OWASP category, CWE ID,
   and a stable dedupe key, then persisted with the parent scan record.
5. Reporting endpoints (`/reports/json`, `/reports/sarif`,
   `/remediation-checklist`, `/policy-gate`) read from this persisted state.

## Multi-Tenant Workspace Model

- `workspaces` table is the top-level tenant boundary.
- `users`, `scans`, and `vulnerabilities` carry `workspace_id`.
- Access tokens include a `wid` claim (workspace id).
- The API dependency layer validates workspace context and blocks
  cross-workspace requests.
- An `X-Workspace-ID` header is optional and, when present, must match the
  token's workspace context.

## Security Baseline

- JWT authentication with signed access tokens and rotating refresh tokens.
- RBAC guards across four roles: `admin`, `security_analyst`, `developer`,
  `viewer`.
- Password hashing (bcrypt), password policy enforcement, account lockout,
  and per-endpoint auth rate limiting.
- Security-headers middleware (`CSP`, `X-Frame-Options`, `nosniff`,
  `no-store` cache control) and request-ID propagation for traceability.

## Scan + Finding Workflow

- Modular **rule registry** scanner with OWASP/CWE mapping, severity,
  per-finding confidence, and stable dedupe keys.
- Three detection profiles: `quick`, `standard`, `deep`.
- Scan lifecycle endpoints and baseline diffing.
- Queue/job abstraction with background-task execution and failure-reason
  telemetry.
- Finding workflow states, comments, risk-acceptance records, and timeline
  events.

## DevSecOps + Reporting

- Policy-gate endpoint (`/scanning/{scan_id}/policy-gate`) and CLI flag
  (`scripts/scan.py --fail-on <severity>`) for CI pass/fail evaluation.
- Suppression export endpoint for baseline management.
- JSON and SARIF report bundles for pipeline integration.
- Optional critical-finding webhook alert hook (`ALERT_WEBHOOK_URL`).
- Workspace-scoped pagination/sorting for scan and vulnerability listings.

## Health and Operability

- `GET /health` — liveness endpoint.
- `GET /ready` — readiness endpoint with a live database probe.

## Deployment

- Docker Compose for the local stack (frontend, backend, Postgres).
- GitHub Actions CI runs backend lint + typecheck + tests and the frontend
  lint + build on every push/PR (`.github/workflows/ci.yml`).

## AI-Assisted Analysis

- Deterministic AI-style summarization service for scan executive summaries
  and per-finding insights (`backend/app/services/ai_analysis_service.py`).
- Clusters findings by OWASP category and rule key to reduce triage noise.
- Emits explanation provenance from scanner evidence, rule keys, and OWASP
  / CWE mappings — no external LLM call is required.

## Observability and Governance

- Audit-log query API (`/observability/audit-logs`) with filtered, paginated
  retrieval for AppSec operations.
- Scan performance metrics summary (`/observability/scan-metrics`) for
  dashboards and SLO tracking.
- Scanner rule-change history API (`/observability/rule-history`) for
  governance and change review.

## DevSecOps Scanner Expansion

- Snippet/file scanning APIs (`/scanning/devsecops/snippet`,
  `/scanning/devsecops/upload`) for inline code/config content in CI and
  developer workflows.
- Dedicated secret/token leakage and config-audit rules in the scanner
  registry.
- Remediation-checklist generator (`/scanning/{scan_id}/remediation-checklist`)
  that drives developer fix workflows.

## Limitations

- Detection uses **static regex pattern matching only** — both false
  positives and false negatives are expected.
- OWASP A04 (Insecure Design) and A09 (Logging/Monitoring) are architectural
  concerns and are out of scope for static input scanning.
- OWASP A06 (Vulnerable Components) is **not** covered — no SBOM ingestion
  or CVE lookup yet.
- The platform is **not** production-hardened: default secrets in
  `.env.example`, intentionally vulnerable demo endpoints, no production
  rate-limit tuning.
- This system is **not** a substitute for professional SAST / DAST / IAST
  tools or authorized penetration testing. It is intended for
  local/owned/authorized test systems only — see [`../ETHICS.md`](../ETHICS.md).
