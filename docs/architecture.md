# Aegis AI Architecture

## Monorepo Layout
- `backend/`: FastAPI API with auth, scan pipeline, detection rules, and reporting.
- `frontend/`: React + Vite dashboard for AppSec operations.
- `docs/`: Operational and architecture docs.

## Multi-Tenant Workspace Model (Phase 5)
- `workspaces` table introduced as top-level tenant boundary.
- `users`, `scans`, and `vulnerabilities` carry `workspace_id`.
- Access tokens include `wid` claim (workspace id).
- API dependency layer validates workspace context and blocks cross-workspace requests.
- `X-Workspace-ID` header is optional and must match token workspace context.

## Security Baseline
- JWT authentication with signed access tokens and rotating refresh tokens.
- RBAC guards (`admin`, `security_analyst`, `developer`, `viewer`).
- Password hashing/policy, lockout, and auth endpoint rate limiting.
- Security headers middleware (`CSP`, `X-Frame-Options`, `nosniff`, `no-store`) and request IDs.

## Scan + Finding Workflow
- Modular rule registry scanner with OWASP/CWE mapping, confidence, severity, and dedupe keys.
- Scan lifecycle and baseline diffing.
- Queue/job abstraction with background-task execution and failure reason telemetry.
- Finding workflow states + comments, risk acceptance records, and timeline events.

## DevSecOps + Reporting
- Policy gate endpoint for CI pass/fail evaluation.
- Suppression export endpoint for baseline management.
- JSON/SARIF report bundles for pipeline integration.
- Critical finding webhook alert hook (`ALERT_WEBHOOK_URL`).
- Workspace-scoped pagination/sorting for scan and vulnerability list views.

## Health and Operability
- `/health` liveness endpoint.
- `/ready` readiness endpoint with live database probe.

## Deployment
- Docker Compose for local stack (frontend, backend, postgres).
- CI runs backend tests and frontend build on pushes/PRs.


## AI-Assisted Analysis (Phase 6)
- Deterministic AI-style summarization service for scan executive summaries and finding insights.
- Clusters findings by OWASP category and rule key to reduce triage noise.
- Emits explanation provenance from scanner evidence, rule keys, OWASP, and CWE mappings.


## Observability and Governance (Phase 7)
- Added observability API surface for audit-log queries and scan metric summaries.
- Added rule-change event persistence + history endpoints for scanner governance.
- Supports filtered, paginated audit review flows for AppSec operations.


## DevSecOps Scanner Expansion (Phase 8)
- Added snippet/file scanning APIs for code/config content in CI and developer workflows.
- Added dedicated secret/token leakage and config audit rules in scanner registry.
- Added remediation checklist generator for developers to drive fix workflows.
