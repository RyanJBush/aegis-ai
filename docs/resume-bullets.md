# Resume Bullets — Obsidian (Honest + AppSec-Focused)

Use these for AppSec, backend, security tooling, and CI/CD applications. Keep wording accurate to implemented functionality.

## Core bullets

- Built **Obsidian**, an educational secure-application platform and vulnerability scanner using FastAPI, React, and Python rule-based analysis.
- Implemented scanner findings with **severity, OWASP, and CWE mapping** plus structured evidence for triage workflows.
- Added **SARIF and JSON reporting** to support developer feedback loops and downstream tooling integration.
- Developed a CLI with **policy gating (`--fail-on`)** to support CI/CD pass/fail checks on severity thresholds.
- Implemented backend security controls including JWT auth flows, role-based access checks, and workspace-aware access patterns.
- Documented architecture, API surface, ethical-use policy, and security disclosure policy to keep claims aligned with actual implementation.

## AppSec-focused variants

- Designed a rule-registry scanning pipeline for local code/config payload checks with explicit limitations and OWASP/CWE traceability.
- Built vulnerability workflow endpoints (status/comments/risk acceptance) to model practical remediation and governance processes.
- Added observability endpoints for audit logs, scanner metrics, and rule-history tracking.

## Backend-focused variants

- Built and documented a FastAPI service layer with auth, scanning, reporting, and observability routes.
- Structured scanning and vulnerability services into modular backend components to support maintainable security tooling evolution.

## CI/CD-focused variants

- Integrated scan-threshold gating patterns suitable for CI pipelines using CLI exit codes and API policy checks.
- Produced machine-consumable SARIF/JSON outputs to enable automated security checks in delivery workflows.

## Honesty guardrail

When using these bullets, keep this qualifier in project descriptions:

> “Educational/local scanner for owned or authorized targets; not a replacement for SAST/DAST/IAST, penetration testing, or professional security review.”
