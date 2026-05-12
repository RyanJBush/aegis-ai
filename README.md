# Obsidian — Secure Application Platform and Vulnerability Scanner

Obsidian is an **educational, local-first AppSec platform** that combines a FastAPI backend, React frontend, and a rule-based vulnerability scanner for developer security workflows.

> **Scope and safety:** Use this project only on systems you own, local lab targets, or systems where you have explicit written authorization. Obsidian is not intended for unauthorized testing and is not production security software.

## What Obsidian does today

- Runs **pattern-based security scans** against text/snippet/config inputs.
- Tags findings with **severity, OWASP category, and CWE IDs**.
- Exports results as **JSON and SARIF**.
- Provides a **CLI** with policy gating via `--fail-on <severity>` for CI/CD pipelines.
- Provides backend endpoints and a frontend dashboard for scan workflows.

## What Obsidian does *not* claim

Obsidian is intentionally framed as a portfolio and educational tool. It **does not** replace:

- commercial or enterprise **SAST**,
- runtime/traffic-focused **DAST**,
- instrumentation-driven **IAST**,
- authorized **penetration testing**, or
- a professional **security review**.

Use it as a learning platform and a lightweight guardrail in local development—not as sole security assurance.

## Responsible use and authorization

Before scanning any target, confirm one of the following is true:

1. You own the target system, or
2. The target is a local/test environment created for security exercises, or
3. You have explicit written authorization to test.

See [ETHICS.md](ETHICS.md) and [SECURITY.md](SECURITY.md) for policy and disclosure expectations.

## Implemented capabilities snapshot

| Area | Implemented in repo |
|---|---|
| Scanner | Rule-registry scanner with profile gating (`quick`, `standard`, `deep`) |
| Security taxonomy | OWASP Top 10 + CWE tagging on implemented rules |
| Reporting | JSON + SARIF report generation |
| CLI | Local scanner runner with fail-on severity gate |
| API | FastAPI routes for auth, scanning, findings, observability |
| CI/CD | Lint/type/test pipeline and CLI gate integration path |

For details of OWASP mapping coverage and known gaps, see [docs/owasp-mapping.md](docs/owasp-mapping.md).

## Quick local demo (CLI)

```bash
pip install -r backend/requirements.txt
python scripts/scan.py data/samples/sqli_payload.txt
python scripts/scan.py --json data/samples/insecure_config.yaml
python scripts/scan.py --fail-on high data/samples/sqli_payload.txt ; echo "exit=$?"
```

## Documentation index

- [Architecture](docs/architecture.md)
- [API docs](docs/api.md)
- [Demo runbook](docs/demo-runbook.md)
- [Resume bullets](docs/resume-bullets.md)
- [Screenshot guide](docs/screenshots/README.md)
- [Ethics policy](ETHICS.md)
- [Security policy](SECURITY.md)
