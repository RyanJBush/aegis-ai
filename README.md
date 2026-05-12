# Obsidian — Secure Application Platform and Vulnerability Scanner

> **Educational disclaimer:** Obsidian is a local, educational scanner built for portfolio and learning use. It is **not** a replacement for professional security testing, secure code review, penetration testing, or commercial SAST/DAST platforms.

Obsidian is a project by a **University of Maryland student studying Information Science and Electrical Engineering with a Business minor**. It demonstrates how a rule-based scanner can parse text-like inputs, flag risky patterns, and return structured findings through a CLI and a FastAPI + React interface.

## Summary

Obsidian scans local payload files (or stdin) with regex-based rules and reports matched evidence with:
- Severity and confidence
- OWASP category and CWE identifier
- Suggested remediation and secure example
- JSON output for automation-style consumption

It is intentionally scoped for transparent behavior and interview-friendly demos, not exhaustive coverage.

## What it demonstrates

- Rule registry design and profile-based execution (`quick`, `standard`, `deep`)
- Pattern checks for:
  - Injection payload indicators (SQLi/XSS)
  - Authentication and access-control misconfiguration patterns
  - Security header and configuration hardening issues
  - Secret/token/private-key leakage patterns
- Reporting flows:
  - Human-readable CLI table
  - JSON output (`--json`)
  - Non-zero exit behavior for severity gates (`--fail-on`)
- Full-stack portfolio workflow with backend APIs and frontend findings/governance views

## Tech stack

- **Backend:** Python, FastAPI, SQLAlchemy, Pydantic
- **Frontend:** React, TypeScript, Vite
- **Scanner engine:** Python rule registry (`backend/app/services/scanner_engine.py`)
- **CLI runner:** `scripts/scan.py`
- **Dev/testing:** pytest, Docker Compose

## Architecture

- Architecture walkthrough: [docs/architecture.md](docs/architecture.md)
- OWASP/CWE mapping notes: [docs/owasp-mapping.md](docs/owasp-mapping.md)
- API docs summary: [docs/api.md](docs/api.md)

## Local run instructions

### 1) Install dependencies

```bash
pip install -r backend/requirements.txt
```

### 2) Run a quick sample scan

```bash
python scripts/scan.py data/samples/sqli_payload.txt
```

### 3) Try JSON mode and profile depth

```bash
python scripts/scan.py --json --profile deep data/samples/insecure_config.yaml
```

### 4) Try severity-gate behavior (good for recruiter demos)

```bash
python scripts/scan.py --fail-on high data/samples/sqli_payload.txt
```

If a finding at or above the threshold is present, the command exits with code `1`.

## Demo workflow (recruiter-friendly)

1. Scan a sample file from `data/samples/`.
2. Re-run with `--json` to show structured output.
3. Re-run with `--fail-on high` to show pipeline-style gate behavior.
4. Open the app demo flow from [docs/demo-runbook.md](docs/demo-runbook.md) for dashboard + remediation screens.

## Screenshots

- Screenshot index and capture notes: [docs/screenshots/README.md](docs/screenshots/README.md)
- Portfolio/UI preview page: [docs/preview/index.html](docs/preview/index.html)

## Limitations and future work

### Current limitations
- Regex pattern matching can produce false positives/false negatives.
- Scanner behavior is limited to implemented rules and text evidence patterns.
- It does not perform runtime exploitation, dynamic crawling, or full application threat modeling.
- Findings should be treated as triage signals that need human validation.

### Future improvements
- Expand rule corpus and test fixtures.
- Add richer parser/context awareness to reduce noise.
- Add optional CI wiring examples for local teams.
- Improve rule tuning UX in the frontend.

## Resume bullets

See: [docs/resume-bullets.md](docs/resume-bullets.md)

## License

This project is released under the [MIT License](LICENSE).
