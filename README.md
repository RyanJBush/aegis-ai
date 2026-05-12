# Obsidian — Secure Application Platform and Vulnerability Scanner

Portfolio demo for local-first application security scanning workflows built with FastAPI, React, and Python.

⚠️ **Educational tool only.** Obsidian is designed for local, educational, and portfolio demonstration purposes. It is not a replacement for professional SAST, DAST, IAST, penetration testing, or a professional security review.

Obsidian is a portfolio-scale AppSec project focused on transparent, grounded implementation. It demonstrates how scan findings can move from pattern detection to triage-friendly outputs in a full-stack workflow. The project is intentionally scoped for demo use on owned or explicitly authorized targets.

## What this project demonstrates

- Implements a rule-based scanner for text and configuration inputs
- Labels findings with severity plus OWASP/CWE identifiers from implemented rules
- Exports scan results in JSON and SARIF formats
- Provides a CLI with `--fail-on` severity gating behavior
- Exposes backend/frontend flows for scanning, findings review, and governance-style workflow updates

## Tech stack

- **Backend:** FastAPI, SQLAlchemy, Pydantic, Python
- **Frontend:** React, TypeScript, Vite
- **Scanner:** Python rule-registry engine
- **Tooling:** Docker Compose, pytest, CLI runner in `scripts/scan.py`

## Architecture overview

- High-level architecture: [docs/architecture.md](docs/architecture.md)
- OWASP/CWE mapping scope: [docs/owasp-mapping.md](docs/owasp-mapping.md)
- API reference: [docs/api.md](docs/api.md)

## How to run locally

```bash
pip install -r backend/requirements.txt
python scripts/scan.py data/samples/sqli_payload.txt
python scripts/scan.py --json data/samples/insecure_config.yaml
python scripts/scan.py --fail-on high data/samples/sqli_payload.txt
```

For the full stack workflow, see [docs/demo-runbook.md](docs/demo-runbook.md).

## Demo workflow

1. Run a sample scan against files in `data/samples/`
2. Review findings and metadata (severity, OWASP, CWE)
3. Export JSON or SARIF reports
4. Walk through dashboard and remediation-oriented UI views
5. Demonstrate CLI gate behavior with `--fail-on`

## Screenshots / demo

See screenshot index and capture notes: [docs/screenshots/README.md](docs/screenshots/README.md)

Portfolio preview page: [docs/preview/index.html](docs/preview/index.html)

## Limitations and future work

- Obsidian is a demo-scale scanner and does not provide comprehensive vulnerability coverage
- Pattern-based detection can miss context-sensitive or runtime-only issues
- CI integration is not wired as a repository workflow yet; current support is CLI/API patterns that can be integrated externally
- Future work: broader rule coverage, richer validation corpus, and optional integrations for automated pipeline use

## Resume bullets

- [docs/resume-bullets.md](docs/resume-bullets.md)

## License

This project is released under the [MIT License](LICENSE).
