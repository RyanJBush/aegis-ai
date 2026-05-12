# Resume Bullets — Obsidian

University of Maryland student studying Information Science and Electrical Engineering with a Business minor.

- Built Obsidian, an educational local security-scanning project with a FastAPI backend, React/TypeScript frontend, and Python scanning engine.
- Implemented a registry-driven scanner (`build_default_registry`) with profile levels (`quick`, `standard`, `deep`) to control rule depth during scans.
- Wrote parsing/detection logic for SQLi, XSS, insecure headers, auth misconfiguration, access-control flags, insecure config defaults, and secret-leak indicators.
- Added structured finding metadata (severity, confidence, OWASP category, CWE ID, remediation, secure examples, dedupe key) to support triage-style reporting.
- Built a CLI workflow (`scripts/scan.py`) supporting table output, JSON mode, stdin/file inputs, and severity-based gating with `--fail-on` exit behavior.
- Integrated scan-related APIs and vulnerability workflow endpoints in FastAPI for dashboard-style review and remediation tracking.
- Added practical developer documentation (architecture, runbooks, screenshot guide, and portfolio preview) to keep claims aligned with implemented features.
