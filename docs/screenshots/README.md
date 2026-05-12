# Screenshots

Place UI captures here and reference them from the root [`README.md`](../../README.md).
Screenshots make the README scannable for recruiters who won't clone and run
the project.

## Recommended shots

| File | View | What it should show |
|---|---|---|
| `01-dashboard.png` | Security dashboard (`/`) | Posture KPIs, recent scans, severity breakdown |
| `02-scan-findings.png` | Scan results (`/scan-results`) | Findings table with severity, OWASP/CWE tags, dedupe keys |
| `03-remediation-checklist.png` | Remediation checklist | Auto-generated developer-facing fix checklist |
| `04-sarif-export.png` | SARIF / JSON export | Report download view or sample SARIF payload |
| `05-api-docs.png` | API docs | FastAPI auto-generated Swagger UI at `/docs` |
| `06-cli-output.png` | CLI scan output | `python scripts/scan.py …` table + JSON modes |

A `06b-cli-fail-on.png` showing the `--fail-on high` non-zero exit is also
useful for the CI/CD policy-gate story.

## Capture guidance

- **Resolution:** capture at 1920×1080 or higher; the README renders well at
  ~1200px wide images.
- **Browser zoom:** 100%; bump to 110% only if text is hard to read.
- **Theme:** pick one (light or dark) and stay consistent across all shots.
- **Redact anything sensitive** — JWTs, real emails, environment values,
  internal URLs. Use the seed analyst account
  (`analyst@example.com`) from the demo runbook.
- **Crop tightly** around the relevant UI region; trim browser chrome
  unless it adds context (e.g. the URL bar showing `/scanning`).
- **PNG, not JPEG**, for UI captures so text stays crisp.

## Referencing from README

Use relative paths so the images render on both GitHub and local previews:

```markdown
![Security dashboard](docs/screenshots/01-dashboard.png)
```

## Safe-use reminder

All captures should be from **local demo data** — bundled sample inputs in
`data/samples/`, or your own seeded analyst account. Never include
screenshots from third-party systems or unauthorized scan targets. See
[`../../ETHICS.md`](../../ETHICS.md).
