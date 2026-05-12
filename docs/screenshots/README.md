# Screenshot Documentation — Obsidian

Use this folder for recruiter-facing evidence of implemented UI and workflow behavior.

## Required screenshot set

| File | What to capture | Why it matters |
|---|---|---|
| `01-dashboard.png` | Dashboard posture + severity distribution | Shows AppSec visibility UX |
| `02-scan-findings.png` | Findings list with severity/OWASP/CWE fields | Shows triage data quality |
| `03-remediation-checklist.png` | Remediation checklist view | Shows developer handoff flow |
| `04-sarif-export.png` | SARIF/JSON export evidence | Shows integration-oriented output |
| `05-api-docs.png` | FastAPI `/docs` page | Shows discoverable API contract |
| `06-cli-output.png` | CLI scan command + output | Shows local scanner utility |
| `06b-cli-fail-on.png` | CLI fail-on example with non-zero exit | Shows CI/CD gate behavior |

## Capture rules

- Capture only local/demo data or owned/authorized targets.
- Never include secrets, live tokens, private URLs, or customer data.
- Keep screenshots faithful to the current implemented product state.
- If a screenshot uses mocked/fallback data, label it clearly in this document.

## Suggested capture procedure

1. Start backend and frontend locally.
2. Run a sample scan from `data/samples/`.
3. Capture dashboard, findings, remediation, API docs, and CLI output.
4. Verify naming matches table above.
5. Reference images from `README.md`.

## README image embed format

```md
![Obsidian dashboard](docs/screenshots/01-dashboard.png)
```

## Accuracy note

Screenshots should reinforce the same honesty standard used across docs: educational/local scanning, authorized targets only, and no claim of replacing professional security assessment workflows.
