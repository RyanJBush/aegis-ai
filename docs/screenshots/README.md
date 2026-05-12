# Screenshots

Place UI captures here and reference them from the root [`README.md`](../../README.md).
Screenshots make the README scannable for recruiters who won't clone and run
the project.

## Captured shots

All checklist images below are committed in this directory and referenced
from the root [`README.md`](../../README.md).

| File | View | Status | Source |
|---|---|---|---|
| `01-dashboard.png` | Security dashboard (`/`) | ✅ captured | Live React UI (`http://localhost:5500/`) |
| `02-scan-findings.png` | Scan results (`/scan-results`) | ✅ captured | Live React UI |
| `03-remediation-checklist.png` | Remediation queue (`/remediation`) | ✅ captured | Live React UI |
| `04-sarif-export.png` | SARIF / JSON export | ✅ captured | Renders the bundled `data/reports/sample-scan-report.json` and a SARIF 2.1.0 payload built with the same shape as `ScanningService.build_sarif_report` |
| `05-api-docs.png` | API docs | ✅ captured | Live FastAPI Swagger UI at `/docs` |
| `06-cli-output.png` | CLI scan output | ✅ captured | Real, unedited output of `scripts/scan.py` (table + JSON modes) rendered into a terminal-style page |
| `06b-cli-fail-on.png` | CLI policy gate | ✅ captured | Real `--fail-on high` run; exit code `1` verified against the live CLI |

### Capture environment

- Backend: `uvicorn app.main:app` on port 8765 with Postgres unavailable
  — the app starts cleanly because `main.py` wraps `Base.metadata.create_all`
  in a try/except and logs a warning. DB-backed endpoints return 401/500;
  the React pages fall back to seeded demo data (`frontend/src/services/mockData.ts`)
  and surface a banner saying so. That banner is visible in the dashboard,
  scan-results, and remediation screenshots — it is **not** a render bug, it
  is the app's honest fallback state.
- Frontend: `vite` dev server on port 5500 with `VITE_API_BASE_URL=http://127.0.0.1:8765/api/v1`.
- Screenshot tool: Playwright (Chromium), `device_scale_factor=2`, viewport
  1440×900 for UI pages.
- Swagger UI: captured with `bypass_csp=True` because the app's
  `default-src 'self'` CSP middleware blocks the `cdn.jsdelivr.net` Swagger
  assets in a headless browser. The rendered Swagger is the real one served
  from `/docs`; only the CSP enforcement is relaxed at the client.

### Known blockers / honest caveats

- **No Postgres in the sandbox.** The full backend boots, but auth/scan
  endpoints can't persist anything. The UI screenshots therefore show the
  app's documented "Live API unavailable — showing demo data" fallback
  state. The route, layout, components, KPI cards, severity bar, and
  vulnerability table are all the real production code paths.
- **`04-sarif-export.png` is a split-view payload preview, not a live
  download.** Because the live `/scanning/{id}/reports/sarif` endpoint
  requires an authenticated scan record (no DB available), this image
  composites the bundled `data/reports/sample-scan-report.json` with a
  SARIF 2.1.0 payload generated in the exact shape that
  `ScanningService.build_sarif_report` returns (`backend/app/services/scanning_service.py:393`).
  This is what a recruiter would see if they downloaded the JSON and SARIF
  exports against this scan.
- **`06-cli-output.png` / `06b-cli-fail-on.png` are real CLI output
  rendered into a styled terminal frame.** The text in the screenshots is
  the exact stdout of `python scripts/scan.py …`; the frame around it is
  cosmetic so the README is scannable. `exit=1` was verified against the
  running CLI before the screenshot was rendered.

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
