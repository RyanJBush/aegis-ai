# Obsidian Demo Runbook

A 10-minute portfolio demo of Obsidian. Use this for recruiter walkthroughs,
interview screen-shares, or your own dry runs.

> ⚠️ **Safe-use:** Demo against bundled sample inputs, your own systems, or
> systems you have explicit written authorization to test. See
> [`../ETHICS.md`](../ETHICS.md).

---

## Option A — 2-minute CLI demo (no Docker, no DB)

Fastest path. Good for asynchronous screen recordings.

```bash
pip install -r backend/requirements.txt

# Table output
python scripts/scan.py data/samples/sqli_payload.txt

# JSON output, deep profile
python scripts/scan.py --profile deep --json data/samples/insecure_config.yaml

# CI-style policy gate
python scripts/scan.py --fail-on high data/samples/sqli_payload.txt ; echo "exit=$?"
```

Talking points:

- Severity, OWASP category, CWE ID, and evidence are all in the row.
- `--fail-on high` exits non-zero — this is exactly what blocks a PR in CI.
- Three profiles (`quick / standard / deep`) trade speed for depth.

---

## Option B — Full-stack walkthrough

### 1. Start the stack

```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
make up
```

- Frontend: `http://localhost:3000`
- Backend API docs: `http://localhost:8000/docs`

### 2. Seed a demo analyst account

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"analyst@example.com","password":"StrongPassw0rd!","role":"security_analyst"}'
```

### 3. Authenticate in the UI

- Open `http://localhost:3000/login`.
- Sign in as `analyst@example.com`.

### 4. Demo script flow

1. **Threat Overview** (`/`)
   - Show KPI posture cards and recent findings.
2. **Scan Ops** (`/scanning`)
   - Run an immediate scan with a SQLi/XSS sample payload.
   - Queue a scan and refresh the job state.
3. **Scan Results** (`/scan-results`)
   - Select a scan and export JSON + SARIF reports.
   - Load the remediation checklist and suppression keys.
4. **Vulnerability Detail** (`/vulnerabilities/:id`)
   - Show the evidence panel and workflow fields.
   - Update status/owner/notes, add a comment, file a risk-acceptance.
5. **Governance** (`/governance`)
   - Show audit events and scanner rule history.

### 5. Safe demo payload guidance

Use only **local, synthetic** payloads. Do **not** target real production
systems.

Example payload:

```text
' OR 1=1 -- <script>alert(1)</script>
```

The bundled samples in `data/samples/` are designed for this — they are
intentionally vulnerable inputs, not real exploits aimed at any service.

### 6. Common troubleshooting

- **401/403 on API requests** — verify the login role is `security_analyst`
  or `admin`.
- **Backend tests fail with missing `httpx`** — install backend dependencies
  from `backend/requirements.txt`.
- **Frontend lint fails** — run `npm install` in `frontend/` to ensure all
  ESLint plugins/configs are present.
- **Postgres connection refused** — confirm the Docker Compose `db` service
  is up (`docker compose ps`) and that `POSTGRES_*` values in
  `backend/.env` match.

---

## Recording tips

- Record at 1920×1080 with browser zoom at 100% so SARIF/JSON output is
  readable.
- Capture both the **UI flow** (Option B) and a **CLI run** (Option A) — the
  CLI sells the "fits in CI" story in seconds.
- Place captures under `docs/screenshots/` and reference them from
  `README.md`. Capture guidance lives in
  [`screenshots/README.md`](screenshots/README.md).
