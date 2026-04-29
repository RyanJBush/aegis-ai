# Aegis AI Demo Runbook

This runbook is for a 10-minute portfolio demo of Aegis AI.

## 1. Start stack

```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
make up
```

## 2. Seed a demo analyst account

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"analyst@example.com","password":"StrongPassw0rd!","role":"security_analyst"}'
```

## 3. Authenticate in UI

- Open `http://localhost:3000/login`.
- Sign in as `analyst@example.com`.

## 4. Demo script flow

1. **Threat Overview** (`/`)
   - Show KPI posture cards and recent findings.
2. **Scan Ops** (`/scanning`)
   - Run an immediate scan on a public URL with SQLi/XSS sample payload.
   - Queue a scan and refresh the job state.
3. **Scan Results** (`/scan-results`)
   - Select a scan and export JSON + SARIF reports.
   - Load remediation checklist and suppression keys.
4. **Vulnerability Detail** (`/vulnerabilities/:id`)
   - Show evidence panel and workflow fields.
   - Update status/owner/notes, add comment, submit risk acceptance.
5. **Governance** (`/governance`)
   - Show audit events and scanner rule history.

## 5. Safe demo payload guidance

Use only local, synthetic payloads for demonstration. Do not target real production systems.

Example payload:

```text
' OR 1=1 -- <script>alert(1)</script>
```

## 6. Common troubleshooting

- If API requests fail with 401/403, verify login role is `security_analyst` or `admin`.
- If backend tests fail locally due missing `httpx`, install backend dependencies from `backend/requirements.txt`.
- If frontend linting fails, run `npm install` in `frontend/` to ensure all ESLint plugins/configs are present.
