# Aegis AI Monorepo

Security-focused monorepo scaffold for:
- FastAPI backend
- React frontend
- PostgreSQL
- JWT authentication + RBAC
- Detection pipeline for SQLi/XSS patterns
- Dockerized local environment + GitHub Actions CI

## Repository Structure

```text
backend/     FastAPI app (routers, models, services, tests)
frontend/    React app (layouts, pages, API service placeholders)
docs/        Architecture and API docs
```

## Backend Security Capabilities (Implemented)
- JWT-based register/login/me flow.
- RBAC roles: `admin`, `analyst`, `viewer`.
- Secure auth input constraints (email + password length policy).
- Scan pipeline that evaluates payloads using SQLi/XSS detection rules.
- Vulnerability persistence and reporting summary by severity/rule.
- Basic logging for account creation, login events, and scans.

## Quick Start

### 1) Environment files
```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```

### 2) Run with Docker
```bash
make up
```

Services:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

### 3) Run locally without Docker
Backend:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn app.main:app --app-dir backend --reload
```

Frontend:
```bash
cd frontend
npm install
npm run dev
```

### 4) Authenticate before using protected UI routes
Most UI pages call protected API endpoints. Register and login from the API first, then sign in from `/login` in the web UI.

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"analyst@example.com","password":"StrongPassw0rd!","role":"security_analyst"}'
```

## Example API Flow
```bash
# Register analyst
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"analyst@example.com","password":"StrongPassw0rd!","role":"analyst"}'

# Login
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"analyst@example.com","password":"StrongPassw0rd!"}' | jq -r .access_token)

# Run scan
curl -X POST http://localhost:8000/api/v1/scanning/run \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://app.example.com/login","payload":"\" OR 1=1 -- <script>alert(1)</script>"}'
```

## Security Notes
- Replace default JWT secret and all credentials before production use.
- Add token refresh/revocation and account lockout controls.
- Add Alembic migrations and audit logging.
- Expand detection coverage and tune false-positive handling.


## Frontend Security Dashboard Pages
- Dashboard (`/`): posture metrics + vulnerability table + scan history.
- App Interface (`/app-interface`): payload input UI for scan execution workflow.
- Scan Results (`/scan-results`): historical scan statuses and detected findings.
- Vulnerability Detail (`/vulnerabilities/:id`): deep technical breakdown and remediation guidance.

## Notes
- The frontend TypeScript app is the supported runtime entrypoint (`src/main.tsx`).

## Quality Gates (Phase 5)

```bash
# run lint + tests/build checks similar to CI
make ci-check
```

## Demo Readiness

- Demo runbook: `docs/demo-runbook.md`
- Recommended walkthrough order:
  1. Dashboard
  2. Scan Ops
  3. Scan Results (JSON/SARIF exports + remediation checklist)
  4. Vulnerability Detail workflow
  5. Governance (audit logs + rule history)
