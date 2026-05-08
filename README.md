![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-61DAFB?style=flat&logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat&logo=typescript&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white)
![CI](https://github.com/RyanJBush/Secure-application-platform-and-vulnerability-scanner/actions/workflows/ci.yml/badge.svg)

# Aegis AI

> A secure full-stack web application with OWASP-aligned protections and an AI-powered vulnerability scanner that detects, classifies, and explains security risks in submitted payloads.

---

## 🎯 What I Built & Why

Most security tutorials show you how to exploit vulnerabilities — Aegis AI is built from the defender's side. I wanted to understand how production security platforms are actually structured: auth hardening, role-based access control, automated scanning pipelines, and audit trails. Key design decisions:

- **JWT + RBAC with 3 roles** (Admin, Analyst, Viewer) — security tooling should itself be secure; every endpoint enforces role-appropriate access
- **SQLi/XSS detection pipeline** — payloads are evaluated against a rule catalog, findings are persisted with severity classification, and summaries are queryable by rule or severity
- **Safe demo endpoints** — intentionally vulnerable simulation routes (isolated from production auth/search logic) let you demonstrate detection workflows without real risk
- **SARIF/JSON export** — scan results are exportable in standard formats for integration into CI/CD pipelines

---

## 📷 Features

- **JWT authentication** — register/login/me flow with secure input constraints
- **RBAC** — Admin, Analyst, and Viewer roles with enforced endpoint permissions
- **Scan pipeline** — evaluates payloads against SQLi/XSS detection rules with severity classification
- **Vulnerability persistence & reporting** — findings grouped by severity and rule, queryable via API
- **SARIF/JSON export** — exportable scan results for CI/CD integration
- **Audit logging** — account creation, login events, and scan activity logged
- **React security dashboard** — posture metrics, vulnerability table, scan history, and remediation workflow
- **Docker Compose** — one-command local stack

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI + SQLAlchemy + PostgreSQL |
| Auth | JWT with RBAC (3 roles) |
| Scanning | Rule-based SQLi/XSS detection pipeline |
| Frontend | React + Vite + TypeScript + Tailwind CSS |
| Infra | Docker Compose + GitHub Actions CI |

---

## 🚀 Quick Start

### Prerequisites
- Docker + Docker Compose
- Python 3.11+
- Node.js 20+

### Docker (Recommended)
```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
make up
# Frontend:         http://localhost:3000
# Backend API docs: http://localhost:8000/docs
```

### Local Development
```bash
# Backend
python -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn app.main:app --app-dir backend --reload

# Frontend
cd frontend && npm install && npm run dev
```

### Example API Flow
```bash
# 1. Register
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"analyst@example.com","password":"StrongPassw0rd!","role":"analyst"}'

# 2. Login and capture token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"analyst@example.com","password":"StrongPassw0rd!"}' | jq -r .access_token)

# 3. Run a scan
curl -X POST http://localhost:8000/api/v1/scanning/run \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://app.example.com/login","payload":"\" OR 1=1 -- <script>alert(1)</script>"}'
```

### Quality Checks
```bash
make ci-check   # lint + tests + build
```

---

## 🗂️ Repository Structure

```
backend/    FastAPI API, auth, RBAC, scan pipeline, vulnerability models, tests
frontend/   React security dashboard (posture metrics, scan ops, vulnerability detail)
docs/       Architecture, API reference, demo runbook
```

---

## 📘 Demo Walkthrough

Recommended order:
1. **Dashboard** — posture KPIs and severity trend charts
2. **Scan Ops** — submit a payload and watch the detection pipeline fire
3. **Scan Results** — JSON/SARIF export and remediation checklist
4. **Vulnerability Detail** — OWASP mapping, safe request/response evidence, remediation workflow
5. **Governance** — audit logs and rule history

Full runbook: `docs/demo-runbook.md`

---

## ⚠️ Security Notes

- Replace the default JWT secret and all credentials before any production use
- Safe demo endpoints (`/login`, `/search`) are controlled simulations isolated from production auth — for testing only
- Add token refresh/revocation and account lockout controls before deploying publicly

---

## 📝 Key Learnings

- Security tooling must itself be secure — designing RBAC for a vulnerability scanner forced me to think carefully about information sensitivity, not just action permissions
- Detection pipelines benefit from persistence and audit trails; a scan result with no history is far less useful than one that shows regression over time
- Exportable results (SARIF/JSON) are what make security tooling usable in real engineering workflows

---

## 📄 License

MIT
