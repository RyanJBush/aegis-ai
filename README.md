# Aegis AI

A production-style monorepo for a secure web application and AI-assisted vulnerability scanner.

## Stack

- **Backend:** FastAPI, SQLAlchemy, PostgreSQL, JWT auth + RBAC
- **Frontend:** React, Vite, Tailwind CSS
- **Security:** Input validation, rate limiting, secure headers
- **Infra:** Docker, docker-compose, GitHub Actions
- **Quality:** pytest, ruff, eslint, prettier

## Repository layout

- `/backend` FastAPI API and tests
- `/frontend` React web app
- `/docs` project docs
- root infra and contributor files

## Quick start

```bash
docker-compose up --build
```

Or run locally:

```bash
make install
make lint
make test
make run-backend
# in another shell
make run-frontend
```
