# Aegis AI Architecture

## Monorepo Layout
- `backend/`: FastAPI API with auth, scan pipeline, detection rules, and reporting.
- `frontend/`: React + Vite dashboard application (placeholder UI).
- `docs/`: Operational and architecture docs.

## Security Baseline
- JWT authentication with signed access tokens carrying user ID and role claims.
- RBAC enforcement in dependency guards (`admin`, `analyst`, `viewer`).
- Password hashing via bcrypt (`passlib`) and strict auth payload constraints.
- Target input validation to block localhost/private IP scanning requests.

## Detection Rules
- SQL injection patterns (e.g., `UNION SELECT`, tautology + comment signatures).
- XSS patterns (script tags, event handler payloads, javascript URI).

## Data Layer
- SQLAlchemy ORM models for `users`, `scans`, and `vulnerabilities`.
- Vulnerability report generation by severity and rule type.

## Deployment
- Docker Compose for local stack (frontend, backend, postgres).
- CI runs backend tests and frontend build on pushes/PRs.
