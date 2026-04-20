# Aegis AI Architecture (MVP)

- FastAPI API exposes auth, app data, scan, and vulnerability endpoints.
- PostgreSQL stores users, app_data, scans, and vulnerabilities.
- JWT bearer auth secures endpoints with role-based authorization.
- Scan service performs rule-based detection and optional LLM-powered explanation.
- React frontend consumes API and displays dashboard, scan results, and vulnerability detail views.
