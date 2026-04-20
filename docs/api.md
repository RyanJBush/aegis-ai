# API Surface

Base URL: `/api/v1`

## Auth
- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`

## App Data
- `GET /app/dashboard`

## Scanning
- `POST /scanning/run`
- `POST /scanning/start` (alias)

## Vulnerabilities
- `GET /vulnerabilities`
- `GET /vulnerabilities/{vuln_id}`
- `GET /vulnerabilities/reports/summary`
