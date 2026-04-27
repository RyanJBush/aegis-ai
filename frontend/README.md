# Aegis AI Frontend

React + TypeScript + Vite dashboard for Aegis AI.

## Local development

```bash
npm install
npm run dev
```

The app expects the backend API at `VITE_API_BASE_URL` (default: `http://localhost:8000/api/v1`).

## Auth flow

- Visit `/login`.
- Use credentials for a registered user (recommended role: `security_analyst` or `admin` for scan actions).
- The access token is stored in local storage and attached as a bearer token for API requests.

## Build

```bash
npm run build
```
