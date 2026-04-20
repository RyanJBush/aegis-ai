.PHONY: install install-backend install-frontend lint test run run-backend run-frontend

install: install-backend install-frontend

install-backend:
cd backend && pip install -r requirements-dev.txt

install-frontend:
cd frontend && npm install

lint:
cd backend && ruff check .
cd frontend && npm run lint
cd frontend && npm run format:check

test:
cd backend && pytest -q

run: run-backend run-frontend

run-backend:
cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

run-frontend:
cd frontend && npm run dev -- --host 0.0.0.0 --port 5173
