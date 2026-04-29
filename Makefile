.PHONY: help up down build backend-install frontend-install test test-backend test-frontend lint ci-check

help:
	@echo "Available targets: up down build backend-install frontend-install test test-backend test-frontend lint ci-check"

up:
	docker compose up --build

down:
	docker compose down -v

build:
	docker compose build

backend-install:
	pip install -r backend/requirements.txt

frontend-install:
	cd frontend && npm install

test: test-backend test-frontend

test-backend:
	cd backend && pytest

test-frontend:
	cd frontend && npm run build

lint:
	cd backend && python -m compileall app
	cd frontend && npm run lint

ci-check: lint test
