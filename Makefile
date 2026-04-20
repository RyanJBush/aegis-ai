.PHONY: help up down build backend-install frontend-install test lint format

help:
	@echo "Available targets: up down build backend-install frontend-install test lint"

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

test:
	cd backend && pytest

lint:
	cd backend && python -m compileall app
	cd frontend && npm run lint
