.PHONY: up down logs test test-backend test-frontend lint seed

up:            ## Start the full stack (http://localhost:8080)
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f backend

seed:          ## Load the fictional demo dataset into the running stack
	docker compose exec backend python -m app.seed

test: test-backend test-frontend

test-backend:
	cd backend && ruff check . && pytest

test-frontend:
	cd frontend && npm run typecheck && npm test && npm run build
