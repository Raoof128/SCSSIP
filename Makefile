.PHONY: help install test lint format docker-up docker-down demo clean

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install dependencies with Poetry
	poetry install

test: ## Run tests with coverage
	poetry run pytest -v

test-integration: ## Run integration tests only
	poetry run pytest tests/integration/ -v

lint: ## Run linters (black, ruff, mypy)
	poetry run black --check src api tests
	poetry run ruff check src api tests
	poetry run mypy src --ignore-missing-imports || true

format: ## Format code with black
	poetry run black src api tests

docker-up: ## Start Docker containers
	docker-compose up -d
	@echo "Waiting for services to be ready..."
	@sleep 5
	@echo "Services started! API: http://localhost:8000"

docker-down: ## Stop Docker containers
	docker-compose down

docker-logs: ## View Docker logs
	docker-compose logs -f api

demo: docker-up ## Run platform demo
	@sleep 3
	@echo "Running platform demo..."
	@bash scripts/demo_platform.sh examples/sboms/log4shell-cyclonedx.json

parse-sbom: ## Parse SBOM file (usage: make parse-sbom FILE=path/to/sbom.json)
	poetry run python scripts/parse_sbom.py $(FILE) -v

clean: ## Clean generated files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name htmlcov -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	find . -type f -name '.coverage' -delete

migrate: ## Run database migrations
	docker-compose --profile migration run migrations

api-docs: docker-up ## Open API documentation
	@echo "Opening API docs at http://localhost:8000/docs"
	@sleep 2
	@python3 -m webbrowser http://localhost:8000/docs 2>/dev/null || true

db-shell: ## Open database shell
	docker-compose exec postgres psql -U sbom_user -d sbom_db

redis-cli: ## Open Redis CLI
	docker-compose exec redis redis-cli

logs-api: ## Tail API logs
	docker-compose logs -f api

logs-db: ## Tail database logs
	docker-compose logs -f postgres

build: ## Build Docker image
	docker-compose build

rebuild: ## Rebuild Docker image from scratch
	docker-compose build --no-cache

health: ## Check API health
	@curl -s http://localhost:8000/health | python3 -m json.tool

info: ## Get platform info
	@curl -s http://localhost:8000/api/v1/info | python3 -m json.tool

k8s-deploy: ## Deploy to Kubernetes
	kubectl apply -f k8s/base/

k8s-delete: ## Delete from Kubernetes
	kubectl delete -f k8s/base/

k8s-status: ## Check Kubernetes deployment status
	kubectl get pods,svc,ingress -l app=sbom-platform
