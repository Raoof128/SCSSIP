.PHONY: help install dev-install test lint format clean docker-build docker-up docker-down k8s-deploy k8s-delete run docs

# Variables
PYTHON := python3
PIP := pip3
DOCKER_COMPOSE := docker-compose
KUBECTL := kubectl
PROJECT_NAME := threat-hunting-platform
NAMESPACE := threat-hunting

# Default target
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "Advanced Threat Hunting Platform - Makefile Commands"
	@echo "======================================================"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Installation
install: ## Install production dependencies
	$(PIP) install -r requirements.txt

dev-install: ## Install development dependencies
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-dev.txt || echo "requirements-dev.txt not found, skipping"
	pre-commit install

# Code Quality
lint: ## Run all linters (flake8, mypy, bandit)
	@echo "Running flake8..."
	flake8 src/ tests/ --max-line-length=120 --extend-ignore=E203,W503
	@echo "Running mypy..."
	mypy src/ --config-file=pyproject.toml || true
	@echo "Running bandit..."
	bandit -r src/ -c pyproject.toml

format: ## Format code with black and isort
	@echo "Running isort..."
	isort src/ tests/ --profile black --line-length 120
	@echo "Running black..."
	black src/ tests/ --line-length 120

check-format: ## Check code formatting without making changes
	@echo "Checking isort..."
	isort src/ tests/ --profile black --line-length 120 --check-only
	@echo "Checking black..."
	black src/ tests/ --line-length 120 --check

# Testing
test: ## Run all tests
	pytest tests/ -v

test-unit: ## Run unit tests only
	pytest tests/unit/ -v

test-integration: ## Run integration tests only
	pytest tests/integration/ -v

test-coverage: ## Run tests with coverage report
	pytest tests/ --cov=src --cov-report=html --cov-report=term

test-performance: ## Run performance benchmarks
	pytest tests/performance/ -v -s

# Development
run: ## Run the application locally
	uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

run-cli: ## Run the CLI application
	$(PYTHON) -m src

verify: ## Verify installation and configuration
	$(PYTHON) scripts/verify_installation.py

# Docker
docker-build: ## Build Docker image
	docker build -t $(PROJECT_NAME):latest .

docker-build-no-cache: ## Build Docker image without cache
	docker build --no-cache -t $(PROJECT_NAME):latest .

docker-up: ## Start all services with docker-compose
	$(DOCKER_COMPOSE) up -d

docker-down: ## Stop all services
	$(DOCKER_COMPOSE) down

docker-logs: ## View docker-compose logs
	$(DOCKER_COMPOSE) logs -f

docker-ps: ## Show running containers
	$(DOCKER_COMPOSE) ps

docker-shell: ## Open shell in API container
	$(DOCKER_COMPOSE) exec api /bin/bash

docker-clean: ## Remove all containers, volumes, and images
	$(DOCKER_COMPOSE) down -v --rmi all

# Kubernetes
k8s-create-namespace: ## Create Kubernetes namespace
	$(KUBECTL) create namespace $(NAMESPACE) --dry-run=client -o yaml | $(KUBECTL) apply -f -

k8s-deploy: ## Deploy to Kubernetes
	$(KUBECTL) apply -f k8s/base/ -n $(NAMESPACE)

k8s-delete: ## Delete Kubernetes deployment
	$(KUBECTL) delete -f k8s/base/ -n $(NAMESPACE)

k8s-status: ## Check Kubernetes deployment status
	$(KUBECTL) get all -n $(NAMESPACE)

k8s-logs: ## View application logs in Kubernetes
	$(KUBECTL) logs -f deployment/threat-hunting-api -n $(NAMESPACE)

k8s-port-forward: ## Port forward API service
	$(KUBECTL) port-forward svc/threat-hunting-api 8000:80 -n $(NAMESPACE)

# Database
db-shell: ## Open PostgreSQL shell
	$(DOCKER_COMPOSE) exec postgres psql -U threat_hunter -d threat_hunting

db-migrate: ## Run database migrations (placeholder)
	@echo "Database migration not implemented yet"

db-backup: ## Backup database
	$(DOCKER_COMPOSE) exec postgres pg_dump -U threat_hunter threat_hunting > backup_$$(date +%Y%m%d_%H%M%S).sql

# Data Management
generate-sample-data: ## Generate sample security events
	$(PYTHON) -c "from src.data_ingestion.adapters.sample_data_generator import SampleDataGenerator; \
		gen = SampleDataGenerator(); \
		events = gen.generate_events(1000); \
		print(f'Generated {len(events)} events')"

# Documentation
docs: ## Generate documentation
	@echo "Generating documentation..."
	@echo "API documentation available at: http://localhost:8000/docs (when running)"

docs-serve: ## Serve documentation locally
	@echo "Starting API server for documentation..."
	uvicorn src.api.main:app --host 0.0.0.0 --port 8000

# Examples
run-example-1: ## Run basic usage example
	$(PYTHON) examples/01_basic_usage.py

run-example-2: ## Run API client example
	$(PYTHON) examples/02_api_client.py

run-example-3: ## Run custom detector example
	$(PYTHON) examples/03_custom_detector.py

# Cleaning
clean: ## Clean build artifacts and cache
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -delete
	find . -type d -name '*.egg-info' -exec rm -rf {} + || true
	find . -type d -name '.pytest_cache' -exec rm -rf {} + || true
	find . -type d -name '.mypy_cache' -exec rm -rf {} + || true
	rm -rf build/ dist/ htmlcov/ .coverage

clean-models: ## Clean trained models
	@echo "Warning: This will delete all trained models!"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		find models/trained/ -type f -not -name '.gitkeep' -delete; \
		echo "Models cleaned"; \
	fi

# Security
security-scan: ## Run security scan
	bandit -r src/ -f json -o security-report.json
	@echo "Security scan complete. Report: security-report.json"

dependency-check: ## Check for vulnerable dependencies
	pip-audit || $(PIP) install pip-audit && pip-audit

# Git
git-setup: ## Set up git hooks
	pre-commit install
	@echo "Git hooks installed"

# Complete Setup
setup: dev-install git-setup ## Complete development environment setup
	@echo "Creating .env file from .env.example..."
	@if [ ! -f .env ]; then cp .env.example .env; fi
	@echo ""
	@echo "=========================================="
	@echo "Setup complete!"
	@echo "=========================================="
	@echo "Next steps:"
	@echo "  1. Edit .env with your configuration"
	@echo "  2. Start services: make docker-up"
	@echo "  3. Run tests: make test"
	@echo "  4. Start API: make run"
	@echo "=========================================="

# CI/CD
ci: check-format lint test security-scan ## Run all CI checks

# All-in-one commands
dev: docker-up run ## Start services and run application

fresh-start: docker-down docker-up ## Restart all services fresh

# Production
build-prod: ## Build production Docker image
	docker build -t $(PROJECT_NAME):$$(git describe --tags --always) .
	docker tag $(PROJECT_NAME):$$(git describe --tags --always) $(PROJECT_NAME):latest

deploy-prod: build-prod k8s-deploy ## Build and deploy to production

# Monitoring
logs: ## View all logs
	@echo "=== API Logs ==="
	$(DOCKER_COMPOSE) logs --tail=100 api
	@echo "\n=== Database Logs ==="
	$(DOCKER_COMPOSE) logs --tail=100 postgres

stats: ## Show resource usage statistics
	docker stats $$(docker ps --format "{{.Names}}")

# Utilities
shell: ## Open Python shell with project context
	$(PYTHON) -i -c "from src.api.main import app; \
		from src.analytics.models import *; \
		from src.data_ingestion.adapters import *; \
		print('Threat Hunting Platform shell ready')"

jupyter: ## Start Jupyter notebook
	jupyter notebook

version: ## Show version information
	@echo "Project: $(PROJECT_NAME)"
	@echo "Python: $$($(PYTHON) --version)"
	@echo "Docker: $$(docker --version)"
	@echo "Docker Compose: $$($(DOCKER_COMPOSE) --version)"
	@echo "Kubectl: $$($(KUBECTL) version --client --short)"

# Requirements
requirements-update: ## Update requirements.txt
	pip-compile requirements.in -o requirements.txt || \
	$(PIP) freeze > requirements.txt

requirements-upgrade: ## Upgrade all dependencies
	$(PIP) install --upgrade -r requirements.txt
