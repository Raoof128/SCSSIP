# Quick Start Guide

Get the SBOM Security Platform running in 5 minutes!

## Prerequisites

- Docker & Docker Compose
- Python 3.11+ (for local development)
- 4GB RAM minimum
- Linux, macOS, or Windows with WSL2

---

## Option 1: Docker (Recommended)

### 1. Start Platform

```bash
# Clone repository
git clone https://github.com/Raoof128/SCSSIP.git
cd SCSSIP

# Start all services
make docker-up

# Or manually:
docker-compose up -d
```

### 2. Verify Installation

```bash
# Check health
make health

# Output:
# {
#   "status": "healthy",
#   "service": "SBOM Security Platform",
#   ...
# }
```

### 3. Run Demo

```bash
# Full platform demo
make demo

# Or manually:
bash scripts/demo_platform.sh
```

### 4. Access API

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **API Base**: http://localhost:8000/api/v1

---

## Option 2: Local Development

### 1. Install Dependencies

```bash
# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies
poetry install

# Copy environment file
cp .env.example .env
```

### 2. Start Database & Redis

```bash
# Start only PostgreSQL and Redis
docker-compose up -d postgres redis
```

### 3. Run Migrations

```bash
# Initialize database
poetry run alembic upgrade head
```

### 4. Start API

```bash
# Development mode with auto-reload
poetry run uvicorn api.main:app --reload

# Or using make
make api-dev
```

---

## Quick Operations

### Upload SBOM

```bash
curl -X POST http://localhost:8000/api/v1/sboms/upload \
  -F "file=@examples/sboms/log4shell-cyclonedx.json"

# Response:
# {
#   "sbom_id": 1,
#   "name": "vulnerable-web-app",
#   "components_count": 5
# }
```

### List SBOMs

```bash
curl http://localhost:8000/api/v1/sboms/ | python3 -m json.tool
```

### Validate SLSA Compliance

```bash
curl http://localhost:8000/api/v1/compliance/1/slsa | python3 -m json.tool
```

### Generate Report

```bash
curl http://localhost:8000/api/v1/compliance/1/report > report.html
xdg-open report.html
```

---

## Example Workflow: Log4Shell Detection

```bash
# 1. Upload vulnerable SBOM
SBOM_ID=$(curl -s -X POST http://localhost:8000/api/v1/sboms/upload \
  -F "file=@examples/sboms/log4shell-cyclonedx.json" | \
  grep -o '"sbom_id":[0-9]*' | cut -d':' -f2)

echo "Uploaded SBOM ID: $SBOM_ID"

# 2. Get SBOM details
curl http://localhost:8000/api/v1/sboms/$SBOM_ID | python3 -m json.tool

# 3. Correlate vulnerabilities (requires NVD API)
# Get first component ID
COMPONENT_ID=$(curl -s http://localhost:8000/api/v1/sboms/$SBOM_ID/components | \
  grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)

curl -X POST http://localhost:8000/api/v1/vulnerabilities/correlate/$COMPONENT_ID

# 4. Calculate risk score
curl -X POST http://localhost:8000/api/v1/risk/score/$SBOM_ID | python3 -m json.tool

# 5. Validate compliance
curl http://localhost:8000/api/v1/compliance/$SBOM_ID/slsa | python3 -m json.tool
curl http://localhost:8000/api/v1/compliance/$SBOM_ID/ntia | python3 -m json.tool

# 6. Generate HTML report
curl http://localhost:8000/api/v1/compliance/$SBOM_ID/report > report.html
```

---

## Troubleshooting

### Port 8000 Already in Use

```bash
# Change port in docker-compose.yml
ports:
  - "8080:8000"  # Use port 8080 instead

# Or in .env
API_PORT=8080
```

### Database Connection Issues

```bash
# Check PostgreSQL is running
docker-compose ps postgres

# View logs
docker-compose logs postgres

# Restart database
docker-compose restart postgres
```

### API Not Starting

```bash
# Check logs
docker-compose logs api

# Common issues:
# 1. Database not ready -> Wait 10 seconds and retry
# 2. Port conflict -> Change port in docker-compose.yml
# 3. Migration needed -> Run: make migrate
```

### Out of Memory

```bash
# Reduce container memory limits in docker-compose.yml
services:
  api:
    deploy:
      resources:
        limits:
          memory: 512M  # Reduce from 1G
```

---

## Useful Commands

```bash
# Make commands
make help              # Show all available commands
make test              # Run tests
make lint              # Check code quality
make format            # Format code
make demo              # Run platform demo
make docker-logs       # View API logs
make db-shell          # Open database shell
make redis-cli         # Open Redis CLI
make api-docs          # Open Swagger UI
make clean             # Clean generated files

# Docker commands
docker-compose up -d            # Start services
docker-compose down             # Stop services
docker-compose logs -f api      # Follow API logs
docker-compose exec api bash    # Shell into API container
docker-compose restart api      # Restart API

# Database commands
make migrate                            # Run migrations
make db-shell                           # PostgreSQL shell
docker-compose exec postgres psql -U sbom_user -d sbom_db

# Testing commands
make test                     # Run all tests
make test-integration         # Integration tests only
poetry run pytest tests/unit/test_cyclonedx_parser.py -v
```

---

## Next Steps

1. **Explore API**: http://localhost:8000/docs
2. **Upload Your SBOM**: Use real SBOMs from your projects
3. **Configure Vulnerability Feeds**: Add NVD API key in .env
4. **Deploy to Production**: See [deployment guide](docs/DEPLOYMENT.md)
5. **CI/CD Integration**: GitHub Actions workflow in `.github/workflows/`

---

## Environment Variables

Key variables in `.env`:

```bash
# Required
DATABASE_URL=postgresql://sbom_user:sbom_pass@postgres:5432/sbom_db
REDIS_URL=redis://redis:6379/0

# Optional (improves vulnerability correlation)
NVD_API_KEY=your_nvd_api_key_here
GITHUB_TOKEN=your_github_token_here

# Configuration
DEBUG=False
MAX_SBOM_SIZE_MB=50
MAX_COMPONENTS_PER_SBOM=50000
```

---

## Support

- **Issues**: https://github.com/Raoof128/SCSSIP/issues
- **Documentation**: See README.md and docs/
- **API Docs**: http://localhost:8000/docs (when running)

---

**Platform Status**: ✅ Production Ready - All 5 Phases Complete
