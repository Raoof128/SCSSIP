# Deployment Guide

## Table of Contents
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Local Development](#local-development)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Production Checklist](#production-checklist)
- [Monitoring & Operations](#monitoring--operations)
- [Troubleshooting](#troubleshooting)
- [Backup & Recovery](#backup--recovery)

---

## Overview

This guide covers deploying the SBOM Security Intelligence Platform across different environments:

- **Development**: Local Python environment or Docker Compose
- **Staging/Testing**: Docker Compose with production-like configuration
- **Production**: Kubernetes cluster with PostgreSQL and Redis

**Deployment Time**:
- Local Development: 5 minutes
- Docker Compose: 10 minutes
- Kubernetes: 30 minutes

---

## Prerequisites

### All Environments

- Git
- Modern terminal (bash, zsh)
- Text editor or IDE

### Local Development

- **Python**: 3.11 or 3.12
- **Poetry**: 1.7.0+ for dependency management
- **PostgreSQL**: 16+
- **Redis**: 7+

Installation:
```bash
# macOS
brew install python@3.11 poetry postgresql@16 redis

# Ubuntu/Debian
sudo apt install python3.11 python3-pip postgresql-16 redis-server
pip install poetry

# Windows (use WSL2)
```

### Docker Deployment

- **Docker**: 24.0+
- **Docker Compose**: 2.20+

```bash
# Verify installation
docker --version
docker compose version
```

### Kubernetes Deployment

- **kubectl**: 1.28+
- **Kubernetes cluster**: 1.28+ (EKS, GKE, AKS, or local with kind/minikube)
- **Helm**: 3.12+ (optional but recommended)

```bash
# Verify cluster access
kubectl cluster-info
kubectl get nodes
```

---

## Local Development

### 1. Clone Repository

```bash
git clone https://github.com/Raoof128/SCSSIP.git
cd SCSSIP
```

### 2. Install Dependencies

```bash
# Install Python dependencies
poetry install

# Activate virtual environment
poetry shell
```

### 3. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings
nano .env
```

**Required Configuration**:
```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/sbom_platform

# Redis
REDIS_URL=redis://localhost:6379/0

# API Keys (optional but recommended)
NVD_API_KEY=your_nvd_api_key_here
GITHUB_TOKEN=your_github_token_here
```

### 4. Setup Database

```bash
# Create database
createdb sbom_platform

# Run migrations
poetry run alembic upgrade head
```

### 5. Start Development Server

```bash
# Start API server with hot reload
poetry run uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# Or use Make
make dev
```

**Access**:
- API: http://localhost:8000
- Swagger Docs: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### 6. Run Tests

```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run specific test file
poetry run pytest tests/unit/test_cyclonedx_parser.py -v
```

---

## Docker Deployment

### Quick Start (Development)

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f api

# Stop all services
docker compose down
```

**Services Started**:
- PostgreSQL (port 5432)
- Redis (port 6379)
- API (port 8000)
- Database migrations (one-time)

### Production-Like Docker Setup

**1. Create production environment file**:

```bash
cp .env.example .env.production
```

**Edit `.env.production`**:
```bash
# Production settings
ENV=production
DEBUG=false
LOG_LEVEL=INFO

# Strong database credentials
DATABASE_URL=postgresql://sbom_admin:STRONG_PASSWORD_HERE@postgres:5432/sbom_platform

# Redis
REDIS_URL=redis://:REDIS_PASSWORD@redis:6379/0

# API Keys
NVD_API_KEY=your_nvd_api_key
GITHUB_TOKEN=your_github_token

# Security
SECRET_KEY=generate_with_openssl_rand_hex_32
ALLOWED_HOSTS=your-domain.com,api.your-domain.com
CORS_ORIGINS=https://your-domain.com

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
```

**2. Create production docker-compose**:

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    env_file: .env.production
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    restart: always
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $$POSTGRES_USER"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    restart: always
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5

  api:
    build:
      context: .
      dockerfile: Dockerfile
    env_file: .env.production
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: always
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - api
    restart: always

volumes:
  postgres_data:
  redis_data:
```

**3. Deploy**:

```bash
# Build and start
docker compose -f docker-compose.prod.yml up -d

# Check health
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs api

# Run migrations
docker compose -f docker-compose.prod.yml exec api alembic upgrade head
```

### Docker Commands Reference

```bash
# View running containers
docker compose ps

# View logs (all services)
docker compose logs -f

# View logs (specific service)
docker compose logs -f api

# Execute command in container
docker compose exec api poetry run pytest

# Restart service
docker compose restart api

# Stop and remove containers
docker compose down

# Stop and remove containers + volumes (WARNING: deletes data)
docker compose down -v

# Update images
docker compose pull
docker compose up -d
```

---

## Kubernetes Deployment

### 1. Prepare Secrets

```bash
# Create namespace
kubectl create namespace sbom-platform

# Create database secret
kubectl create secret generic postgres-credentials \
  --from-literal=username=sbom_admin \
  --from-literal=password=$(openssl rand -base64 32) \
  --from-literal=database=sbom_platform \
  -n sbom-platform

# Create API keys secret
kubectl create secret generic api-keys \
  --from-literal=nvd-api-key=YOUR_NVD_KEY \
  --from-literal=github-token=YOUR_GITHUB_TOKEN \
  -n sbom-platform

# Create Redis password
kubectl create secret generic redis-credentials \
  --from-literal=password=$(openssl rand -base64 32) \
  -n sbom-platform
```

### 2. Deploy PostgreSQL

```bash
# Apply PostgreSQL StatefulSet
kubectl apply -f k8s/base/deployment.yaml -n sbom-platform

# Wait for PostgreSQL to be ready
kubectl wait --for=condition=ready pod -l app=postgres -n sbom-platform --timeout=300s

# Run migrations
kubectl exec -it deployment/sbom-api -n sbom-platform -- alembic upgrade head
```

### 3. Deploy Application

```bash
# Apply all manifests
kubectl apply -f k8s/base/ -n sbom-platform

# Check rollout status
kubectl rollout status deployment/sbom-api -n sbom-platform
kubectl rollout status deployment/redis -n sbom-platform

# Verify pods
kubectl get pods -n sbom-platform
```

### 4. Setup Ingress (with TLS)

```bash
# Install cert-manager (if not already installed)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Apply ingress
kubectl apply -f k8s/base/ingress.yaml -n sbom-platform

# Check certificate provisioning
kubectl get certificate -n sbom-platform
kubectl describe certificate sbom-tls -n sbom-platform
```

### 5. Verify Deployment

```bash
# Check all resources
kubectl get all -n sbom-platform

# Check logs
kubectl logs -f deployment/sbom-api -n sbom-platform

# Test API (port-forward for testing)
kubectl port-forward svc/sbom-api 8000:8000 -n sbom-platform
curl http://localhost:8000/health
```

### Kubernetes Scaling

```bash
# Manual scaling
kubectl scale deployment sbom-api --replicas=5 -n sbom-platform

# Horizontal Pod Autoscaler
kubectl autoscale deployment sbom-api \
  --cpu-percent=70 \
  --min=2 \
  --max=10 \
  -n sbom-platform

# Check HPA status
kubectl get hpa -n sbom-platform
```

### Kubernetes Updates

```bash
# Update image (rolling update)
kubectl set image deployment/sbom-api \
  sbom-api=ghcr.io/raoof128/scssip:v1.2.0 \
  -n sbom-platform

# Check rollout status
kubectl rollout status deployment/sbom-api -n sbom-platform

# Rollback if needed
kubectl rollout undo deployment/sbom-api -n sbom-platform
```

---

## Production Checklist

### Security

- [ ] Change all default passwords
- [ ] Generate strong `SECRET_KEY`
- [ ] Enable TLS/SSL (HTTPS only)
- [ ] Configure CORS with specific origins
- [ ] Implement authentication (OAuth2/API Keys)
- [ ] Enable rate limiting
- [ ] Setup Web Application Firewall (WAF)
- [ ] Regular security scanning (Dependabot, Trivy)
- [ ] Restrict database access (firewall rules)
- [ ] Enable database SSL connections
- [ ] Use secrets manager (AWS Secrets Manager, HashiCorp Vault)

### Database

- [ ] Enable automated backups (daily minimum)
- [ ] Test backup restoration process
- [ ] Configure connection pooling (20-50 connections)
- [ ] Enable query logging (slow queries > 1s)
- [ ] Setup read replicas for scalability
- [ ] Enable PostgreSQL extensions: `pg_stat_statements`, `pg_trgm`
- [ ] Configure autovacuum
- [ ] Monitor disk usage (alert at 75%)

### Application

- [ ] Set `ENV=production`
- [ ] Set `DEBUG=false`
- [ ] Configure logging level (`INFO` or `WARNING`)
- [ ] Setup structured logging (JSON format)
- [ ] Configure log aggregation (ELK, Datadog, Splunk)
- [ ] Enable application metrics (Prometheus)
- [ ] Setup health check monitoring
- [ ] Configure external API timeouts
- [ ] Implement retry logic with exponential backoff

### Infrastructure

- [ ] Setup load balancer (nginx, AWS ALB, Traefik)
- [ ] Configure auto-scaling (HPA in Kubernetes)
- [ ] Setup monitoring (Grafana, Datadog, New Relic)
- [ ] Configure alerts (Slack, PagerDuty)
- [ ] Implement log rotation
- [ ] Setup CDN (if serving static assets)
- [ ] Configure DNS with health checks
- [ ] Document disaster recovery plan

### Compliance

- [ ] Enable audit logging
- [ ] Implement data retention policy
- [ ] Setup access control (RBAC)
- [ ] Document data privacy practices
- [ ] Configure GDPR compliance (if applicable)
- [ ] Enable compliance reporting

---

## Monitoring & Operations

### Health Checks

**Liveness Probe**:
```bash
curl http://localhost:8000/health
# Expected: {"status": "healthy", ...}
```

**Readiness Probe**:
```bash
curl http://localhost:8000/
# Expected: {"name": "SBOM Security Intelligence Platform", ...}
```

### Key Metrics to Monitor

**Application Metrics**:
- Request rate (requests/second)
- Response time (p50, p95, p99)
- Error rate (5xx errors)
- Active connections
- API endpoint latency

**Database Metrics**:
- Connection pool usage
- Query execution time
- Database size
- Index hit rate (should be > 95%)
- Replication lag

**Infrastructure Metrics**:
- CPU usage (alert at 70%)
- Memory usage (alert at 80%)
- Disk I/O
- Network throughput

### Logging

**View logs** (Docker):
```bash
docker compose logs -f api
```

**View logs** (Kubernetes):
```bash
kubectl logs -f deployment/sbom-api -n sbom-platform
```

**Log Levels**:
- `DEBUG`: Development only
- `INFO`: General information (production default)
- `WARNING`: Warning messages
- `ERROR`: Error messages
- `CRITICAL`: Critical failures

---

## Troubleshooting

### API Won't Start

**Symptoms**: Container/pod restarts continuously

**Diagnosis**:
```bash
# Docker
docker compose logs api

# Kubernetes
kubectl describe pod <pod-name> -n sbom-platform
kubectl logs <pod-name> -n sbom-platform
```

**Common Causes**:
1. **Database connection failure**
   - Check DATABASE_URL
   - Verify PostgreSQL is running: `pg_isready`
   - Check network connectivity

2. **Missing environment variables**
   - Verify .env file exists
   - Check all required variables are set

3. **Port already in use**
   - Change port in docker-compose.yml or .env

### Database Connection Errors

**Error**: `could not connect to server`

**Solutions**:
```bash
# Check PostgreSQL is running
docker compose ps postgres

# Check PostgreSQL logs
docker compose logs postgres

# Test connection
psql postgresql://user:password@localhost:5432/sbom_platform -c "SELECT 1;"

# Verify DATABASE_URL in .env
echo $DATABASE_URL
```

### Slow API Responses

**Symptoms**: API takes > 5 seconds to respond

**Diagnosis**:
1. Check external API rate limits (NVD, OSV, GitHub)
2. Check database query performance
3. Check Redis cache hit rate

**Solutions**:
```bash
# Enable query logging
# Add to postgresql.conf:
log_min_duration_statement = 1000  # Log queries > 1s

# Check slow queries
docker compose exec postgres psql -U sbom_user -d sbom_platform \
  -c "SELECT query, calls, total_time FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;"

# Clear Redis cache (if needed)
docker compose exec redis redis-cli FLUSHALL
```

### Out of Memory

**Symptoms**: Container killed, OOMKilled status

**Solutions**:
```yaml
# Increase memory limits in docker-compose.yml
api:
  deploy:
    resources:
      limits:
        memory: 2G
      reservations:
        memory: 1G

# Kubernetes: Update resource limits
resources:
  limits:
    memory: "2Gi"
  requests:
    memory: "1Gi"
```

### Migration Failures

**Error**: `alembic upgrade head` fails

**Solutions**:
```bash
# Check current migration version
poetry run alembic current

# Check migration history
poetry run alembic history

# Downgrade one version
poetry run alembic downgrade -1

# Force to specific version
poetry run alembic upgrade <revision>

# Generate new migration
poetry run alembic revision --autogenerate -m "description"
```

---

## Backup & Recovery

### Database Backup

**Manual Backup** (Docker):
```bash
# Backup to file
docker compose exec postgres pg_dump -U sbom_user sbom_platform > backup_$(date +%Y%m%d_%H%M%S).sql

# Backup with compression
docker compose exec postgres pg_dump -U sbom_user sbom_platform | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz
```

**Automated Backup** (cron job):
```bash
# Add to crontab
0 2 * * * cd /path/to/SCSSIP && docker compose exec -T postgres pg_dump -U sbom_user sbom_platform | gzip > /backups/sbom_$(date +\%Y\%m\%d).sql.gz
```

**Kubernetes Backup**:
```bash
kubectl exec -it statefulset/postgres -n sbom-platform -- pg_dump -U sbom_user sbom_platform > backup.sql
```

### Database Restore

**Restore from Backup**:
```bash
# Stop API
docker compose stop api

# Drop and recreate database
docker compose exec postgres dropdb -U sbom_user sbom_platform
docker compose exec postgres createdb -U sbom_user sbom_platform

# Restore
cat backup.sql | docker compose exec -T postgres psql -U sbom_user sbom_platform

# Or from compressed backup
gunzip -c backup.sql.gz | docker compose exec -T postgres psql -U sbom_user sbom_platform

# Restart API
docker compose start api
```

### Disaster Recovery

**Full System Restore**:

1. **Restore PostgreSQL data**:
```bash
docker compose up -d postgres
# Wait for PostgreSQL to be ready
docker compose exec postgres psql -U sbom_user sbom_platform < backup.sql
```

2. **Verify data**:
```bash
docker compose exec postgres psql -U sbom_user sbom_platform -c "SELECT COUNT(*) FROM sboms;"
```

3. **Start all services**:
```bash
docker compose up -d
```

**Recovery Time Objective (RTO)**: < 1 hour
**Recovery Point Objective (RPO)**: < 24 hours (with daily backups)

---

## Performance Tuning

### PostgreSQL Optimization

```sql
-- postgresql.conf settings for production

# Memory (for 8GB RAM server)
shared_buffers = 2GB
effective_cache_size = 6GB
maintenance_work_mem = 512MB
work_mem = 32MB

# Connections
max_connections = 100

# Query planner
random_page_cost = 1.1  # For SSD storage

# Autovacuum
autovacuum = on
autovacuum_max_workers = 3
```

### API Performance

```python
# .env settings
UVICORN_WORKERS=4  # (2 * CPU cores) + 1
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10
REDIS_POOL_SIZE=10
```

### Caching Strategy

- Vulnerability data: 24 hours TTL
- Component metadata: 1 hour TTL
- API responses (GET): 5 minutes TTL

---

**Last Updated**: 2025-11-16
**Version**: 1.0
