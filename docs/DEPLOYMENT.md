# Deployment Guide

Complete guide for deploying the Advanced Threat Hunting Platform to production.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Local Development](#local-development)
3. [Docker Deployment](#docker-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [AWS Deployment](#aws-deployment)
6. [Configuration](#configuration)
7. [Monitoring](#monitoring)
8. [Security](#security)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

- **CPU**: 8+ cores recommended
- **RAM**: 16GB minimum, 32GB recommended
- **Storage**: 100GB+ SSD for data and models
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+), macOS, Windows WSL2

### Software Dependencies

- Python 3.10+
- Docker 20.10+
- Docker Compose 2.0+
- Git

---

## Local Development

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/threat-hunting-platform.git
cd threat-hunting-platform
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 5. Start Infrastructure

```bash
docker-compose up -d postgres redis kafka
```

### 6. Initialize Database

```bash
# Run migrations
python src/main.py init-db
```

### 7. Run Application

```bash
# Start API server
python src/main.py serve --host 0.0.0.0 --port 8000

# Or use uvicorn directly
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

### 8. Access Application

- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9091

---

## Docker Deployment

### Full Stack Deployment

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Stop and remove volumes (careful - deletes data!)
docker-compose down -v
```

### Production Docker Compose

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  threat-hunting-api:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      APP_ENV: production
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      API_SECRET_KEY: ${API_SECRET_KEY}
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
    restart: always
```

```bash
docker-compose -f docker-compose.prod.yml up -d
```

---

## Kubernetes Deployment

### 1. Create Namespace

```bash
kubectl create namespace threat-hunting
```

### 2. Deploy Database

```yaml
# k8s/postgres-deployment.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: threat-hunting
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: timescale/timescaledb:latest-pg15
        env:
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
  - metadata:
      name: postgres-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 100Gi
```

### 3. Deploy Application

```yaml
# k8s/app-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: threat-hunting-api
  namespace: threat-hunting
spec:
  replicas: 3
  selector:
    matchLabels:
      app: threat-hunting-api
  template:
    metadata:
      labels:
        app: threat-hunting-api
    spec:
      containers:
      - name: api
        image: youracr.azurecr.io/threat-hunting-platform:latest
        ports:
        - containerPort: 8000
        env:
        - name: APP_ENV
          value: "production"
        - name: POSTGRES_HOST
          value: "postgres"
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
          limits:
            memory: "4Gi"
            cpu: "2"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
```

### 4. Deploy Service

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: threat-hunting-api
  namespace: threat-hunting
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 8000
  selector:
    app: threat-hunting-api
```

### 5. Apply Configurations

```bash
kubectl apply -f k8s/
```

---

## AWS Deployment

### Using AWS ECS

1. **Create ECR Repository**

```bash
aws ecr create-repository --repository-name threat-hunting-platform
```

2. **Build and Push Image**

```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com

# Build image
docker build -t threat-hunting-platform .

# Tag and push
docker tag threat-hunting-platform:latest YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/threat-hunting-platform:latest
docker push YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/threat-hunting-platform:latest
```

3. **Create ECS Task Definition**

```json
{
  "family": "threat-hunting-platform",
  "containerDefinitions": [
    {
      "name": "api",
      "image": "YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/threat-hunting-platform:latest",
      "memory": 4096,
      "cpu": 2048,
      "essential": true,
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "APP_ENV", "value": "production"}
      ]
    }
  ]
}
```

---

## Configuration

### Environment Variables

```bash
# Application
APP_ENV=production
APP_HOST=0.0.0.0
APP_PORT=8000
LOG_LEVEL=INFO

# Database
POSTGRES_HOST=your-db.region.rds.amazonaws.com
POSTGRES_PASSWORD=secure_password

# Security
API_SECRET_KEY=generate_with_openssl_rand_base64_32

# Scaling
MAX_WORKERS=8
BATCH_SIZE=1000
```

### Configuration Files

**Production Config** (`config/production.yaml`):

```yaml
app:
  environment: production
  debug: false
  max_workers: 8

database:
  postgres:
    pool_size: 20
    max_overflow: 40

analytics:
  models:
    isolation_forest:
      n_estimators: 200
    autoencoder:
      epochs: 50

performance:
  batch_processing:
    batch_size: 1000
    worker_threads: 8
```

---

## Monitoring

### Prometheus Metrics

Access Prometheus at `http://localhost:9091/targets`

**Key Metrics:**
- `threat_hunting_events_processed_total`: Total events processed
- `threat_hunting_anomalies_detected_total`: Total anomalies
- `threat_hunting_detection_latency_seconds`: Detection latency
- `threat_hunting_api_requests_total`: API request count

### Grafana Dashboards

1. Access Grafana: `http://localhost:3000`
2. Login: `admin/admin`
3. Import dashboard from `docker/grafana/dashboards/`

### Health Checks

```bash
# API health
curl http://localhost:8000/health

# Component health
curl http://localhost:8000/api/v1/health/components
```

---

## Security

### 1. Generate Secure Keys

```bash
# API secret key
openssl rand -base64 32

# Database password
openssl rand -base64 24
```

### 2. Enable HTTPS

Use nginx or load balancer for TLS termination:

```nginx
server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 3. Firewall Rules

```bash
# Allow only necessary ports
ufw allow 22/tcp   # SSH
ufw allow 443/tcp  # HTTPS
ufw enable
```

### 4. Security Scanning

```bash
# Run Bandit security scan
bandit -r src/ -f json -o security-report.json

# Scan Docker image
trivy image threat-hunting-platform:latest
```

---

## Troubleshooting

### Database Connection Issues

```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Test connection
psql -h localhost -U threat_hunter -d threat_hunting

# View logs
docker-compose logs postgres
```

### High Memory Usage

```bash
# Check container stats
docker stats

# Reduce batch size in config
# config/production.yaml
performance:
  batch_processing:
    batch_size: 500  # Reduce from 1000
```

### Model Training Failures

```bash
# Check available disk space
df -h

# Increase training timeout
# In code or config
training:
  timeout_minutes: 120
```

### API Performance Issues

```bash
# Check Prometheus metrics
curl http://localhost:9091/metrics | grep latency

# Increase workers
APP_PORT=8000 uvicorn src.api.main:app --workers 8
```

---

## Backup & Recovery

### Database Backup

```bash
# Create backup
docker exec postgres pg_dump -U threat_hunter threat_hunting > backup.sql

# Restore backup
docker exec -i postgres psql -U threat_hunter threat_hunting < backup.sql
```

### Model Backup

```bash
# Backup trained models
tar -czf models-backup.tar.gz models/trained/

# Restore models
tar -xzf models-backup.tar.gz
```

---

## Performance Tuning

### Database Optimization

```sql
-- Analyze tables
ANALYZE security_events;
ANALYZE anomalies;

-- Vacuum
VACUUM ANALYZE;
```

### Application Tuning

```yaml
# config/production.yaml
performance:
  batch_processing:
    batch_size: 2000  # Increase for higher throughput
    worker_threads: 16  # Match CPU cores

  caching:
    enabled: true
    ttl_seconds: 3600
    max_size_mb: 1024
```

---

## Support

For issues and support:
- **Documentation**: https://docs.example.com
- **Issues**: https://github.com/yourusername/threat-hunting-platform/issues
- **Email**: support@example.com
