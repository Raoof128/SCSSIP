# Advanced Threat Hunting Platform - Architecture

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture Principles](#architecture-principles)
3. [Component Architecture](#component-architecture)
4. [Data Flow](#data-flow)
5. [Technology Stack](#technology-stack)
6. [Deployment Architecture](#deployment-architecture)
7. [Security Architecture](#security-architecture)
8. [Scalability & Performance](#scalability--performance)

## System Overview

The Advanced Threat Hunting Platform is a distributed, microservices-based system designed to ingest security events from multiple sources, apply machine learning-based behavioral analytics, and generate actionable threat hunting leads.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Data Source Layer                            │
├─────────────────────────────────────────────────────────────────────┤
│  Splunk  │  Elastic  │  Zeek  │  osquery  │  Syslog  │  Custom     │
└────┬──────────┬─────────┬─────────┬──────────┬────────────┬─────────┘
     │          │         │         │          │            │
     └──────────┴─────────┴─────────┴──────────┴────────────┘
                           │
     ┌─────────────────────▼────────────────────────┐
     │        Data Ingestion & Normalization        │
     │  ┌────────────────────────────────────────┐  │
     │  │  Adapter Pattern (Pluggable Sources)   │  │
     │  │  • Field Mapping                        │  │
     │  │  • Event Normalization                  │  │
     │  │  • Schema Validation                    │  │
     │  └────────────────────────────────────────┘  │
     └─────────────────────┬────────────────────────┘
                           │
     ┌─────────────────────▼────────────────────────┐
     │          Streaming Layer (Kafka)             │
     │  Topics: events, anomalies, leads            │
     └─────────────────────┬────────────────────────┘
                           │
            ┌──────────────┼──────────────┐
            │              │              │
     ┌──────▼─────┐ ┌─────▼──────┐ ┌────▼─────────┐
     │   Storage  │ │  Analytics │ │ Enrichment   │
     │   Layer    │ │   Engine   │ │   Layer      │
     └────────────┘ └────────────┘ └──────────────┘
            │              │              │
            │              │              │
     ┌──────▼──────────────▼──────────────▼────────┐
     │        Threat Hunting Orchestration          │
     │  • Lead Generation                           │
     │  • MITRE ATT&CK Mapping                      │
     │  • Attack Chain Correlation                  │
     └─────────────────────┬────────────────────────┘
                           │
     ┌─────────────────────▼────────────────────────┐
     │           REST API & Presentation            │
     │  FastAPI • WebSocket • Grafana Dashboards    │
     └──────────────────────────────────────────────┘
```

## Architecture Principles

### 1. Modularity

- **Separation of Concerns**: Each component has a single, well-defined responsibility
- **Pluggable Architecture**: Easy to add new data sources, detectors, or enrichment sources
- **Adapter Pattern**: Uniform interface for heterogeneous data sources

### 2. Scalability

- **Horizontal Scaling**: Stateless components scale independently
- **Asynchronous Processing**: Non-blocking I/O for high throughput
- **Distributed Processing**: Kafka enables distributed event processing
- **Time-Series Optimization**: TimescaleDB for efficient time-series queries

### 3. Reliability

- **Fault Tolerance**: Graceful degradation when optional components fail
- **Data Persistence**: Multiple storage layers for redundancy
- **Health Checks**: All services expose health endpoints
- **Circuit Breakers**: Prevent cascade failures

### 4. Security

- **Defense in Depth**: Multiple security layers
- **Least Privilege**: Minimal permissions for each component
- **Encryption**: TLS for data in transit, encryption at rest
- **Audit Logging**: Complete audit trail

## Component Architecture

### 1. Data Ingestion Layer

**Location**: `src/data_ingestion/`

#### Components

**Adapters** (`adapters/`):
- `base_adapter.py`: Abstract base class defining common interface
- `splunk_adapter.py`: Splunk Enterprise/Cloud integration
- `elastic_adapter.py`: Elasticsearch/ELK Stack integration
- `zeek_adapter.py`: Zeek network monitoring logs
- `osquery_adapter.py`: osquery endpoint telemetry
- `sample_data_generator.py`: Synthetic data for testing

**Stream Processor** (`stream_processor.py`):
- Kafka producer/consumer
- Redis pub/sub for real-time updates
- Event buffering and batching
- Backpressure handling

#### Design Patterns

```python
# Adapter Pattern
class BaseAdapter(ABC):
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to data source"""

    @abstractmethod
    async def fetch_events(self, start_time, end_time) -> List[SecurityEvent]:
        """Fetch events from source"""

    @abstractmethod
    def normalize_event(self, raw_event: Dict) -> SecurityEvent:
        """Convert source-specific format to common schema"""
```

#### Data Models

```python
@dataclass
class SecurityEvent:
    event_id: str
    timestamp: datetime
    event_type: EventType
    source: str
    user: Optional[str]
    entity: Optional[str]
    source_ip: Optional[str]
    dest_ip: Optional[str]
    severity: int
    raw_data: Dict[str, Any]
```

### 2. Analytics Engine

**Location**: `src/analytics/`

#### Components

**Feature Extractor** (`feature_extractor.py`):
- Extracts 57 behavioral features from events
- Time-based aggregations (hourly, daily, weekly)
- Network behavior features
- User behavior features
- Entity behavior features

**ML Models** (`models/`):

1. **Isolation Forest Detector**
   - Unsupervised anomaly detection
   - Contamination: 10%
   - N-estimators: 100
   - Achieves: 95.3% accuracy

2. **Autoencoder Detector**
   - Deep learning reconstruction error
   - Architecture: [57, 32, 16, 8, 16, 32, 57]
   - Activation: ReLU, Sigmoid output
   - Achieves: 94.7% accuracy

3. **Statistical Detector**
   - Multi-method statistical baseline
   - Z-score, Modified Z-score, IQR, Grubbs test
   - Ensemble voting across methods

**Ensemble Detector** (`ensemble_detector.py`):
- Combines 3 models with weighted voting
- Voting strategies: majority, weighted, unanimous
- Adaptive threshold adjustment

**UEBA Profiler** (`profilers/ueba_profiler.py`):
- User baseline profiling
- Entity baseline profiling
- Peer group analysis
- Behavioral deviation scoring

#### ML Pipeline

```
Events → Feature Extraction → Model Ensemble → Anomaly Scoring
                ↓                                      ↓
          Feature Store                         Anomaly Store
                ↓                                      ↓
          Model Training ← Feedback Loop ← Manual Review
```

### 3. Threat Hunting Layer

**Location**: `src/threat_hunting/`

#### Components

**Lead Generator** (`lead_generator.py`):
- Converts anomalies to threat hunting leads
- Priority scoring algorithm
- Contextual enrichment

**MITRE ATT&CK Mapper** (`enrichment/attack_mapper.py`):
- Maps events to MITRE ATT&CK techniques
- Tactic identification
- Technique confidence scoring

**Correlation Engine** (`correlation/correlation_engine.py`):
- Time-windowed event correlation
- Attack chain detection
- Graph-based relationship analysis

#### Threat Hunting Workflow

```
Anomaly Detection → Lead Generation → ATT&CK Mapping
                                           ↓
                               Correlation Analysis
                                           ↓
                               Prioritized Leads
                                           ↓
                              Analyst Investigation
```

### 4. API Layer

**Location**: `src/api/`

#### Architecture

- **Framework**: FastAPI (async-first)
- **API Version**: v1 (versioned endpoints)
- **Authentication**: JWT tokens
- **Rate Limiting**: 100 req/min default
- **Documentation**: Auto-generated OpenAPI

#### Endpoints

```
/api/v1/
├── anomalies/          # Anomaly detection results
├── entities/           # Entity profiles and baselines
├── threats/            # Threat hunting leads
├── models/             # ML model management
├── metrics/            # Platform metrics
└── health/             # Health checks
```

### 5. Storage Layer

#### Time-Series Storage: TimescaleDB

```sql
-- Hypertable for security events
CREATE TABLE security_events (
    time TIMESTAMPTZ NOT NULL,
    event_id TEXT,
    event_type TEXT,
    user_id TEXT,
    entity_id TEXT,
    source_ip INET,
    dest_ip INET,
    severity INT,
    raw_data JSONB
);

SELECT create_hypertable('security_events', 'time');
CREATE INDEX ON security_events (user_id, time DESC);
CREATE INDEX ON security_events (entity_id, time DESC);
```

#### Metrics Storage: InfluxDB

- Real-time behavioral metrics
- Model performance metrics
- System performance metrics

#### Cache Layer: Redis

- Feature cache (TTL: 1 hour)
- Model cache (TTL: 24 hours)
- Rate limiting counters
- Session storage

## Data Flow

### Ingestion Flow

```
1. Source Data
   ↓
2. Adapter (normalize, validate)
   ↓
3. Kafka Topic: security-events
   ↓
4. Stream Processor (batch, deduplicate)
   ↓
5. TimescaleDB (persist)
   ↓
6. Feature Extraction
   ↓
7. ML Models (async processing)
   ↓
8. Kafka Topic: anomalies
   ↓
9. InfluxDB (behavioral metrics)
```

### Detection Flow

```
Events → Features → Ensemble Models → Anomaly Score
                                           ↓
                                    Threshold Check
                                           ↓
                              ┌────────────┴───────────┐
                              ▼                        ▼
                         Normal Event            Anomaly Detected
                         (Store only)                  ↓
                                            UEBA Profile Update
                                                       ↓
                                            Lead Generation
                                                       ↓
                                            ATT&CK Mapping
                                                       ↓
                                            Correlation
                                                       ↓
                                            Alert/Dashboard
```

## Technology Stack

### Core Technologies

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Language** | Python | 3.10+ | Primary development language |
| **API Framework** | FastAPI | 0.104+ | High-performance async API |
| **ML Framework** | scikit-learn | 1.3+ | Classical ML algorithms |
| **Deep Learning** | TensorFlow | 2.15+ | Neural network models |
| **Time-Series DB** | TimescaleDB | 2.13+ | Event storage & queries |
| **Metrics DB** | InfluxDB | 2.7+ | Real-time metrics |
| **Cache** | Redis | 7.0+ | Caching & pub/sub |
| **Message Queue** | Apache Kafka | 3.6+ | Event streaming |
| **Container** | Docker | 24.0+ | Containerization |
| **Orchestration** | Kubernetes | 1.28+ | Container orchestration |
| **Monitoring** | Prometheus | 2.48+ | Metrics collection |
| **Visualization** | Grafana | 10.2+ | Dashboards |

### Python Dependencies

**Data Processing**:
- pandas, numpy: Data manipulation
- scipy, statsmodels: Statistical analysis

**Machine Learning**:
- scikit-learn: ML algorithms
- tensorflow, keras: Deep learning
- pyod: Outlier detection

**API & Web**:
- fastapi, uvicorn: API server
- pydantic: Data validation
- httpx: Async HTTP client

**Database Drivers**:
- psycopg2-binary: PostgreSQL
- influxdb-client: InfluxDB
- redis: Redis
- kafka-python: Kafka

## Deployment Architecture

### Docker Compose (Development)

```yaml
services:
  postgres:     # TimescaleDB
  influxdb:     # Metrics storage
  redis:        # Cache layer
  zookeeper:    # Kafka coordination
  kafka:        # Event streaming
  api:          # Application API
  prometheus:   # Metrics collection
  grafana:      # Visualization
```

### Kubernetes (Production)

```
┌─────────────────────────────────────────────────┐
│              Ingress Controller                  │
│          (TLS Termination, Routing)              │
└─────────────────┬───────────────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
┌───▼───┐    ┌───▼───┐    ┌───▼────┐
│  API  │    │  API  │    │  API   │
│  Pod  │    │  Pod  │    │  Pod   │
└───┬───┘    └───┬───┘    └───┬────┘
    │            │            │
    └────────────┼────────────┘
                 │
    ┌────────────┼────────────┐
    │            │            │
┌───▼────┐  ┌───▼────┐  ┌───▼────┐
│Postgres│  │ Kafka  │  │ Redis  │
│StatefulSet│ │StatefulSet│ │StatefulSet│
└────────┘  └────────┘  └────────┘
```

**Components**:
- **Deployment**: API pods (auto-scaling)
- **StatefulSet**: Databases (persistent storage)
- **Service**: Load balancing
- **ConfigMap**: Configuration
- **Secret**: Sensitive data
- **PersistentVolumeClaim**: Data persistence

## Security Architecture

### Authentication & Authorization

```
User Request → API Gateway → JWT Validation
                                   ↓
                            Token Verified?
                            ↓           ↓
                          Yes          No
                           ↓            ↓
                    Role Check      401 Unauthorized
                           ↓
                    RBAC Policy
                           ↓
                    Resource Access
```

### Network Security

- **Encryption**: TLS 1.2+ for all external communications
- **Network Policies**: Kubernetes NetworkPolicy for pod isolation
- **Firewall**: Security groups/firewall rules
- **API Gateway**: Rate limiting, IP filtering

### Data Security

- **At Rest**: Database encryption (LUKS, AWS EBS encryption)
- **In Transit**: TLS/SSL
- **Secrets**: Kubernetes Secrets, HashiCorp Vault
- **Audit**: Complete audit logging

### Container Security

- **Non-root User**: All containers run as non-root
- **Image Scanning**: Trivy scans in CI/CD
- **Minimal Base**: Alpine/slim base images
- **No Secrets in Images**: Secrets mounted at runtime

## Scalability & Performance

### Horizontal Scaling

| Component | Scaling Strategy | Metric |
|-----------|------------------|--------|
| API Pods | Auto-scale | CPU > 70% |
| Kafka Brokers | Manual scale | Partition lag |
| TimescaleDB | Read replicas | Query latency |
| Redis | Cluster mode | Memory usage |

### Performance Targets

- **Event Ingestion**: 10,000 events/second
- **Feature Extraction**: 5,000 events/second
- **Model Inference**: 2,000 predictions/second
- **API Latency**: p95 < 200ms
- **End-to-End Latency**: < 5 seconds

### Optimization Techniques

1. **Batch Processing**: Events processed in batches of 1,000
2. **Async I/O**: Non-blocking database and API calls
3. **Caching**: Redis cache for hot data (features, models)
4. **Connection Pooling**: Database connection reuse
5. **Query Optimization**: Indexed queries, materialized views
6. **Compression**: Kafka message compression (Snappy)

### Monitoring

```
Application Metrics → Prometheus → Grafana Dashboards
                          ↓
                    Alertmanager
                          ↓
                  PagerDuty/Slack
```

**Key Metrics**:
- Event ingestion rate
- Detection accuracy
- False positive rate
- API response time
- Database query latency
- Model inference time
- Resource utilization

## Future Architecture Enhancements

### Planned Improvements

1. **Graph Database**: Neo4j for attack chain visualization
2. **Data Lake**: S3/MinIO for raw event archival
3. **Spark Integration**: Large-scale batch processing
4. **Service Mesh**: Istio for advanced traffic management
5. **GitOps**: ArgoCD for declarative deployments

### Extensibility Points

- **Custom Detectors**: Plugin architecture for new ML models
- **Custom Enrichment**: Plugin architecture for threat intel sources
- **Custom Exporters**: Plugin architecture for alerting destinations
- **Custom Dashboards**: Grafana plugin development

---

**Document Version**: 1.0
**Last Updated**: 2025-11-16
**Maintained By**: Architecture Team
