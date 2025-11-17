# System Architecture

## Table of Contents
- [Overview](#overview)
- [High-Level Architecture](#high-level-architecture)
- [Component Design](#component-design)
- [Data Flow](#data-flow)
- [Database Schema](#database-schema)
- [Technology Stack](#technology-stack)
- [Design Decisions](#design-decisions)
- [Security Architecture](#security-architecture)
- [Scalability & Performance](#scalability--performance)

---

## Overview

The SBOM Intelligence Platform is a production-grade system for analyzing software supply chain security. It follows a layered architecture pattern with clear separation of concerns between presentation, business logic, and data persistence layers.

### Key Characteristics
- **Asynchronous Processing**: Non-blocking I/O for vulnerability feed queries
- **Modular Design**: Each component is independently testable and deployable
- **Database-First**: PostgreSQL as source of truth with Redis caching
- **API-Driven**: RESTful API for all operations, enabling CI/CD integration
- **Container-Native**: Docker-first deployment with Kubernetes orchestration

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      External Clients & Users                        │
│               (CI/CD Pipelines, Security Teams, Dashboards)          │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ HTTPS (TLS 1.3)
                             ↓
┌─────────────────────────────────────────────────────────────────────┐
│                       API Gateway / Load Balancer                    │
│                    (nginx, Traefik, AWS ALB, etc.)                   │
│              Rate Limiting │ TLS Termination │ CORS                  │
└────────────────────────────┬─────────────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────────────┐
│                          API Layer (FastAPI)                         │
│  ┌────────────┬────────────┬────────────┬────────────┬────────────┐ │
│  │   SBOM     │  Component │ Vuln       │   Risk     │ Compliance │ │
│  │  Router    │  Router    │ Router     │  Router    │   Router   │ │
│  └────────────┴────────────┴────────────┴────────────┴────────────┘ │
│           OpenAPI/Swagger │ Pydantic Validation │ CORS               │
└────────────────────────────┬─────────────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────────────┐
│                        Business Logic Layer                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ SBOM Ingestion   │  │Vuln Correlation  │  │  Risk Scoring    │  │
│  │ • Parser Factory │  │ • Multi-Feed     │  │  • Multi-Factor  │  │
│  │ • CycloneDX      │  │ • CPE/PURL Match │  │  • EPSS + CVSS   │  │
│  │ • SPDX           │  │ • Deduplication  │  │  • License Risk  │  │
│  │ • Validation     │  │ • Async Queries  │  │  • Dep Depth     │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
│                                                                       │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │  Compliance      │  │  Report Gen      │  │  Common Utils    │  │
│  │  • SLSA L1-L3    │  │  • HTML Reports  │  │  • Config        │  │
│  │  • NTIA          │  │  • Executive Sum │  │  • Exceptions    │  │
│  │  • Validation    │  │  • Remediation   │  │  • Enums         │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
└────────────────────────────┬─────────────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────────────┐
│                         Data Access Layer                            │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │  SQLAlchemy ORM  │  │   Redis Client   │  │  HTTP Clients    │  │
│  │  • Models        │  │  • Cache         │  │  • NVD API       │  │
│  │  • Repositories  │  │  • Rate Limit    │  │  • OSV API       │  │
│  │  • Migrations    │  │  • Sessions      │  │  • GitHub API    │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
└────────────────────────────┬─────────────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────────────┐
│                        Data Persistence Layer                        │
│  ┌───────────────────────────────┐  ┌────────────────────────────┐  │
│  │      PostgreSQL 16            │  │       Redis 7              │  │
│  │  • SBOMs                      │  │  • API Response Cache      │  │
│  │  • Components                 │  │  • Rate Limit Counters     │  │
│  │  • Vulnerabilities            │  │  • Session Storage         │  │
│  │  • Licenses                   │  │  • Background Tasks        │  │
│  │  • Risk Assessments           │  │                            │  │
│  └───────────────────────────────┘  └────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Component Design

### 1. SBOM Ingestion Module

**Purpose**: Parse and validate SBOM files in multiple formats

**Components**:
- `ParserFactory`: Factory pattern for creating format-specific parsers
- `CycloneDXParser`: Handles CycloneDX 1.4-1.6 format
- `SPDXParser`: Handles SPDX 2.2-3.0 format
- `ParsedSBOM`: Standardized internal representation

**Design Pattern**: Factory + Strategy Pattern

**Key Features**:
- Format auto-detection via JSON schema validation
- Dependency graph construction using BFS traversal
- License risk assessment based on SPDX license database
- Component hash verification (SHA256, SHA512, SHA1, MD5)

**Flow**:
```
SBOM File → Validation → Parser Selection → Parsing →
Dependency Graph → License Analysis → Database Storage
```

### 2. Vulnerability Correlation Module

**Purpose**: Query multiple vulnerability feeds and correlate with SBOM components

**Components**:
- `NVDClient`: NVD API 2.0 integration with rate limiting
- `OSVClient`: Open Source Vulnerabilities API
- `GitHubClient`: GitHub Security Advisory API
- `EPSSClient`: EPSS exploit probability scores
- `VulnerabilityMatcher`: CPE/PURL matching engine
- `CorrelationService`: Orchestrates multi-feed queries

**Design Pattern**: Client + Service Pattern with Async/Await

**Matching Strategies**:
1. **CPE Matching**: Exact and fuzzy CPE string comparison
2. **PURL Matching**: Package URL ecosystem mapping
3. **Name+Version Matching**: Fallback for components without identifiers

**Deduplication Logic**:
- Prefer NVD data (authoritative source)
- Merge data from multiple sources
- Deduplicate by CVE ID

**Performance Optimization**:
- Concurrent API queries using `asyncio.gather()`
- Rate limiting with exponential backoff
- Redis caching of vulnerability data (TTL: 24 hours)

### 3. Risk Scoring Module

**Purpose**: Calculate multi-factor risk scores for components and SBOMs

**Algorithm**:
```
Risk Score = (
    VulnScore × 0.40 +      # Vulnerability severity (CVSS + EPSS)
    LicenseScore × 0.20 +    # License risk (copyleft, legal issues)
    SigningScore × 0.20 +    # Signature/provenance verification
    MaintainerScore × 0.10 + # Maintainer reputation
    DepthScore × 0.10        # Dependency depth (transitive risk)
)

Range: 0-10
Levels: CRITICAL (8-10), HIGH (6-8), MEDIUM (4-6), LOW (2-4), MINIMAL (0-2)
```

**Vulnerability Scoring**:
- CVSS Base Score (0-10): Weighted by exploitability
- EPSS Score (0-1): Probability of exploitation in next 30 days
- Severity aggregation: Critical > High > Medium > Low

**License Scoring**:
- Copyleft licenses: Higher risk for commercial use
- Permissive licenses: Lower risk (MIT, Apache-2.0)
- Unknown/Custom licenses: Highest risk

### 4. Compliance Validation Module

**Purpose**: Validate SBOMs against industry frameworks

**SLSA Framework (Levels 0-3)**:

| Level | Requirements | Validation |
|-------|-------------|------------|
| 0 | No guarantees | Baseline |
| 1 | Build provenance documented | Timestamp, supplier present |
| 2 | Tamper-resistant artifacts | Digital signatures verified |
| 3 | Non-falsifiable provenance | Strong crypto, build service |

**NTIA Minimum Elements**:
- 7 Required Fields: Supplier, Component Name, Version, Unique ID, Dependencies, Author, Timestamp
- Coverage Threshold: ≥95% of components must have all fields
- Dependency Graph: Must be complete and traversable

### 5. REST API Module

**Endpoints**:

**SBOM Management**:
- `POST /api/v1/sboms/upload` - Upload and parse SBOM
- `GET /api/v1/sboms/{id}` - Retrieve SBOM details
- `GET /api/v1/sboms` - List all SBOMs
- `GET /api/v1/sboms/{id}/components` - Get component tree
- `DELETE /api/v1/sboms/{id}` - Delete SBOM

**Vulnerability Analysis**:
- `POST /api/v1/vulnerabilities/correlate/{sbom_id}` - Run correlation
- `GET /api/v1/vulnerabilities/{sbom_id}` - Get vulnerabilities
- `GET /api/v1/vulnerabilities/{id}` - Get specific CVE details

**Risk Assessment**:
- `POST /api/v1/risk/score/{sbom_id}` - Calculate risk
- `GET /api/v1/risk/{sbom_id}` - Get risk assessment

**Compliance**:
- `GET /api/v1/compliance/{sbom_id}/slsa` - SLSA validation
- `GET /api/v1/compliance/{sbom_id}/ntia` - NTIA validation
- `GET /api/v1/compliance/{sbom_id}/report` - HTML report

**Authentication**: Currently none (add OAuth2 for production)

---

## Data Flow

### SBOM Upload & Analysis Flow

```
┌─────────┐
│  User   │
│ Upload  │
│  SBOM   │
└────┬────┘
     │
     ↓
┌────────────────┐
│ File Validation│
│ • Size < 10MB  │
│ • Valid JSON   │
└────┬───────────┘
     │
     ↓
┌────────────────┐
│ Format Detect  │
│ CycloneDX/SPDX │
└────┬───────────┘
     │
     ↓
┌────────────────┐
│ Parse & Extract│
│ • Components   │
│ • Licenses     │
│ • Dependencies │
└────┬───────────┘
     │
     ↓
┌────────────────┐
│ Store in DB    │
│ PostgreSQL     │
└────┬───────────┘
     │
     ↓
┌────────────────┐
│ Async Jobs     │
│ • Vuln Lookup  │────┐
│ • Risk Score   │    │
│ • Compliance   │    │
└────┬───────────┘    │
     │                │
     │    ┌───────────▼────────┐
     │    │ External APIs      │
     │    │ • NVD, OSV, GitHub │
     │    │ • EPSS             │
     │    └───────────┬────────┘
     │                │
     ↓                ↓
┌────────────────────────┐
│  Results Aggregation   │
│  • Deduplication       │
│  • Score Calculation   │
└────┬───────────────────┘
     │
     ↓
┌────────────────┐
│  Update DB     │
│  • Vulns       │
│  • Risk Scores │
│  • Compliance  │
└────┬───────────┘
     │
     ↓
┌────────────────┐
│ Return Results │
│  to User (API) │
└────────────────┘
```

---

## Database Schema

### Entity Relationship Diagram

```
┌──────────────┐      ┌──────────────────┐      ┌─────────────────┐
│    SBOMs     │──┬──→│ SBOM_Components  │←──┬──│   Components    │
├──────────────┤  │   ├──────────────────┤   │  ├─────────────────┤
│ id (PK)      │  │   │ id (PK)          │   │  │ id (PK)         │
│ bom_ref      │  │   │ sbom_id (FK)     │   │  │ name            │
│ name         │  │   │ component_id (FK)│   │  │ version         │
│ format       │  │   │ dependency_depth │   │  │ purl            │
│ spec_version │  │   │ risk_score       │   │  │ cpe             │
│ scan_status  │  │   │ vuln_count       │   │  │ type            │
│ risk_score   │  │   │ is_direct        │   │  │ description     │
│ slsa_level   │  │   │ parent_comp_id   │   │  │ supplier        │
│ ntia_comp    │  │   └──────────────────┘   │  └─────────────────┘
└──────────────┘  │                           │           │
                  │                           │           │
                  │   ┌──────────────────┐   │           │
                  └──→│ComponentVulns    │←──┘           │
                      │  (M:N Junction)  │               │
                      ├──────────────────┤               │
                      │ component_id (FK)│               │
                      │ vuln_id (FK)     │               │
                      │ confidence       │               │
                      │ source           │               │
                      └──────────────────┘               │
                               │                         │
                               ↓                         ↓
                      ┌──────────────────┐   ┌──────────────────┐
                      │Vulnerabilities   │   │ComponentHashes   │
                      ├──────────────────┤   ├──────────────────┤
                      │ id (PK)          │   │ id (PK)          │
                      │ cve_id (UNIQUE)  │   │ component_id (FK)│
                      │ vuln_id (UNIQUE) │   │ algorithm        │
                      │ cvss_score       │   │ hash_value       │
                      │ severity         │   └──────────────────┘
                      │ epss_score       │
                      │ published_date   │   ┌──────────────────┐
                      │ source           │   │ Licenses         │
                      └──────────────────┘   ├──────────────────┤
                                             │ id (PK)          │
                      ┌──────────────────┐   │ spdx_id (UNIQUE) │
                      │VulnReferences    │   │ name             │
                      ├──────────────────┤   │ risk_level       │
                      │ id (PK)          │   │ is_osi_approved  │
                      │ vuln_id (FK)     │   │ is_copyleft      │
                      │ url              │   └──────────────────┘
                      │ source           │            │
                      │ type             │            │
                      └──────────────────┘            ↓
                                             ┌──────────────────┐
                                             │ComponentLicenses │
                                             │   (M:N Junction) │
                                             ├──────────────────┤
                                             │ component_id (FK)│
                                             │ license_id (FK)  │
                                             │ expression       │
                                             └──────────────────┘
```

### Indexing Strategy

**Performance-Critical Indexes**:
- `idx_component_name_version` - Component lookup by name+version
- `idx_component_purl` - PURL-based queries
- `idx_component_cpe` - CPE-based vulnerability matching
- `idx_vuln_cve_id` - CVE ID lookups
- `idx_vuln_severity` - Severity-based filtering
- `idx_sbom_status_uploaded` - SBOM processing queue

**Rationale**:
- 80% of queries involve component lookups by identifier
- Vulnerability correlation requires fast CPE/PURL matching
- SBOM listing sorted by upload time needs composite index

---

## Technology Stack

### Core Technologies

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| **API Framework** | FastAPI | 0.109+ | High-performance async API |
| **Database** | PostgreSQL | 16 | Relational data, JSONB support |
| **Cache** | Redis | 7 | API caching, rate limiting |
| **ORM** | SQLAlchemy | 2.0 | Database abstraction |
| **Validation** | Pydantic | 2.x | Request/response validation |
| **Testing** | pytest | 7.4+ | Unit & integration tests |
| **Container** | Docker | 24.0+ | Containerization |
| **Orchestration** | Kubernetes | 1.28+ | Production deployment |

### Python Libraries

**SBOM Parsing**:
- `cyclonedx-python-lib` - CycloneDX parsing
- `spdx-tools` - SPDX parsing
- `packageurl-python` - PURL handling
- `license-expression` - License parsing

**HTTP Clients**:
- `httpx` - Async HTTP client
- `aiofiles` - Async file I/O

**Development Tools**:
- `black` - Code formatting
- `ruff` - Fast linting
- `mypy` - Type checking
- `poetry` - Dependency management

---

## Design Decisions

### ADR-001: Async-First API Design

**Decision**: Use FastAPI with async/await for all I/O operations

**Rationale**:
- Vulnerability feed queries are I/O-bound (10+ API calls per SBOM)
- Async processing allows concurrent queries → 10x faster
- Non-blocking I/O prevents request timeout during long operations

**Trade-offs**:
- More complex error handling
- Requires understanding of async patterns
- Background tasks need job queue (future enhancement)

### ADR-002: PostgreSQL over NoSQL

**Decision**: Use PostgreSQL with JSONB fields

**Rationale**:
- Relational data model fits SBOM structure (components, licenses, vulns)
- ACID transactions ensure data consistency
- JSONB provides flexibility for raw SBOM storage
- Strong query performance with proper indexing

**Trade-offs**:
- Vertical scaling limits (mitigated with read replicas)
- More complex schema migrations

### ADR-003: Multi-Feed Aggregation

**Decision**: Query NVD, OSV, and GitHub Advisory APIs

**Rationale**:
- NVD alone has ~2-week lag for new CVEs
- OSV covers more ecosystems (npm, PyPI, Maven, etc.)
- GitHub Advisory has early disclosure for popular projects
- Triangulation improves accuracy

**Trade-offs**:
- 3x API calls = slower processing
- More complex deduplication logic
- Higher rate limit concerns

### ADR-004: Separation of Concerns

**Decision**: Layered architecture (API → Service → Data)

**Rationale**:
- Testability: Each layer can be tested independently
- Maintainability: Business logic isolated from HTTP concerns
- Flexibility: Swap implementations without breaking contracts

**Trade-offs**:
- More boilerplate code
- Slight performance overhead from abstraction layers

---

## Security Architecture

### Authentication & Authorization

**Current**: None (designed for internal use)

**Production Recommendations**:
1. **OAuth2 with JWT**: Use FastAPI's OAuth2PasswordBearer
2. **API Keys**: For service-to-service communication
3. **RBAC**: Role-based access (Admin, Analyst, Read-Only)

### Input Validation

- **File Upload**: Size limit (10MB), type validation (JSON)
- **SBOM Parsing**: JSON schema validation before processing
- **API Requests**: Pydantic models enforce type safety
- **SQL Injection**: Parameterized queries via SQLAlchemy ORM

### Secrets Management

- **Environment Variables**: `.env` for local development
- **Production**: AWS Secrets Manager, HashiCorp Vault, or Kubernetes Secrets
- **API Keys**: NVD, GitHub tokens stored securely

### Network Security

- **TLS**: HTTPS only in production
- **CORS**: Configured for allowed origins
- **Rate Limiting**: Protect against abuse (future enhancement)

---

## Scalability & Performance

### Horizontal Scaling

**API Layer**:
- Stateless design → Multiple replicas behind load balancer
- Session data in Redis (shared state)
- No in-memory caching (use Redis for consistency)

**Database Layer**:
- PostgreSQL read replicas for query scaling
- Connection pooling (asyncpg with 20-50 connections)
- Write scaling: Partitioning by SBOM upload date

### Performance Targets

| Operation | Target | Current |
|-----------|--------|---------|
| SBOM Upload | < 2s (50 components) | ~1.5s |
| Vuln Correlation | < 10s (50 components) | ~8s |
| Risk Calculation | < 1s | ~500ms |
| API Response | < 200ms (p95) | ~150ms |

### Bottlenecks

1. **External APIs**: NVD rate limit (10/min) → Use caching
2. **Database Writes**: Bulk insert with SQLAlchemy Core
3. **Large SBOMs**: Stream processing for 1000+ components

### Caching Strategy

- **Vulnerability Data**: Redis cache, 24h TTL
- **SBOM Metadata**: No caching (always fresh)
- **API Responses**: Cache GET requests, 5min TTL

---

## Deployment Architecture

### Docker Compose (Development)

```
┌─────────────┐
│   nginx     │ (reverse proxy)
└──────┬──────┘
       │
┌──────▼──────┐
│  FastAPI    │ × 3 replicas
└──────┬──────┘
       │
    ┌──┴──┐
┌───▼──┐  └───▼────┐
│ PG   │  │ Redis  │
└──────┘  └────────┘
```

### Kubernetes (Production)

```
┌──────────────────┐
│   Ingress        │ (TLS termination, routing)
│  (nginx/Traefik) │
└────────┬─────────┘
         │
┌────────▼─────────┐
│   Service        │
│  (ClusterIP)     │
└────────┬─────────┘
         │
    ┌────┴────┐
┌───▼───┐ ┌──▼────┐
│ Pod 1 │ │ Pod 2 │ (API replicas)
└───┬───┘ └──┬────┘
    │        │
┌───▼────────▼───┐
│  StatefulSet   │
│  PostgreSQL    │
└────────────────┘
```

**Scaling Rules**:
- HPA (Horizontal Pod Autoscaler): Scale at 70% CPU
- Min replicas: 2, Max replicas: 10
- Resource requests: 500m CPU, 512Mi memory

---

**Version**: 1.0
**Last Updated**: 2025-11-16
**Status**: Current
