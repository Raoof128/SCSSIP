# API Reference

Complete API reference for the Advanced Threat Hunting Platform.

## Base URL

```
http://localhost:8000/api/v1
```

## Authentication

Currently using API key authentication (configure in production):

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:8000/api/v1/anomalies
```

---

## Anomaly Detection Endpoints

### `POST /anomalies/detect`

Trigger anomaly detection on recent data.

**Request Body:**
```json
{
  "data_source": "realtime",
  "time_window_hours": 24,
  "models": ["isolation_forest", "autoencoder", "statistical"]
}
```

**Response:**
```json
{
  "status": "detection_started",
  "job_id": "det-20251116-001",
  "models": ["isolation_forest", "autoencoder", "statistical"],
  "time_window_hours": 24
}
```

### `GET /anomalies`

List detected anomalies with filtering and pagination.

**Query Parameters:**
- `limit` (int, 1-500): Maximum results (default: 50)
- `offset` (int): Pagination offset (default: 0)
- `min_score` (float, 0-1): Minimum anomaly score (default: 0)
- `entity_type` (string): Filter by entity type
- `start_time` (ISO datetime): Start of time range
- `end_time` (ISO datetime): End of time range

**Example:**
```bash
curl "http://localhost:8000/api/v1/anomalies?min_score=0.9&limit=10"
```

**Response:**
```json
[
  {
    "id": 1,
    "detected_at": "2025-11-16T10:30:00Z",
    "entity_type": "user",
    "entity_id": "admin-user01",
    "anomaly_type": "unusual_login_time",
    "anomaly_score": 0.94,
    "model_name": "isolation_forest",
    "confidence": 0.92,
    "is_confirmed": false
  }
]
```

### `GET /anomalies/{anomaly_id}`

Get detailed information about a specific anomaly.

**Response:**
```json
{
  "id": 1,
  "detected_at": "2025-11-16T10:30:00Z",
  "entity_type": "user",
  "entity_id": "admin-user01",
  "anomaly_score": 0.94,
  "baseline_value": 9.5,
  "observed_value": 23.0,
  "deviation_sigma": 3.2,
  "feature_importance": {
    "hour_of_day": 0.45,
    "login_count": 0.30,
    "source_ip_entropy": 0.25
  }
}
```

---

## Entity Endpoints

### `GET /entities`

List entities with behavioral profiles.

**Response:**
```json
[
  {
    "entity_type": "user",
    "entity_id": "alice",
    "baseline_start": "2025-10-16T00:00:00Z",
    "baseline_end": "2025-11-16T00:00:00Z",
    "event_count": 15423,
    "last_updated": "2025-11-16T10:30:00Z"
  }
]
```

### `GET /entities/{entity_type}/{entity_id}/profile`

Get detailed behavioral profile for an entity.

**Response:**
```json
{
  "entity_type": "user",
  "entity_id": "alice",
  "baseline_period": {
    "start": "2025-10-16T00:00:00Z",
    "end": "2025-11-16T00:00:00Z",
    "days": 30
  },
  "statistics": {
    "total_events": 15423,
    "avg_events_per_day": 514,
    "unique_destinations": 47
  },
  "behavioral_patterns": {
    "authentication": {
      "typical_success_rate": 0.98,
      "typical_login_count_daily": 3.2
    },
    "network": {
      "typical_destinations": 15,
      "typical_bytes_sent": 524288
    }
  },
  "risk_score": 0.15
}
```

---

## Threat Hunting Endpoints

### `GET /threats/leads`

List threat hunting leads.

**Query Parameters:**
- `severity`: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
- `status`: Filter by status (NEW, INVESTIGATING, CONFIRMED, FALSE_POSITIVE, RESOLVED)
- `min_confidence` (float): Minimum confidence score
- `limit` (int): Maximum results
- `offset` (int): Pagination offset

**Response:**
```json
[
  {
    "lead_id": "THL-2025-001847",
    "severity": "HIGH",
    "status": "NEW",
    "confidence": 0.94,
    "title": "Potential Lateral Movement - Unusual SMB Share Access",
    "created_at": "2025-11-16T10:30:00Z",
    "updated_at": "2025-11-16T10:30:00Z"
  }
]
```

### `GET /threats/leads/{lead_id}`

Get detailed information about a threat hunting lead.

**Response:**
```json
{
  "lead_id": "THL-2025-001847",
  "severity": "HIGH",
  "confidence": 0.94,
  "title": "Potential Lateral Movement",
  "description": "User admin-user01 accessed 47 uncommon SMB shares...",
  "attack_techniques": [
    {
      "id": "T1021.002",
      "name": "Remote Services: SMB/Windows Admin Shares",
      "tactic": "Lateral Movement"
    }
  ],
  "recommended_actions": [
    "Check share access logs for malware patterns",
    "Correlate with PowerShell execution events"
  ],
  "evidence": {
    "event_count": 47,
    "unique_shares": 47,
    "baseline_avg_shares": 3.2,
    "deviation_sigma": 3.4
  }
}
```

### `POST /investigation/correlate`

Perform cross-correlation analysis on events.

**Request Body:**
```json
{
  "entity_ids": ["admin-user01", "WORKSTATION-42"],
  "time_window_hours": 24,
  "max_depth": 3
}
```

**Response:**
```json
{
  "correlation_id": "corr-20251116-001",
  "entity_count": 2,
  "correlations_found": 5,
  "attack_chains": [
    {
      "chain_id": "chain-001",
      "steps": [
        {"step": 1, "technique": "T1078", "description": "Initial Access"},
        {"step": 2, "technique": "T1021.002", "description": "Lateral Movement"}
      ],
      "confidence": 0.89
    }
  ]
}
```

---

## ML Model Endpoints

### `GET /models/status`

Get status of all ML models.

**Response:**
```json
[
  {
    "model_name": "isolation_forest_v1",
    "model_type": "isolation_forest",
    "version": "1.0.0",
    "is_active": true,
    "trained_at": "2025-11-16T00:00:00Z",
    "performance": {
      "accuracy": 0.953,
      "precision": 0.921,
      "recall": 0.887,
      "f1_score": 0.904,
      "false_positive_rate": 0.018
    }
  }
]
```

### `POST /models/train`

Trigger model training.

**Request Body:**
```json
{
  "model_type": "isolation_forest",
  "data_source": "recent",
  "days": 30
}
```

---

## Metrics Endpoints

### `GET /metrics/dashboard`

Get dashboard metrics for specified time range.

**Query Parameters:**
- `time_range_hours` (int): Time range in hours (default: 24)

**Response:**
```json
{
  "events": {
    "total_processed": 124837,
    "processing_rate_per_second": 1434.2
  },
  "anomalies": {
    "total_detected": 47,
    "high_confidence": 23
  },
  "detection": {
    "accuracy": 0.953,
    "false_positive_rate": 0.018
  }
}
```

---

## Error Responses

All endpoints return standard error responses:

```json
{
  "error": "Error type",
  "message": "Detailed error message",
  "path": "/api/v1/endpoint"
}
```

**HTTP Status Codes:**
- `200`: Success
- `400`: Bad Request
- `401`: Unauthorized
- `404`: Not Found
- `429`: Rate Limit Exceeded
- `500`: Internal Server Error

---

## Rate Limiting

- Default: 100 requests per minute per API key
- Burst: 20 requests
- Headers: `X-RateLimit-Remaining`, `X-RateLimit-Reset`

---

## Interactive Documentation

Visit `http://localhost:8000/docs` for interactive Swagger UI documentation.
