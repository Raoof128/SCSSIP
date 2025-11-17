# API Documentation

## Table of Contents
- [Overview](#overview)
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Error Handling](#error-handling)
- [SBOM Endpoints](#sbom-endpoints)
- [Vulnerability Endpoints](#vulnerability-endpoints)
- [Risk Assessment Endpoints](#risk-assessment-endpoints)
- [Compliance Endpoints](#compliance-endpoints)
- [Health & Status Endpoints](#health--status-endpoints)
- [Code Examples](#code-examples)

---

## Overview

**Base URL**: `http://localhost:8000` (development)
**Production URL**: `https://api.yourdomain.com`

**API Version**: v1
**Content-Type**: `application/json`
**Date Format**: ISO 8601 (`2025-11-16T10:30:00Z`)

### OpenAPI Documentation

Interactive API documentation is available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

---

## Authentication

**Current Version**: No authentication required (designed for internal use)

### Production Recommendations

```python
# OAuth2 with Bearer token
headers = {
    "Authorization": "Bearer your_access_token_here",
    "Content-Type": "application/json"
}
```

**Future Authentication Methods**:
- OAuth2 with JWT tokens
- API Key authentication
- Service account credentials

---

## Rate Limiting

**Current**: No rate limiting implemented

**Recommended Limits** (for production):
- Anonymous: 100 requests/hour
- Authenticated: 1000 requests/hour
- Per endpoint: 10 requests/second

**Headers**:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1699876543
```

---

## Error Handling

### Standard Error Response

```json
{
  "detail": "Error message describing what went wrong",
  "status_code": 400,
  "error_type": "ValidationError",
  "timestamp": "2025-11-16T10:30:00Z"
}
```

### HTTP Status Codes

| Code | Meaning | Usage |
|------|---------|-------|
| 200 | OK | Successful request |
| 201 | Created | Resource created successfully |
| 400 | Bad Request | Invalid input data |
| 404 | Not Found | Resource doesn't exist |
| 422 | Unprocessable Entity | Validation error |
| 500 | Internal Server Error | Server-side error |
| 503 | Service Unavailable | External API failure |

### Common Error Types

**Validation Error**:
```json
{
  "detail": [
    {
      "loc": ["body", "format"],
      "msg": "Invalid SBOM format",
      "type": "value_error"
    }
  ]
}
```

**Not Found Error**:
```json
{
  "detail": "SBOM with id 123 not found"
}
```

---

## SBOM Endpoints

### Upload SBOM

Upload and parse an SBOM file (CycloneDX or SPDX format).

**Endpoint**: `POST /api/v1/sboms/upload`

**Request**:
```http
POST /api/v1/sboms/upload
Content-Type: multipart/form-data

file: (binary data)
```

**cURL Example**:
```bash
curl -X POST http://localhost:8000/api/v1/sboms/upload \
  -F "file=@sbom.json" \
  -H "Content-Type: multipart/form-data"
```

**Response** (200 OK):
```json
{
  "sbom_id": 42,
  "message": "SBOM uploaded and parsed successfully",
  "format": "CycloneDX",
  "spec_version": "1.4",
  "components_count": 127,
  "uploaded_at": "2025-11-16T10:30:00Z"
}
```

**Validations**:
- File size: Maximum 10MB
- Format: Valid JSON
- Schema: Must be valid CycloneDX (1.4-1.6) or SPDX (2.2-3.0)

---

### Get SBOM by ID

Retrieve detailed information about a specific SBOM.

**Endpoint**: `GET /api/v1/sboms/{sbom_id}`

**Request**:
```http
GET /api/v1/sboms/42
```

**Response** (200 OK):
```json
{
  "id": 42,
  "bom_ref": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "name": "my-application",
  "version": "1.2.3",
  "format": "CycloneDX",
  "spec_version": "1.4",
  "serial_number": "urn:uuid:...",
  "supplier_name": "ACME Inc.",
  "manufacturer_name": "ACME Inc.",
  "authors": [
    {
      "name": "John Doe",
      "email": "john@acme.com"
    }
  ],
  "timestamp": "2025-11-15T14:30:00Z",
  "scan_status": "COMPLETED",
  "uploaded_at": "2025-11-16T10:30:00Z",
  "processed_at": "2025-11-16T10:30:15Z",
  "scan_duration_seconds": 15.3,
  "is_signed": true,
  "signature_algorithm": "RS256",
  "signature_verified": true,
  "total_components": 127,
  "total_vulnerabilities": 8,
  "critical_vulns": 1,
  "high_vulns": 3,
  "medium_vulns": 4,
  "low_vulns": 0,
  "overall_risk_score": 6.7,
  "overall_risk_level": "HIGH",
  "slsa_level": 2,
  "ntia_compliant": true
}
```

---

### List All SBOMs

Retrieve a paginated list of all SBOMs.

**Endpoint**: `GET /api/v1/sboms`

**Query Parameters**:
- `skip` (integer, default: 0): Number of records to skip
- `limit` (integer, default: 10, max: 100): Number of records to return
- `status` (string, optional): Filter by scan status (`PENDING`, `IN_PROGRESS`, `COMPLETED`, `FAILED`)

**Request**:
```http
GET /api/v1/sboms?skip=0&limit=10&status=COMPLETED
```

**Response** (200 OK):
```json
{
  "total": 42,
  "skip": 0,
  "limit": 10,
  "sboms": [
    {
      "id": 42,
      "name": "my-application",
      "version": "1.2.3",
      "format": "CycloneDX",
      "uploaded_at": "2025-11-16T10:30:00Z",
      "scan_status": "COMPLETED",
      "total_components": 127,
      "total_vulnerabilities": 8,
      "overall_risk_level": "HIGH"
    }
  ]
}
```

---

### Get SBOM Components

Retrieve all components in an SBOM with dependency tree structure.

**Endpoint**: `GET /api/v1/sboms/{sbom_id}/components`

**Request**:
```http
GET /api/v1/sboms/42/components
```

**Response** (200 OK):
```json
{
  "sbom_id": 42,
  "total_components": 127,
  "components": [
    {
      "id": 1001,
      "name": "log4j-core",
      "version": "2.14.1",
      "component_type": "LIBRARY",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
      "group": "org.apache.logging.log4j",
      "description": "The Apache Log4j Implementation",
      "supplier_name": "Apache Software Foundation",
      "is_direct_dependency": true,
      "dependency_depth": 0,
      "vuln_count": 1,
      "risk_score": 9.2,
      "risk_level": "CRITICAL",
      "licenses": [
        {
          "spdx_id": "Apache-2.0",
          "name": "Apache License 2.0",
          "risk_level": "LOW"
        }
      ],
      "hashes": [
        {
          "algorithm": "SHA256",
          "hash_value": "sha256:abc123..."
        }
      ]
    }
  ]
}
```

---

### Delete SBOM

Delete an SBOM and all associated data.

**Endpoint**: `DELETE /api/v1/sboms/{sbom_id}`

**Request**:
```http
DELETE /api/v1/sboms/42
```

**Response** (200 OK):
```json
{
  "message": "SBOM 42 deleted successfully"
}
```

---

## Vulnerability Endpoints

### Correlate Vulnerabilities

Trigger vulnerability correlation for an SBOM (queries NVD, OSV, GitHub Advisory).

**Endpoint**: `POST /api/v1/vulnerabilities/correlate/{sbom_id}`

**Request**:
```http
POST /api/v1/vulnerabilities/correlate/42
```

**Response** (200 OK):
```json
{
  "sbom_id": 42,
  "message": "Vulnerability correlation initiated",
  "status": "IN_PROGRESS",
  "estimated_duration_seconds": 30
}
```

**Background Processing**:
- Queries run asynchronously
- Results appear in GET endpoints after completion

---

### Get Vulnerabilities for SBOM

Retrieve all vulnerabilities found in an SBOM.

**Endpoint**: `GET /api/v1/vulnerabilities/{sbom_id}`

**Query Parameters**:
- `severity` (string, optional): Filter by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
- `skip` (integer, default: 0)
- `limit` (integer, default: 10)

**Request**:
```http
GET /api/v1/vulnerabilities/42?severity=CRITICAL&limit=10
```

**Response** (200 OK):
```json
{
  "sbom_id": 42,
  "total_vulnerabilities": 8,
  "vulnerabilities": [
    {
      "id": 5001,
      "cve_id": "CVE-2021-44228",
      "vulnerability_id": "CVE-2021-44228",
      "source": "NVD",
      "title": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
      "description": "Apache Log4j2 2.0-beta9 through 2.15.0...",
      "published_date": "2021-12-10T10:00:00Z",
      "modified_date": "2023-11-07T03:55:00Z",
      "cvss_score": 10.0,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      "cvss_version": "3.1",
      "severity": "CRITICAL",
      "epss_score": 0.975,
      "epss_percentile": 99.9,
      "affected_components": [
        {
          "component_id": 1001,
          "name": "log4j-core",
          "version": "2.14.1",
          "confidence": 1.0,
          "match_type": "CPE"
        }
      ],
      "references": [
        {
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
          "source": "NVD",
          "type": "ADVISORY"
        }
      ],
      "cwe_ids": ["CWE-502", "CWE-400"]
    }
  ]
}
```

---

### Get Vulnerability by ID

Retrieve detailed information about a specific vulnerability.

**Endpoint**: `GET /api/v1/vulnerabilities/details/{vulnerability_id}`

**Request**:
```http
GET /api/v1/vulnerabilities/details/5001
```

**Response**: Same as individual vulnerability object above

---

## Risk Assessment Endpoints

### Calculate Risk Score

Calculate multi-factor risk score for an SBOM.

**Endpoint**: `POST /api/v1/risk/score/{sbom_id}`

**Request**:
```http
POST /api/v1/risk/score/42
```

**Response** (200 OK):
```json
{
  "sbom_id": 42,
  "overall_risk_score": 6.7,
  "overall_risk_level": "HIGH",
  "risk_factors": {
    "vulnerability_score": 8.2,
    "license_score": 3.1,
    "signing_score": 2.0,
    "maintainer_score": 5.0,
    "dependency_depth_score": 4.5
  },
  "weights": {
    "vulnerability": 0.40,
    "license": 0.20,
    "signing": 0.20,
    "maintainer": 0.10,
    "dependency_depth": 0.10
  },
  "calculated_at": "2025-11-16T10:35:00Z"
}
```

---

### Get Risk Assessment

Retrieve the risk assessment for an SBOM.

**Endpoint**: `GET /api/v1/risk/{sbom_id}`

**Request**:
```http
GET /api/v1/risk/42
```

**Response** (200 OK):
```json
{
  "sbom_id": 42,
  "overall_risk_score": 6.7,
  "overall_risk_level": "HIGH",
  "risk_breakdown": {
    "critical_vulnerabilities": 1,
    "high_vulnerabilities": 3,
    "medium_vulnerabilities": 4,
    "low_vulnerabilities": 0,
    "high_risk_licenses": 2,
    "unsigned_components": 15,
    "max_dependency_depth": 7
  },
  "top_vulnerable_components": [
    {
      "component_id": 1001,
      "name": "log4j-core",
      "version": "2.14.1",
      "risk_score": 9.2,
      "risk_level": "CRITICAL",
      "vulnerability_count": 1,
      "critical_vulns": 1
    }
  ],
  "recommendations": [
    "Update log4j-core to version 2.17.1 or higher to address CVE-2021-44228",
    "Review and update 3 components with HIGH severity vulnerabilities",
    "Consider implementing digital signature verification for 15 unsigned components"
  ]
}
```

---

## Compliance Endpoints

### SLSA Validation

Validate SBOM against SLSA Framework (Levels 1-3).

**Endpoint**: `GET /api/v1/compliance/{sbom_id}/slsa`

**Request**:
```http
GET /api/v1/compliance/42/slsa
```

**Response** (200 OK):
```json
{
  "sbom_id": 42,
  "achieved_level": 2,
  "level_0": {
    "compliant": true,
    "requirements": "No guarantees",
    "issues": []
  },
  "level_1": {
    "compliant": true,
    "requirements": "Build provenance documented",
    "checks": {
      "has_timestamp": true,
      "has_supplier": true,
      "has_build_info": true
    },
    "issues": []
  },
  "level_2": {
    "compliant": true,
    "requirements": "Tamper-resistant artifacts",
    "checks": {
      "has_signatures": true,
      "signatures_verified": true,
      "has_hashes": true
    },
    "issues": []
  },
  "level_3": {
    "compliant": false,
    "requirements": "Non-falsifiable provenance",
    "checks": {
      "strong_cryptography": true,
      "hermetic_builds": false,
      "isolated_build_service": false
    },
    "issues": [
      "No evidence of hermetic build process",
      "Build service not identified"
    ]
  }
}
```

---

### NTIA Minimum Elements

Validate SBOM against NTIA Minimum Elements requirements.

**Endpoint**: `GET /api/v1/compliance/{sbom_id}/ntia`

**Request**:
```http
GET /api/v1/compliance/42/ntia
```

**Response** (200 OK):
```json
{
  "sbom_id": 42,
  "compliant": true,
  "compliance_percentage": 98.4,
  "minimum_elements_check": {
    "has_supplier": {
      "required": true,
      "present": true,
      "coverage": 100.0
    },
    "has_component_name": {
      "required": true,
      "present": true,
      "coverage": 100.0
    },
    "has_version": {
      "required": true,
      "present": true,
      "coverage": 98.4
    },
    "has_unique_identifier": {
      "required": true,
      "present": true,
      "coverage": 96.9
    },
    "has_dependencies": {
      "required": true,
      "present": true,
      "coverage": 100.0
    },
    "has_author": {
      "required": true,
      "present": true,
      "coverage": 95.3
    },
    "has_timestamp": {
      "required": true,
      "present": true,
      "coverage": 100.0
    }
  },
  "missing_elements": [
    {
      "component": "some-library",
      "version": "1.0.0",
      "missing_fields": ["unique_identifier", "author"]
    }
  ],
  "issues": [
    "2 components missing unique identifiers (PURL/CPE)",
    "6 components missing author information"
  ]
}
```

---

### Generate Compliance Report

Generate an HTML compliance report for an SBOM.

**Endpoint**: `GET /api/v1/compliance/{sbom_id}/report`

**Request**:
```http
GET /api/v1/compliance/42/report
```

**Response** (200 OK):
```html
<!DOCTYPE html>
<html>
<head>
  <title>Supply Chain Security Assessment Report</title>
  <style>...</style>
</head>
<body>
  <h1>Supply Chain Security Assessment Report</h1>
  <h2>SBOM: my-application v1.2.3</h2>

  <div class="executive-summary">
    <h3>Executive Summary</h3>
    <p>Overall Risk: <span class="risk-high">HIGH</span></p>
    <p>SLSA Level: 2</p>
    <p>NTIA Compliant: Yes</p>
  </div>

  <!-- ... detailed report content ... -->
</body>
</html>
```

**Content-Type**: `text/html`

---

## Health & Status Endpoints

### Root Endpoint

Basic API information.

**Endpoint**: `GET /`

**Response** (200 OK):
```json
{
  "name": "SBOM Security Intelligence Platform",
  "version": "0.1.0",
  "status": "operational"
}
```

---

### Health Check

Comprehensive health check including database connectivity.

**Endpoint**: `GET /health`

**Response** (200 OK):
```json
{
  "status": "healthy",
  "timestamp": "2025-11-16T10:30:00Z",
  "database": "connected",
  "cache": "connected"
}
```

**Response** (503 Service Unavailable):
```json
{
  "status": "unhealthy",
  "timestamp": "2025-11-16T10:30:00Z",
  "database": "disconnected",
  "cache": "connected",
  "errors": ["Database connection failed"]
}
```

---

### System Information

Get system version and configuration details.

**Endpoint**: `GET /info`

**Response** (200 OK):
```json
{
  "version": "0.1.0",
  "environment": "development",
  "supported_formats": ["CycloneDX 1.4-1.6", "SPDX 2.2-3.0"],
  "vulnerability_sources": ["NVD", "OSV", "GitHub Advisory", "EPSS"],
  "compliance_frameworks": ["SLSA", "NTIA"]
}
```

---

## Code Examples

### Python (requests)

```python
import requests
import json

# Upload SBOM
def upload_sbom(file_path):
    url = "http://localhost:8000/api/v1/sboms/upload"
    with open(file_path, 'rb') as f:
        files = {'file': ('sbom.json', f, 'application/json')}
        response = requests.post(url, files=files)
    return response.json()

# Correlate vulnerabilities
def correlate_vulnerabilities(sbom_id):
    url = f"http://localhost:8000/api/v1/vulnerabilities/correlate/{sbom_id}"
    response = requests.post(url)
    return response.json()

# Get risk assessment
def get_risk_assessment(sbom_id):
    url = f"http://localhost:8000/api/v1/risk/{sbom_id}"
    response = requests.get(url)
    return response.json()

# Example usage
result = upload_sbom("sbom.json")
sbom_id = result["sbom_id"]

correlate_vulnerabilities(sbom_id)
risk = get_risk_assessment(sbom_id)
print(f"Overall Risk: {risk['overall_risk_level']}")
```

### Python (httpx - async)

```python
import httpx
import asyncio

async def analyze_sbom(file_path):
    async with httpx.AsyncClient() as client:
        # Upload SBOM
        with open(file_path, 'rb') as f:
            files = {'file': ('sbom.json', f, 'application/json')}
            upload_response = await client.post(
                "http://localhost:8000/api/v1/sboms/upload",
                files=files
            )

        sbom_id = upload_response.json()["sbom_id"]

        # Run analysis in parallel
        tasks = [
            client.post(f"http://localhost:8000/api/v1/vulnerabilities/correlate/{sbom_id}"),
            client.post(f"http://localhost:8000/api/v1/risk/score/{sbom_id}"),
            client.get(f"http://localhost:8000/api/v1/compliance/{sbom_id}/slsa"),
            client.get(f"http://localhost:8000/api/v1/compliance/{sbom_id}/ntia")
        ]

        results = await asyncio.gather(*tasks)
        return {
            "sbom_id": sbom_id,
            "vulnerabilities": results[0].json(),
            "risk": results[1].json(),
            "slsa": results[2].json(),
            "ntia": results[3].json()
        }

# Run async analysis
results = asyncio.run(analyze_sbom("sbom.json"))
```

### cURL

```bash
# Upload SBOM
curl -X POST http://localhost:8000/api/v1/sboms/upload \
  -F "file=@sbom.json"

# Get SBOM details
curl http://localhost:8000/api/v1/sboms/42

# Correlate vulnerabilities
curl -X POST http://localhost:8000/api/v1/vulnerabilities/correlate/42

# Get vulnerabilities (filter by severity)
curl "http://localhost:8000/api/v1/vulnerabilities/42?severity=CRITICAL"

# Calculate risk score
curl -X POST http://localhost:8000/api/v1/risk/score/42

# Get SLSA compliance
curl http://localhost:8000/api/v1/compliance/42/slsa

# Get NTIA compliance
curl http://localhost:8000/api/v1/compliance/42/ntia

# Download HTML report
curl http://localhost:8000/api/v1/compliance/42/report > report.html
```

### JavaScript (fetch)

```javascript
// Upload SBOM
async function uploadSBOM(file) {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch('http://localhost:8000/api/v1/sboms/upload', {
    method: 'POST',
    body: formData
  });

  return await response.json();
}

// Get vulnerabilities
async function getVulnerabilities(sbomId) {
  const response = await fetch(
    `http://localhost:8000/api/v1/vulnerabilities/${sbomId}?severity=CRITICAL`
  );
  return await response.json();
}

// Example usage
const fileInput = document.getElementById('sbom-file');
const file = fileInput.files[0];

const result = await uploadSBOM(file);
const vulns = await getVulnerabilities(result.sbom_id);
console.log(`Found ${vulns.total_vulnerabilities} vulnerabilities`);
```

---

**API Version**: 1.0
**Last Updated**: 2025-11-16
**Status**: Current
