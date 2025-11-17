# Usage Examples & Tutorials

## Table of Contents
- [Quick Start](#quick-start)
- [Common Workflows](#common-workflows)
- [CI/CD Integration](#cicd-integration)
- [Advanced Use Cases](#advanced-use-cases)
- [Example SBOMs](#example-sboms)
- [API Usage Examples](#api-usage-examples)

---

## Quick Start

### 1. Analyze a Single SBOM

**Upload and analyze an SBOM in one command**:

```bash
# Using the demo script
make demo FILE=examples/sboms/log4shell-cyclonedx.json

# Or manually
curl -X POST http://localhost:8000/api/v1/sboms/upload \
  -F "file=@examples/sboms/log4shell-cyclonedx.json" \
  | jq '.sbom_id'
```

**Expected Output**:
```json
{
  "sbom_id": 1,
  "message": "SBOM uploaded and parsed successfully",
  "format": "CycloneDX",
  "spec_version": "1.4",
  "components_count": 12,
  "uploaded_at": "2025-11-16T10:30:00Z"
}
```

### 2. Check for Vulnerabilities

```bash
# Correlate vulnerabilities
curl -X POST http://localhost:8000/api/v1/vulnerabilities/correlate/1

# Get results (after ~10 seconds)
curl http://localhost:8000/api/v1/vulnerabilities/1?severity=CRITICAL | jq '.'
```

### 3. Generate Compliance Report

```bash
# Download HTML report
curl http://localhost:8000/api/v1/compliance/1/report > report.html
open report.html  # macOS
xdg-open report.html  # Linux
```

---

## Common Workflows

### Workflow 1: Complete SBOM Analysis

```bash
#!/bin/bash
# analyze-sbom.sh

SBOM_FILE=$1
API_URL="http://localhost:8000"

echo "📤 Uploading SBOM..."
RESPONSE=$(curl -s -X POST "$API_URL/api/v1/sboms/upload" -F "file=@$SBOM_FILE")
SBOM_ID=$(echo $RESPONSE | jq -r '.sbom_id')

echo "✅ SBOM uploaded (ID: $SBOM_ID)"

echo "🔍 Correlating vulnerabilities..."
curl -s -X POST "$API_URL/api/v1/vulnerabilities/correlate/$SBOM_ID" > /dev/null

echo "⏳ Waiting for correlation to complete..."
sleep 10

echo "📊 Calculating risk score..."
curl -s -X POST "$API_URL/api/v1/risk/score/$SBOM_ID" | jq '.overall_risk_level'

echo "✅ Getting SLSA compliance..."
curl -s "$API_URL/api/v1/compliance/$SBOM_ID/slsa" | jq '.achieved_level'

echo "✅ Getting NTIA compliance..."
curl -s "$API_URL/api/v1/compliance/$SBOM_ID/ntia" | jq '.compliant'

echo "📄 Generating report..."
curl -s "$API_URL/api/v1/compliance/$SBOM_ID/report" > "report_$SBOM_ID.html"

echo "✅ Analysis complete! Report saved to report_$SBOM_ID.html"
```

**Usage**:
```bash
chmod +x analyze-sbom.sh
./analyze-sbom.sh examples/sboms/log4shell-cyclonedx.json
```

### Workflow 2: Batch Analysis

```python
#!/usr/bin/env python3
"""Analyze multiple SBOMs and generate summary report."""

import requests
import time
from pathlib import Path
import json

API_URL = "http://localhost:8000"

def analyze_sbom(file_path):
    """Upload and analyze a single SBOM."""
    # Upload
    with open(file_path, 'rb') as f:
        response = requests.post(
            f"{API_URL}/api/v1/sboms/upload",
            files={'file': (file_path.name, f, 'application/json')}
        )
    sbom_id = response.json()['sbom_id']

    # Correlate vulnerabilities
    requests.post(f"{API_URL}/api/v1/vulnerabilities/correlate/{sbom_id}")
    time.sleep(10)  # Wait for correlation

    # Get risk assessment
    risk = requests.get(f"{API_URL}/api/v1/risk/{sbom_id}").json()

    # Get vulnerabilities
    vulns = requests.get(f"{API_URL}/api/v1/vulnerabilities/{sbom_id}").json()

    return {
        'file': file_path.name,
        'sbom_id': sbom_id,
        'risk_level': risk['overall_risk_level'],
        'risk_score': risk['overall_risk_score'],
        'total_vulns': vulns['total_vulnerabilities'],
        'critical_vulns': risk['risk_breakdown']['critical_vulnerabilities']
    }

def main():
    # Analyze all SBOMs in examples directory
    sbom_dir = Path('examples/sboms')
    results = []

    for sbom_file in sbom_dir.glob('*.json'):
        print(f"Analyzing {sbom_file.name}...")
        result = analyze_sbom(sbom_file)
        results.append(result)
        print(f"  Risk: {result['risk_level']}, Vulns: {result['total_vulns']}")

    # Generate summary
    print("\n" + "="*60)
    print("SUMMARY REPORT")
    print("="*60)

    for r in sorted(results, key=lambda x: x['risk_score'], reverse=True):
        print(f"{r['file']:30s} | Risk: {r['risk_level']:8s} | "
              f"Vulns: {r['total_vulns']:2d} | Critical: {r['critical_vulns']}")

    # Save to JSON
    with open('batch_analysis_results.json', 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to batch_analysis_results.json")

if __name__ == '__main__':
    main()
```

### Workflow 3: Monitor Application Over Time

```python
#!/usr/bin/env python3
"""Track vulnerability changes over time."""

import requests
import sqlite3
from datetime import datetime

API_URL = "http://localhost:8000"

def track_sbom(sbom_id, db_path='tracking.db'):
    """Record current state of SBOM."""
    # Get current vulnerability count
    vulns = requests.get(f"{API_URL}/api/v1/vulnerabilities/{sbom_id}").json()
    risk = requests.get(f"{API_URL}/api/v1/risk/{sbom_id}").json()

    # Store in database
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS sbom_tracking
                 (timestamp TEXT, sbom_id INTEGER, total_vulns INTEGER,
                  critical_vulns INTEGER, high_vulns INTEGER,
                  risk_score REAL, risk_level TEXT)''')

    c.execute('''INSERT INTO sbom_tracking VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (datetime.now().isoformat(), sbom_id,
               vulns['total_vulnerabilities'],
               risk['risk_breakdown']['critical_vulnerabilities'],
               risk['risk_breakdown']['high_vulnerabilities'],
               risk['overall_risk_score'],
               risk['overall_risk_level']))

    conn.commit()
    conn.close()

    print(f"Tracked SBOM {sbom_id} at {datetime.now()}")

# Run daily via cron
# 0 0 * * * /path/to/track_sbom.py --sbom-id 1
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/sbom-scan.yml
name: SBOM Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  sbom-analysis:
    runs-on: ubuntu-latest

    services:
      sbom-api:
        image: ghcr.io/raoof128/scssip:latest
        ports:
          - 8000:8000
        env:
          DATABASE_URL: postgresql://postgres:postgres@postgres:5432/sbom_db
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}

      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: sbom_db
        ports:
          - 5432:5432

    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM (CycloneDX)
        run: |
          # Using CycloneDX CLI
          cyclonedx-cli convert --input package-lock.json --output sbom.json

      - name: Upload SBOM to Security Platform
        id: upload
        run: |
          RESPONSE=$(curl -X POST http://localhost:8000/api/v1/sboms/upload \
            -F "file=@sbom.json")
          SBOM_ID=$(echo $RESPONSE | jq -r '.sbom_id')
          echo "sbom_id=$SBOM_ID" >> $GITHUB_OUTPUT

      - name: Analyze Vulnerabilities
        run: |
          curl -X POST http://localhost:8000/api/v1/vulnerabilities/correlate/${{ steps.upload.outputs.sbom_id }}
          sleep 15  # Wait for analysis

      - name: Check Security Threshold
        run: |
          RISK=$(curl http://localhost:8000/api/v1/risk/${{ steps.upload.outputs.sbom_id }})
          CRITICAL=$(echo $RISK | jq '.risk_breakdown.critical_vulnerabilities')

          if [ $CRITICAL -gt 0 ]; then
            echo "❌ CRITICAL vulnerabilities found: $CRITICAL"
            exit 1
          fi

      - name: Generate Report
        if: always()
        run: |
          curl http://localhost:8000/api/v1/compliance/${{ steps.upload.outputs.sbom_id }}/report > sbom-report.html

      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sbom-security-report
          path: sbom-report.html
```

### GitLab CI/CD

```yaml
# .gitlab-ci.yml
stages:
  - sbom-generate
  - sbom-analyze
  - security-gate

variables:
  SBOM_API: "http://sbom-platform.internal:8000"

generate-sbom:
  stage: sbom-generate
  image: cyclonedx/cyclonedx-cli
  script:
    - cyclonedx-cli convert --input package-lock.json --output sbom.json
  artifacts:
    paths:
      - sbom.json
    expire_in: 1 week

analyze-sbom:
  stage: sbom-analyze
  image: curlimages/curl:latest
  script:
    - |
      RESPONSE=$(curl -X POST $SBOM_API/api/v1/sboms/upload -F "file=@sbom.json")
      SBOM_ID=$(echo $RESPONSE | jq -r '.sbom_id')
      echo "SBOM_ID=$SBOM_ID" > sbom.env
    - curl -X POST $SBOM_API/api/v1/vulnerabilities/correlate/$SBOM_ID
    - sleep 15
    - curl $SBOM_API/api/v1/compliance/$SBOM_ID/report > sbom-report.html
  artifacts:
    paths:
      - sbom-report.html
    reports:
      dotenv: sbom.env

security-gate:
  stage: security-gate
  image: curlimages/curl:latest
  script:
    - |
      RISK=$(curl $SBOM_API/api/v1/risk/$SBOM_ID)
      CRITICAL=$(echo $RISK | jq '.risk_breakdown.critical_vulnerabilities')
      HIGH=$(echo $RISK | jq '.risk_breakdown.high_vulnerabilities')

      echo "Critical vulnerabilities: $CRITICAL"
      echo "High vulnerabilities: $HIGH"

      if [ $CRITICAL -gt 0 ]; then
        echo "❌ Build failed: CRITICAL vulnerabilities found"
        exit 1
      fi
```

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        SBOM_API = 'http://sbom-platform:8000'
    }

    stages {
        stage('Generate SBOM') {
            steps {
                sh 'cyclonedx-cli convert --input package-lock.json --output sbom.json'
            }
        }

        stage('Upload to Security Platform') {
            steps {
                script {
                    def response = sh(
                        script: "curl -X POST ${SBOM_API}/api/v1/sboms/upload -F 'file=@sbom.json'",
                        returnStdout: true
                    )
                    def json = readJSON text: response
                    env.SBOM_ID = json.sbom_id
                }
            }
        }

        stage('Vulnerability Analysis') {
            steps {
                sh "curl -X POST ${SBOM_API}/api/v1/vulnerabilities/correlate/${env.SBOM_ID}"
                sleep 15
            }
        }

        stage('Security Gate') {
            steps {
                script {
                    def risk = sh(
                        script: "curl ${SBOM_API}/api/v1/risk/${env.SBOM_ID}",
                        returnStdout: true
                    )
                    def riskJson = readJSON text: risk

                    if (riskJson.risk_breakdown.critical_vulnerabilities > 0) {
                        error("Build failed: CRITICAL vulnerabilities found")
                    }
                }
            }
        }

        stage('Generate Report') {
            steps {
                sh "curl ${SBOM_API}/api/v1/compliance/${env.SBOM_ID}/report > sbom-report.html"
                publishHTML([
                    reportDir: '.',
                    reportFiles: 'sbom-report.html',
                    reportName: 'SBOM Security Report'
                ])
            }
        }
    }
}
```

---

## Advanced Use Cases

### Use Case 1: Continuous Monitoring

**Scenario**: Monitor production SBOMs daily and alert on new vulnerabilities

```python
import requests
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta

def check_for_new_vulnerabilities(sbom_id, last_check_file='last_check.txt'):
    """Check for vulnerabilities discovered since last check."""

    # Read last check time
    try:
        with open(last_check_file, 'r') as f:
            last_check = datetime.fromisoformat(f.read())
    except FileNotFoundError:
        last_check = datetime.now() - timedelta(days=30)

    # Re-correlate (gets latest CVE data)
    requests.post(f"http://localhost:8000/api/v1/vulnerabilities/correlate/{sbom_id}")

    # Get vulnerabilities published after last check
    vulns = requests.get(f"http://localhost:8000/api/v1/vulnerabilities/{sbom_id}").json()

    new_vulns = [
        v for v in vulns['vulnerabilities']
        if datetime.fromisoformat(v['published_date']) > last_check
    ]

    if new_vulns:
        send_alert(sbom_id, new_vulns)

    # Update last check time
    with open(last_check_file, 'w') as f:
        f.write(datetime.now().isoformat())

    return new_vulns

def send_alert(sbom_id, vulnerabilities):
    """Send email alert for new vulnerabilities."""
    critical = [v for v in vulnerabilities if v['severity'] == 'CRITICAL']

    msg_body = f"""
    New vulnerabilities detected in SBOM {sbom_id}:

    Total: {len(vulnerabilities)}
    Critical: {len(critical)}

    Critical Vulnerabilities:
    """

    for v in critical:
        msg_body += f"\n- {v['cve_id']}: {v['title']}"

    msg = MIMEText(msg_body)
    msg['Subject'] = f'ALERT: {len(critical)} Critical Vulnerabilities in SBOM {sbom_id}'
    msg['From'] = 'security@company.com'
    msg['To'] = 'security-team@company.com'

    # Send email (configure SMTP settings)
    # smtp = smtplib.SMTP('localhost')
    # smtp.send_message(msg)
    # smtp.quit()

    print(msg_body)

# Run daily via cron
# 0 9 * * * python3 continuous_monitoring.py
```

### Use Case 2: Policy Enforcement

```python
"""Enforce security policies before deployment."""

import requests
import sys

POLICIES = {
    'max_critical_vulns': 0,
    'max_high_vulns': 3,
    'min_slsa_level': 2,
    'ntia_compliant': True,
    'max_risk_score': 6.0,
    'banned_licenses': ['GPL-3.0', 'AGPL-3.0']
}

def enforce_policies(sbom_id):
    """Check if SBOM meets security policies."""
    violations = []

    # Check vulnerability thresholds
    vulns = requests.get(f"http://localhost:8000/api/v1/vulnerabilities/{sbom_id}").json()
    risk = requests.get(f"http://localhost:8000/api/v1/risk/{sbom_id}").json()
    slsa = requests.get(f"http://localhost:8000/api/v1/compliance/{sbom_id}/slsa").json()
    ntia = requests.get(f"http://localhost:8000/api/v1/compliance/{sbom_id}/ntia").json()

    # Vulnerability policy
    critical = risk['risk_breakdown']['critical_vulnerabilities']
    if critical > POLICIES['max_critical_vulns']:
        violations.append(f"CRITICAL vulnerabilities: {critical} (max: {POLICIES['max_critical_vulns']})")

    high = risk['risk_breakdown']['high_vulnerabilities']
    if high > POLICIES['max_high_vulns']:
        violations.append(f"HIGH vulnerabilities: {high} (max: {POLICIES['max_high_vulns']})")

    # SLSA policy
    if slsa['achieved_level'] < POLICIES['min_slsa_level']:
        violations.append(f"SLSA Level: {slsa['achieved_level']} (min: {POLICIES['min_slsa_level']})")

    # NTIA policy
    if POLICIES['ntia_compliant'] and not ntia['compliant']:
        violations.append(f"NTIA Compliance: {ntia['compliant']} (required: True)")

    # Risk score policy
    if risk['overall_risk_score'] > POLICIES['max_risk_score']:
        violations.append(f"Risk Score: {risk['overall_risk_score']} (max: {POLICIES['max_risk_score']})")

    # License policy
    components = requests.get(f"http://localhost:8000/api/v1/sboms/{sbom_id}/components").json()
    for comp in components['components']:
        for license in comp.get('licenses', []):
            if license['spdx_id'] in POLICIES['banned_licenses']:
                violations.append(f"Banned license {license['spdx_id']} in {comp['name']}")

    if violations:
        print("❌ POLICY VIOLATIONS:")
        for v in violations:
            print(f"  - {v}")
        return False
    else:
        print("✅ All policies passed")
        return True

if __name__ == '__main__':
    sbom_id = int(sys.argv[1])
    if not enforce_policies(sbom_id):
        sys.exit(1)
```

---

## Example SBOMs

### 1. Log4Shell Vulnerable Application (CycloneDX)

Location: `examples/sboms/log4shell-cyclonedx.json`

**Demonstrates**:
- Critical vulnerability (CVE-2021-44228)
- Dependency graph with transitive dependencies
- Multiple license types
- Component hashes

**Expected Results**:
- Risk Level: CRITICAL
- Total Vulnerabilities: 1-2
- SLSA Level: 0-1
- NTIA Compliant: Yes

### 2. Secure Application (CycloneDX)

Location: `examples/sboms/secure-app-cyclonedx.json`

**Demonstrates**:
- No known vulnerabilities
- Signed components
- Complete metadata

**Expected Results**:
- Risk Level: LOW
- Total Vulnerabilities: 0
- SLSA Level: 2
- NTIA Compliant: Yes

### 3. Log4Shell Vulnerable Application (SPDX)

Location: `examples/sboms/log4shell-spdx.json`

**Demonstrates**:
- SPDX 2.3 format
- Package relationships
- File-level SBOM

---

## API Usage Examples

### Python with httpx (Async)

```python
import httpx
import asyncio

async def full_analysis(sbom_path):
    """Complete SBOM analysis using async HTTP."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Upload SBOM
        with open(sbom_path, 'rb') as f:
            upload = await client.post(
                "http://localhost:8000/api/v1/sboms/upload",
                files={'file': (sbom_path, f, 'application/json')}
            )

        sbom_id = upload.json()['sbom_id']
        print(f"Uploaded SBOM ID: {sbom_id}")

        # Trigger analysis tasks concurrently
        await client.post(f"http://localhost:8000/api/v1/vulnerabilities/correlate/{sbom_id}")
        await asyncio.sleep(10)  # Wait for external API calls

        # Fetch results in parallel
        tasks = [
            client.get(f"http://localhost:8000/api/v1/sboms/{sbom_id}"),
            client.get(f"http://localhost:8000/api/v1/vulnerabilities/{sbom_id}"),
            client.get(f"http://localhost:8000/api/v1/risk/{sbom_id}"),
            client.get(f"http://localhost:8000/api/v1/compliance/{sbom_id}/slsa"),
            client.get(f"http://localhost:8000/api/v1/compliance/{sbom_id}/ntia")
        ]

        results = await asyncio.gather(*tasks)

        return {
            'sbom': results[0].json(),
            'vulnerabilities': results[1].json(),
            'risk': results[2].json(),
            'slsa': results[3].json(),
            'ntia': results[4].json()
        }

# Run analysis
results = asyncio.run(full_analysis('sbom.json'))
print(f"Risk Level: {results['risk']['overall_risk_level']}")
```

---

**Last Updated**: 2025-11-16
**Version**: 1.0
