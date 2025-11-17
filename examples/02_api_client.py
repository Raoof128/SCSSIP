"""
Example 2: Using the REST API Client

This example demonstrates:
- Connecting to the Threat Hunting Platform API
- Retrieving anomalies
- Fetching entity profiles
- Getting threat hunting leads
- Querying MITRE ATT&CK mappings

Requirements:
- Platform API running: uvicorn src.api.main:app --reload
- API credentials configured in .env
"""

import httpx
import asyncio
from datetime import datetime, timedelta
import json


class ThreatHuntingClient:
    """Simple client for the Threat Hunting Platform API."""

    def __init__(self, base_url: str = "http://localhost:8000", api_key: str = None):
        self.base_url = base_url
        self.api_key = api_key
        self.headers = {}

        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"

    async def get_health(self):
        """Check platform health status."""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.base_url}/health")
            return response.json()

    async def get_anomalies(self, limit: int = 10, severity_min: int = None):
        """Retrieve recent anomalies."""
        params = {"limit": limit}
        if severity_min:
            params["severity_min"] = severity_min

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/anomalies/",
                headers=self.headers,
                params=params
            )
            return response.json()

    async def get_anomaly_by_id(self, anomaly_id: str):
        """Get details of a specific anomaly."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/anomalies/{anomaly_id}",
                headers=self.headers
            )
            return response.json()

    async def get_entity_profile(self, entity_id: str):
        """Get behavioral profile for an entity (user/host)."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/entities/{entity_id}/profile",
                headers=self.headers
            )
            return response.json()

    async def get_entity_anomalies(self, entity_id: str):
        """Get anomalies for a specific entity."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/entities/{entity_id}/anomalies",
                headers=self.headers
            )
            return response.json()

    async def get_threat_leads(self, priority: str = None):
        """Get threat hunting leads."""
        params = {}
        if priority:
            params["priority"] = priority

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/threats/leads",
                headers=self.headers,
                params=params
            )
            return response.json()

    async def get_mitre_attacks(self, tactic: str = None):
        """Get MITRE ATT&CK technique mappings."""
        params = {}
        if tactic:
            params["tactic"] = tactic

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/threats/mitre-attacks",
                headers=self.headers,
                params=params
            )
            return response.json()

    async def get_model_metrics(self):
        """Get ML model performance metrics."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/models/metrics",
                headers=self.headers
            )
            return response.json()


async def main():
    print("="*70)
    print("Advanced Threat Hunting Platform - API Client Example")
    print("="*70)

    # Initialize client
    client = ThreatHuntingClient(
        base_url="http://localhost:8000",
        api_key=None  # Set if authentication is enabled
    )

    try:
        # 1. Check platform health
        print("\n[1] Checking platform health...")
        health = await client.get_health()
        print(f"✓ Platform status: {health.get('status', 'unknown')}")
        print(f"  API version: {health.get('version', 'N/A')}")

        # 2. Retrieve recent anomalies
        print("\n[2] Retrieving recent anomalies...")
        anomalies = await client.get_anomalies(limit=5, severity_min=7)

        if isinstance(anomalies, list):
            print(f"✓ Found {len(anomalies)} high-severity anomalies:")
            for i, anomaly in enumerate(anomalies[:5], 1):
                anomaly_id = anomaly.get('id', 'N/A')
                score = anomaly.get('anomaly_score', 0)
                timestamp = anomaly.get('timestamp', 'N/A')
                print(f"  {i}. ID: {anomaly_id} | Score: {score:.4f} | Time: {timestamp}")
        else:
            print(f"  Response: {anomalies}")

        # 3. Get entity profile
        print("\n[3] Retrieving entity profile...")
        entity_id = "alice"  # Example user
        profile = await client.get_entity_profile(entity_id)

        if isinstance(profile, dict):
            print(f"✓ Profile for entity '{entity_id}':")
            print(f"  Total events: {profile.get('total_events', 0)}")
            print(f"  Avg events/day: {profile.get('avg_events_per_day', 0):.1f}")
            print(f"  Risk score: {profile.get('risk_score', 0):.2f}")

            baseline = profile.get('baseline', {})
            if baseline:
                print("\n  Behavioral baseline:")
                print(f"    - Normal login hours: {baseline.get('normal_hours', 'N/A')}")
                print(f"    - Typical IPs: {len(baseline.get('typical_ips', []))}")
        else:
            print(f"  Response: {profile}")

        # 4. Get threat hunting leads
        print("\n[4] Retrieving threat hunting leads...")
        leads = await client.get_threat_leads(priority="high")

        if isinstance(leads, list):
            print(f"✓ Found {len(leads)} high-priority leads:")
            for i, lead in enumerate(leads[:5], 1):
                lead_id = lead.get('id', 'N/A')
                title = lead.get('title', 'Unknown')
                confidence = lead.get('confidence', 0)
                print(f"  {i}. {title}")
                print(f"     ID: {lead_id} | Confidence: {confidence:.0%}")
        else:
            print(f"  Response: {leads}")

        # 5. Get MITRE ATT&CK mappings
        print("\n[5] Retrieving MITRE ATT&CK mappings...")
        mitre_data = await client.get_mitre_attacks(tactic="credential-access")

        if isinstance(mitre_data, list):
            print(f"✓ Found {len(mitre_data)} credential access techniques:")
            for i, technique in enumerate(mitre_data[:5], 1):
                tech_id = technique.get('technique_id', 'N/A')
                tech_name = technique.get('name', 'Unknown')
                confidence = technique.get('confidence', 0)
                print(f"  {i}. {tech_id}: {tech_name} (confidence: {confidence:.2f})")
        else:
            print(f"  Response: {mitre_data}")

        # 6. Get model performance metrics
        print("\n[6] Retrieving model performance metrics...")
        metrics = await client.get_model_metrics()

        if isinstance(metrics, dict):
            print("✓ Model performance:")
            print(f"  Accuracy: {metrics.get('accuracy', 0):.2%}")
            print(f"  Precision: {metrics.get('precision', 0):.2%}")
            print(f"  Recall: {metrics.get('recall', 0):.2%}")
            print(f"  F1 Score: {metrics.get('f1_score', 0):.2%}")
            print(f"  False positive rate: {metrics.get('false_positive_rate', 0):.2%}")
        else:
            print(f"  Response: {metrics}")

    except httpx.ConnectError:
        print("\n❌ Error: Could not connect to API")
        print("   Make sure the platform is running:")
        print("   uvicorn src.api.main:app --reload")
    except httpx.HTTPStatusError as e:
        print(f"\n❌ HTTP Error: {e.response.status_code}")
        print(f"   {e.response.text}")
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")

    print("\n" + "="*70)
    print("API Client Example Completed")
    print("="*70)

    print("\nNext steps:")
    print("  1. Explore API documentation: http://localhost:8000/docs")
    print("  2. Try different query parameters and filters")
    print("  3. Integrate with your existing security tools")
    print("  4. Build custom dashboards using the API")


if __name__ == "__main__":
    asyncio.run(main())
