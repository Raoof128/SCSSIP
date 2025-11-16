"""Integration tests for API endpoints."""

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from api.main import app
from src.database.base import Base
from src.database import get_db


# Test database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override database dependency for testing."""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="function")
def test_db():
    """Create test database."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(test_db):
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def sample_cyclonedx_file():
    """Load sample CycloneDX SBOM file."""
    sbom_path = Path(__file__).parent.parent.parent / "examples" / "sboms" / "log4shell-cyclonedx.json"
    return sbom_path


class TestHealthEndpoints:
    """Test health check endpoints."""

    def test_root(self, client: TestClient):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "SBOM Security Platform" in data["service"]

    def test_health(self, client: TestClient):
        """Test health endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "components" in data

    def test_info(self, client: TestClient):
        """Test info endpoint."""
        response = client.get("/api/v1/info")
        assert response.status_code == 200
        data = response.json()
        assert data["features"]["sbom_parsing"] is True
        assert data["features"]["vulnerability_correlation"] is True
        assert "NVD" in data["vulnerability_sources"]


class TestSBOMEndpoints:
    """Test SBOM endpoints."""

    def test_upload_sbom(self, client: TestClient, sample_cyclonedx_file: Path):
        """Test SBOM upload."""
        with open(sample_cyclonedx_file, "rb") as f:
            response = client.post(
                "/api/v1/sboms/upload",
                files={"file": ("test.json", f, "application/json")},
            )

        assert response.status_code == 200
        data = response.json()
        assert "sbom_id" in data
        assert data["name"] == "vulnerable-web-app"
        assert data["status"] == "success"

    def test_list_sboms_empty(self, client: TestClient):
        """Test listing SBOMs when empty."""
        response = client.get("/api/v1/sboms/")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert len(data["sboms"]) == 0

    def test_get_sbom_not_found(self, client: TestClient):
        """Test getting non-existent SBOM."""
        response = client.get("/api/v1/sboms/9999")
        assert response.status_code == 404

    def test_upload_and_retrieve(self, client: TestClient, sample_cyclonedx_file: Path):
        """Test full SBOM upload and retrieval flow."""
        # Upload
        with open(sample_cyclonedx_file, "rb") as f:
            upload_response = client.post(
                "/api/v1/sboms/upload",
                files={"file": ("test.json", f, "application/json")},
            )

        assert upload_response.status_code == 200
        sbom_id = upload_response.json()["sbom_id"]

        # Retrieve
        get_response = client.get(f"/api/v1/sboms/{sbom_id}")
        assert get_response.status_code == 200
        data = get_response.json()
        assert data["id"] == sbom_id
        assert data["name"] == "vulnerable-web-app"
        assert data["total_components"] == 5

        # Get components
        components_response = client.get(f"/api/v1/sboms/{sbom_id}/components")
        assert components_response.status_code == 200
        comp_data = components_response.json()
        assert comp_data["total"] == 5


class TestVulnerabilityEndpoints:
    """Test vulnerability endpoints."""

    def test_list_vulnerabilities_empty(self, client: TestClient):
        """Test listing vulnerabilities when empty."""
        response = client.get("/api/v1/vulnerabilities/")
        assert response.status_code == 200
        data = response.json()
        assert "vulnerabilities" in data

    def test_get_vulnerability_not_found(self, client: TestClient):
        """Test getting non-existent vulnerability."""
        response = client.get("/api/v1/vulnerabilities/9999")
        assert response.status_code == 404


class TestRiskEndpoints:
    """Test risk scoring endpoints."""

    def test_score_sbom_not_found(self, client: TestClient):
        """Test scoring non-existent SBOM."""
        response = client.post("/api/v1/risk/score/9999")
        assert response.status_code == 404

    def test_get_risk_not_found(self, client: TestClient):
        """Test getting risk for non-existent SBOM."""
        response = client.get("/api/v1/risk/9999")
        assert response.status_code == 404


class TestComplianceEndpoints:
    """Test compliance endpoints."""

    def test_slsa_validation_not_found(self, client: TestClient):
        """Test SLSA validation for non-existent SBOM."""
        response = client.get("/api/v1/compliance/9999/slsa")
        assert response.status_code == 404

    def test_ntia_validation_not_found(self, client: TestClient):
        """Test NTIA validation for non-existent SBOM."""
        response = client.get("/api/v1/compliance/9999/ntia")
        assert response.status_code == 404

    def test_full_compliance_flow(self, client: TestClient, sample_cyclonedx_file: Path):
        """Test complete compliance validation flow."""
        # Upload SBOM
        with open(sample_cyclonedx_file, "rb") as f:
            upload_response = client.post(
                "/api/v1/sboms/upload",
                files={"file": ("test.json", f, "application/json")},
            )

        sbom_id = upload_response.json()["sbom_id"]

        # Validate SLSA
        slsa_response = client.get(f"/api/v1/compliance/{sbom_id}/slsa")
        assert slsa_response.status_code == 200
        slsa_data = slsa_response.json()
        assert "achieved_level" in slsa_data
        assert "level_1" in slsa_data
        assert "compliant" in slsa_data["level_1"]
        assert isinstance(slsa_data["level_1"]["compliant"], bool)

        # Validate NTIA
        ntia_response = client.get(f"/api/v1/compliance/{sbom_id}/ntia")
        assert ntia_response.status_code == 200
        ntia_data = ntia_response.json()
        assert "compliant" in ntia_data
        assert "compliance_percentage" in ntia_data

        # Generate report
        report_response = client.get(f"/api/v1/compliance/{sbom_id}/report")
        assert report_response.status_code == 200
        assert "Supply Chain Security Assessment Report" in report_response.text
