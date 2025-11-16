"""Tests for CycloneDX parser."""

from typing import Any

import pytest

from src.common.enums import ComponentType, HashAlgorithm, LicenseRiskLevel, SBOMFormat
from src.common.exceptions import SBOMValidationError
from src.sbom_ingestion.parsers.cyclonedx import CycloneDXParser


class TestCycloneDXParser:
    """Test CycloneDX parser functionality."""

    @pytest.fixture
    def parser(self) -> CycloneDXParser:
        """Create parser instance."""
        return CycloneDXParser()

    def test_detect_format_valid(self, parser: CycloneDXParser, sample_cyclonedx_sbom: dict[str, Any]) -> None:
        """Test format detection for valid CycloneDX SBOM."""
        assert parser.detect_format(sample_cyclonedx_sbom) is True

    def test_detect_format_invalid(self, parser: CycloneDXParser) -> None:
        """Test format detection for invalid SBOM."""
        invalid_sbom = {"invalid": "data"}
        assert parser.detect_format(invalid_sbom) is False

    def test_get_version(self, parser: CycloneDXParser, sample_cyclonedx_sbom: dict[str, Any]) -> None:
        """Test version extraction."""
        version = parser.get_version(sample_cyclonedx_sbom)
        assert version == "1.5"

    def test_validate_valid_sbom(
        self, parser: CycloneDXParser, sample_cyclonedx_sbom: dict[str, Any]
    ) -> None:
        """Test validation of valid SBOM."""
        assert parser.validate(sample_cyclonedx_sbom) is True

    def test_validate_invalid_format(self, parser: CycloneDXParser) -> None:
        """Test validation fails for invalid format."""
        invalid_sbom = {"invalid": "data"}
        with pytest.raises(SBOMValidationError, match="Not a valid CycloneDX SBOM"):
            parser.validate(invalid_sbom)

    def test_validate_unsupported_version(self, parser: CycloneDXParser) -> None:
        """Test validation fails for unsupported version."""
        invalid_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "0.1",
            "version": 1,
        }
        with pytest.raises(SBOMValidationError, match="Unsupported CycloneDX version"):
            parser.validate(invalid_sbom)

    def test_validate_missing_required_fields(self, parser: CycloneDXParser) -> None:
        """Test validation fails for missing required fields."""
        invalid_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            # Missing 'version' field
        }
        with pytest.raises(SBOMValidationError, match="Missing required fields"):
            parser.validate(invalid_sbom)

    def test_parse_valid_sbom(
        self, parser: CycloneDXParser, sample_cyclonedx_sbom: dict[str, Any]
    ) -> None:
        """Test parsing of valid SBOM."""
        parsed = parser.parse(sample_cyclonedx_sbom)

        assert parsed.format == SBOMFormat.CYCLONEDX
        assert parsed.spec_version == "1.5"
        assert parsed.name == "vulnerable-web-app"
        assert parsed.version == "1.0.0"
        assert len(parsed.components) == 5
        assert parsed.main_component is not None
        assert parsed.main_component.name == "vulnerable-web-app"

    def test_parse_components(
        self, parser: CycloneDXParser, sample_cyclonedx_sbom: dict[str, Any]
    ) -> None:
        """Test component parsing."""
        parsed = parser.parse(sample_cyclonedx_sbom)

        # Find log4j-core component
        log4j_core = next(
            (c for c in parsed.components if c.name == "log4j-core"), None
        )
        assert log4j_core is not None
        assert log4j_core.version == "2.14.1"
        assert log4j_core.component_type == ComponentType.LIBRARY
        assert log4j_core.purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
        assert log4j_core.cpe is not None
        assert "log4j" in log4j_core.cpe.lower()

    def test_parse_hashes(
        self, parser: CycloneDXParser, sample_cyclonedx_sbom: dict[str, Any]
    ) -> None:
        """Test hash parsing."""
        parsed = parser.parse(sample_cyclonedx_sbom)

        log4j_core = next(
            (c for c in parsed.components if c.name == "log4j-core"), None
        )
        assert log4j_core is not None
        assert len(log4j_core.hashes) > 0
        assert log4j_core.hashes[0].algorithm == HashAlgorithm.SHA256
        assert len(log4j_core.hashes[0].value) > 0

    def test_parse_licenses(
        self, parser: CycloneDXParser, sample_cyclonedx_sbom: dict[str, Any]
    ) -> None:
        """Test license parsing."""
        parsed = parser.parse(sample_cyclonedx_sbom)

        log4j_core = next(
            (c for c in parsed.components if c.name == "log4j-core"), None
        )
        assert log4j_core is not None
        assert len(log4j_core.licenses) > 0
        license = log4j_core.licenses[0]
        assert license.spdx_id == "Apache-2.0"
        assert license.risk_level == LicenseRiskLevel.LOW
        assert license.is_copyleft is False

    def test_parse_dependencies(
        self, parser: CycloneDXParser, sample_cyclonedx_sbom: dict[str, Any]
    ) -> None:
        """Test dependency graph parsing."""
        parsed = parser.parse(sample_cyclonedx_sbom)

        assert len(parsed.dependency_graph) > 0
        # Main component should have dependencies
        main_ref = "pkg:maven/com.example/vulnerable-web-app@1.0.0"
        assert main_ref in parsed.dependency_graph
        assert len(parsed.dependency_graph[main_ref]) == 3

    def test_calculate_dependency_depth(
        self, parser: CycloneDXParser, sample_cyclonedx_sbom: dict[str, Any]
    ) -> None:
        """Test dependency depth calculation."""
        parsed = parser.parse(sample_cyclonedx_sbom)

        # log4j-api should be depth 1 (transitive dependency)
        log4j_api = next(
            (c for c in parsed.components if c.name == "log4j-api"), None
        )
        assert log4j_api is not None
        assert log4j_api.dependency_depth == 1
        assert log4j_api.is_direct_dependency is False

    def test_parse_external_references(
        self, parser: CycloneDXParser, sample_cyclonedx_sbom: dict[str, Any]
    ) -> None:
        """Test external reference parsing."""
        parsed = parser.parse(sample_cyclonedx_sbom)

        log4j_core = next(
            (c for c in parsed.components if c.name == "log4j-core"), None
        )
        assert log4j_core is not None
        assert len(log4j_core.external_references) > 0

        # Check for website reference
        website_ref = next(
            (r for r in log4j_core.external_references if r.type == "website"), None
        )
        assert website_ref is not None
        assert "logging.apache.org" in website_ref.url

    def test_assess_license_risk(self, parser: CycloneDXParser) -> None:
        """Test license risk assessment."""
        assert parser._assess_license_risk("MIT") == LicenseRiskLevel.LOW
        assert parser._assess_license_risk("Apache-2.0") == LicenseRiskLevel.LOW
        assert parser._assess_license_risk("GPL-3.0") == LicenseRiskLevel.HIGH
        assert parser._assess_license_risk("LGPL-2.1") == LicenseRiskLevel.MEDIUM
        assert parser._assess_license_risk("Unknown-License") == LicenseRiskLevel.UNKNOWN

    def test_is_copyleft(self, parser: CycloneDXParser) -> None:
        """Test copyleft detection."""
        assert parser._is_copyleft("GPL-3.0") is True
        assert parser._is_copyleft("AGPL-3.0") is True
        assert parser._is_copyleft("LGPL-2.1") is True
        assert parser._is_copyleft("MIT") is False
        assert parser._is_copyleft("Apache-2.0") is False

    def test_parse_timestamp(self, parser: CycloneDXParser) -> None:
        """Test timestamp parsing."""
        timestamp = parser._parse_timestamp("2021-12-10T10:29:00Z")
        assert timestamp is not None
        assert timestamp.year == 2021
        assert timestamp.month == 12
        assert timestamp.day == 10

    def test_parse_timestamp_invalid(self, parser: CycloneDXParser) -> None:
        """Test invalid timestamp handling."""
        timestamp = parser._parse_timestamp("invalid-date")
        assert timestamp is None

    def test_parse_authors(self, parser: CycloneDXParser, sample_cyclonedx_sbom: dict[str, Any]) -> None:
        """Test author parsing."""
        parsed = parser.parse(sample_cyclonedx_sbom)
        assert len(parsed.authors) > 0
        author = parsed.authors[0]
        assert author.name == "Security Team"
        assert author.email == "security@example.com"
