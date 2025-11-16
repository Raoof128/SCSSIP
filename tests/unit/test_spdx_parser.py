"""Tests for SPDX parser."""

from typing import Any

import pytest

from src.common.enums import ComponentType, SBOMFormat
from src.common.exceptions import SBOMValidationError
from src.sbom_ingestion.parsers.spdx import SPDXParser


class TestSPDXParser:
    """Test SPDX parser functionality."""

    @pytest.fixture
    def parser(self) -> SPDXParser:
        """Create parser instance."""
        return SPDXParser()

    def test_detect_format_valid(self, parser: SPDXParser, sample_spdx_sbom: dict[str, Any]) -> None:
        """Test format detection for valid SPDX SBOM."""
        assert parser.detect_format(sample_spdx_sbom) is True

    def test_detect_format_invalid(self, parser: SPDXParser) -> None:
        """Test format detection for invalid SBOM."""
        invalid_sbom = {"invalid": "data"}
        assert parser.detect_format(invalid_sbom) is False

    def test_get_version(self, parser: SPDXParser, sample_spdx_sbom: dict[str, Any]) -> None:
        """Test version extraction."""
        version = parser.get_version(sample_spdx_sbom)
        assert version == "SPDX-2.3"

    def test_validate_valid_sbom(self, parser: SPDXParser, sample_spdx_sbom: dict[str, Any]) -> None:
        """Test validation of valid SBOM."""
        assert parser.validate(sample_spdx_sbom) is True

    def test_validate_invalid_format(self, parser: SPDXParser) -> None:
        """Test validation fails for invalid format."""
        invalid_sbom = {"invalid": "data"}
        with pytest.raises(SBOMValidationError, match="Not a valid SPDX SBOM"):
            parser.validate(invalid_sbom)

    def test_validate_missing_required_fields(self, parser: SPDXParser) -> None:
        """Test validation fails for missing required fields."""
        invalid_sbom = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            # Missing SPDXID and name
        }
        with pytest.raises(SBOMValidationError, match="Missing required fields"):
            parser.validate(invalid_sbom)

    def test_parse_valid_sbom(self, parser: SPDXParser, sample_spdx_sbom: dict[str, Any]) -> None:
        """Test parsing of valid SBOM."""
        parsed = parser.parse(sample_spdx_sbom)

        assert parsed.format == SBOMFormat.SPDX
        assert parsed.spec_version == "SPDX-2.3"
        assert parsed.name == "vulnerable-web-app"
        assert len(parsed.components) == 6  # 6 packages

    def test_parse_packages(self, parser: SPDXParser, sample_spdx_sbom: dict[str, Any]) -> None:
        """Test package parsing."""
        parsed = parser.parse(sample_spdx_sbom)

        # Find log4j-core package
        log4j_core = next((c for c in parsed.components if c.name == "log4j-core"), None)
        assert log4j_core is not None
        assert log4j_core.version == "2.14.1"
        assert log4j_core.component_type == ComponentType.LIBRARY
        assert log4j_core.bom_ref == "SPDXRef-Package-log4j-core"

    def test_parse_purl_from_external_refs(
        self, parser: SPDXParser, sample_spdx_sbom: dict[str, Any]
    ) -> None:
        """Test PURL extraction from external references."""
        parsed = parser.parse(sample_spdx_sbom)

        log4j_core = next((c for c in parsed.components if c.name == "log4j-core"), None)
        assert log4j_core is not None
        assert log4j_core.purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"

    def test_parse_cpe_from_external_refs(
        self, parser: SPDXParser, sample_spdx_sbom: dict[str, Any]
    ) -> None:
        """Test CPE extraction from external references."""
        parsed = parser.parse(sample_spdx_sbom)

        log4j_core = next((c for c in parsed.components if c.name == "log4j-core"), None)
        assert log4j_core is not None
        assert log4j_core.cpe is not None
        assert "log4j" in log4j_core.cpe.lower()

    def test_parse_checksums(self, parser: SPDXParser, sample_spdx_sbom: dict[str, Any]) -> None:
        """Test checksum parsing."""
        parsed = parser.parse(sample_spdx_sbom)

        log4j_core = next((c for c in parsed.components if c.name == "log4j-core"), None)
        assert log4j_core is not None
        assert len(log4j_core.hashes) > 0

    def test_parse_licenses(self, parser: SPDXParser, sample_spdx_sbom: dict[str, Any]) -> None:
        """Test license parsing."""
        parsed = parser.parse(sample_spdx_sbom)

        log4j_core = next((c for c in parsed.components if c.name == "log4j-core"), None)
        assert log4j_core is not None
        assert len(log4j_core.licenses) > 0
        assert log4j_core.licenses[0].spdx_id == "Apache-2.0"

    def test_parse_relationships(
        self, parser: SPDXParser, sample_spdx_sbom: dict[str, Any]
    ) -> None:
        """Test relationship parsing."""
        parsed = parser.parse(sample_spdx_sbom)

        assert len(parsed.dependency_graph) > 0
        # Check that main package has dependencies
        main_ref = "SPDXRef-Package-vulnerable-web-app"
        assert main_ref in parsed.dependency_graph

    def test_parse_creators(self, parser: SPDXParser, sample_spdx_sbom: dict[str, Any]) -> None:
        """Test creator parsing."""
        parsed = parser.parse(sample_spdx_sbom)

        assert len(parsed.authors) > 0
        author = parsed.authors[0]
        assert author.name == "Security Team"
        assert author.email == "security@example.com"

    def test_parse_supplier(self, parser: SPDXParser) -> None:
        """Test supplier parsing."""
        assert parser._parse_supplier("Organization: Example Inc") == "Example Inc"
        assert parser._parse_supplier("Person: John Doe") == "John Doe"
        assert parser._parse_supplier("NOASSERTION") is None
        assert parser._parse_supplier("NONE") is None
        assert parser._parse_supplier(None) is None

    def test_parse_main_component(
        self, parser: SPDXParser, sample_spdx_sbom: dict[str, Any]
    ) -> None:
        """Test main component identification."""
        parsed = parser.parse(sample_spdx_sbom)

        assert parsed.main_component is not None
        assert parsed.main_component.name == "vulnerable-web-app"
        assert parsed.main_component.version == "1.0.0"
