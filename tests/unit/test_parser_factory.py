"""Tests for SBOM parser factory."""

from typing import Any

import pytest

from src.common.enums import SBOMFormat
from src.common.exceptions import UnsupportedSBOMFormat
from src.sbom_ingestion.factory import SBOMParserFactory
from src.sbom_ingestion.parsers.cyclonedx import CycloneDXParser
from src.sbom_ingestion.parsers.spdx import SPDXParser


class TestSBOMParserFactory:
    """Test SBOM parser factory."""

    def test_create_parser_cyclonedx(self, sample_cyclonedx_sbom: dict[str, Any]) -> None:
        """Test parser creation for CycloneDX."""
        parser = SBOMParserFactory.create_parser(sample_cyclonedx_sbom)
        assert isinstance(parser, CycloneDXParser)

    def test_create_parser_spdx(self, sample_spdx_sbom: dict[str, Any]) -> None:
        """Test parser creation for SPDX."""
        parser = SBOMParserFactory.create_parser(sample_spdx_sbom)
        assert isinstance(parser, SPDXParser)

    def test_create_parser_unsupported(self) -> None:
        """Test parser creation for unsupported format."""
        invalid_sbom = {"invalid": "data"}
        with pytest.raises(UnsupportedSBOMFormat):
            SBOMParserFactory.create_parser(invalid_sbom)

    def test_get_parser_for_format_cyclonedx(self) -> None:
        """Test getting parser for specific format."""
        parser = SBOMParserFactory.get_parser_for_format(SBOMFormat.CYCLONEDX)
        assert isinstance(parser, CycloneDXParser)

    def test_get_parser_for_format_spdx(self) -> None:
        """Test getting parser for specific format."""
        parser = SBOMParserFactory.get_parser_for_format(SBOMFormat.SPDX)
        assert isinstance(parser, SPDXParser)

    def test_get_parser_for_format_unsupported(self) -> None:
        """Test getting parser for unsupported format."""
        with pytest.raises(UnsupportedSBOMFormat):
            SBOMParserFactory.get_parser_for_format(SBOMFormat.UNKNOWN)

    def test_supported_formats(self) -> None:
        """Test getting list of supported formats."""
        formats = SBOMParserFactory.supported_formats()
        assert SBOMFormat.CYCLONEDX in formats
        assert SBOMFormat.SPDX in formats
        assert len(formats) == 2
