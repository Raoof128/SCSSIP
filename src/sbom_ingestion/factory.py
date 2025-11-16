"""SBOM Parser Factory for automatic format detection."""

import logging
from typing import Any

from src.common.enums import SBOMFormat
from src.common.exceptions import UnsupportedSBOMFormat
from src.sbom_ingestion.parsers.base import BaseSBOMParser
from src.sbom_ingestion.parsers.cyclonedx import CycloneDXParser
from src.sbom_ingestion.parsers.spdx import SPDXParser

logger = logging.getLogger(__name__)


class SBOMParserFactory:
    """Factory for creating appropriate SBOM parsers."""

    _parsers: dict[SBOMFormat, type[BaseSBOMParser]] = {
        SBOMFormat.CYCLONEDX: CycloneDXParser,
        SBOMFormat.SPDX: SPDXParser,
    }

    @classmethod
    def create_parser(cls, sbom_data: dict[str, Any]) -> BaseSBOMParser:
        """
        Create appropriate parser based on SBOM format detection.

        Args:
            sbom_data: Raw SBOM data as dictionary

        Returns:
            Instance of appropriate parser

        Raises:
            UnsupportedSBOMFormat: If format cannot be detected or is not supported
        """
        # Try each parser to detect format
        for format_type, parser_class in cls._parsers.items():
            parser = parser_class()
            if parser.detect_format(sbom_data):
                logger.info(f"Detected SBOM format: {format_type.value}")
                return parser

        raise UnsupportedSBOMFormat(
            "Could not detect SBOM format. Supported formats: CycloneDX, SPDX"
        )

    @classmethod
    def get_parser_for_format(cls, format_type: SBOMFormat) -> BaseSBOMParser:
        """
        Get parser for specific format.

        Args:
            format_type: SBOM format type

        Returns:
            Instance of appropriate parser

        Raises:
            UnsupportedSBOMFormat: If format is not supported
        """
        if format_type not in cls._parsers:
            raise UnsupportedSBOMFormat(f"Unsupported SBOM format: {format_type}")

        parser_class = cls._parsers[format_type]
        return parser_class()

    @classmethod
    def supported_formats(cls) -> list[SBOMFormat]:
        """Get list of supported SBOM formats."""
        return list(cls._parsers.keys())
