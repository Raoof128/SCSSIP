"""Base SBOM parser interface."""

from abc import ABC, abstractmethod
from typing import Any

from src.sbom_ingestion.schemas import ParsedSBOM


class BaseSBOMParser(ABC):
    """Abstract base class for SBOM parsers."""

    @abstractmethod
    def parse(self, sbom_data: dict[str, Any]) -> ParsedSBOM:
        """
        Parse SBOM data into a standardized format.

        Args:
            sbom_data: Raw SBOM data as dictionary

        Returns:
            Parsed SBOM data

        Raises:
            SBOMParsingError: If parsing fails
            SBOMValidationError: If validation fails
        """
        pass

    @abstractmethod
    def validate(self, sbom_data: dict[str, Any]) -> bool:
        """
        Validate SBOM format and structure.

        Args:
            sbom_data: Raw SBOM data as dictionary

        Returns:
            True if valid, False otherwise

        Raises:
            SBOMValidationError: If validation fails
        """
        pass

    @abstractmethod
    def detect_format(self, sbom_data: dict[str, Any]) -> bool:
        """
        Detect if this parser can handle the given SBOM format.

        Args:
            sbom_data: Raw SBOM data as dictionary

        Returns:
            True if this parser can handle the format
        """
        pass

    @abstractmethod
    def get_version(self, sbom_data: dict[str, Any]) -> str:
        """
        Extract SBOM specification version.

        Args:
            sbom_data: Raw SBOM data as dictionary

        Returns:
            Version string (e.g., "1.5", "2.3")
        """
        pass
