"""Custom exceptions for the platform."""


class SBOMPlatformError(Exception):
    """Base exception for all platform errors."""

    pass


class SBOMParsingError(SBOMPlatformError):
    """Raised when SBOM parsing fails."""

    pass


class SBOMValidationError(SBOMPlatformError):
    """Raised when SBOM validation fails."""

    pass


class UnsupportedSBOMFormat(SBOMPlatformError):
    """Raised when SBOM format is not supported."""

    pass


class UnsupportedSBOMVersion(SBOMPlatformError):
    """Raised when SBOM version is not supported."""

    pass


class SignatureVerificationError(SBOMPlatformError):
    """Raised when signature verification fails."""

    pass


class DatabaseError(SBOMPlatformError):
    """Raised when database operations fail."""

    pass


class VulnerabilityFeedError(SBOMPlatformError):
    """Raised when vulnerability feed access fails."""

    pass


class ComponentNotFoundError(SBOMPlatformError):
    """Raised when component is not found in database."""

    pass


class SBOMNotFoundError(SBOMPlatformError):
    """Raised when SBOM is not found in database."""

    pass


class RiskScoringError(SBOMPlatformError):
    """Raised when risk scoring calculation fails."""

    pass


class ComplianceCheckError(SBOMPlatformError):
    """Raised when compliance checking fails."""

    pass


class ConfigurationError(SBOMPlatformError):
    """Raised when configuration is invalid."""

    pass


class RateLimitError(SBOMPlatformError):
    """Raised when API rate limit is exceeded."""

    pass
