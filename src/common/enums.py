"""Enumerations used across the platform."""

from enum import Enum


class SBOMFormat(str, Enum):
    """SBOM format types."""

    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"
    UNKNOWN = "unknown"


class SBOMVersion(str, Enum):
    """SBOM specification versions."""

    CYCLONEDX_1_4 = "1.4"
    CYCLONEDX_1_5 = "1.5"
    CYCLONEDX_1_6 = "1.6"
    SPDX_2_3 = "2.3"
    SPDX_3_0 = "3.0"


class ComponentType(str, Enum):
    """Component types in SBOM."""

    APPLICATION = "application"
    FRAMEWORK = "framework"
    LIBRARY = "library"
    CONTAINER = "container"
    OPERATING_SYSTEM = "operating-system"
    DEVICE = "device"
    FIRMWARE = "firmware"
    FILE = "file"


class VulnerabilitySeverity(str, Enum):
    """CVE severity levels based on CVSS."""

    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"  # 7.0-8.9
    MEDIUM = "medium"  # 4.0-6.9
    LOW = "low"  # 0.1-3.9
    NONE = "none"  # 0.0
    UNKNOWN = "unknown"


class LicenseRiskLevel(str, Enum):
    """License risk categories."""

    HIGH = "high"  # Copyleft (GPL, AGPL)
    MEDIUM = "medium"  # Weak copyleft (LGPL, MPL)
    LOW = "low"  # Permissive (MIT, Apache, BSD)
    UNKNOWN = "unknown"


class SLSALevel(int, Enum):
    """SLSA Framework levels."""

    LEVEL_0 = 0
    LEVEL_1 = 1
    LEVEL_2 = 2
    LEVEL_3 = 3
    LEVEL_4 = 4


class RiskLevel(str, Enum):
    """Overall risk assessment levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class ScanStatus(str, Enum):
    """SBOM scan status."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class HashAlgorithm(str, Enum):
    """Supported hash algorithms."""

    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
