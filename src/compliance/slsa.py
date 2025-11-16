"""SLSA (Supply-chain Levels for Software Artifacts) framework validation."""

import logging
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class SLSALevel(Enum):
    """SLSA levels."""

    LEVEL_0 = 0
    LEVEL_1 = 1
    LEVEL_2 = 2
    LEVEL_3 = 3
    LEVEL_4 = 4


class SLSAValidator:
    """Validator for SLSA framework compliance."""

    def __init__(self) -> None:
        """Initialize SLSA validator."""
        pass

    def validate_sbom(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """
        Validate SBOM against SLSA requirements.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            Dictionary with validation results
        """
        results = {
            "level_0": self._check_level_0(sbom_data),
            "level_1": self._check_level_1(sbom_data),
            "level_2": self._check_level_2(sbom_data),
            "level_3": self._check_level_3(sbom_data),
            "achieved_level": SLSALevel.LEVEL_0.value,
            "issues": [],
        }

        # Determine highest achieved level
        if results["level_3"]["compliant"]:
            results["achieved_level"] = SLSALevel.LEVEL_3.value
        elif results["level_2"]["compliant"]:
            results["achieved_level"] = SLSALevel.LEVEL_2.value
        elif results["level_1"]["compliant"]:
            results["achieved_level"] = SLSALevel.LEVEL_1.value

        # Collect all issues
        for level_key in ["level_1", "level_2", "level_3"]:
            results["issues"].extend(results[level_key].get("issues", []))

        return results

    def _check_level_0(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """
        SLSA Level 0: No guarantees.

        This is the baseline - any SBOM passes.
        """
        return {
            "compliant": True,
            "description": "No requirements",
            "checks": {},
        }

    def _check_level_1(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """
        SLSA Level 1: Documentation of build process.

        Requirements:
        - Build process is documented
        - Provenance exists (who built it, when, what)
        """
        checks = {}
        issues = []

        # Check for build metadata
        has_metadata = bool(sbom_data.get("metadata"))
        checks["has_metadata"] = has_metadata
        if not has_metadata:
            issues.append("Missing SBOM metadata")

        # Check for timestamp (when built)
        has_timestamp = bool(sbom_data.get("timestamp"))
        checks["has_timestamp"] = has_timestamp
        if not has_timestamp:
            issues.append("Missing build timestamp")

        # Check for tools/authors (who built it)
        has_tools = bool(sbom_data.get("tools")) or bool(sbom_data.get("authors"))
        checks["has_build_info"] = has_tools
        if not has_tools:
            issues.append("Missing build tool/author information")

        compliant = all(checks.values())

        return {
            "compliant": compliant,
            "description": "Build process documented with provenance",
            "checks": checks,
            "issues": issues,
        }

    def _check_level_2(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """
        SLSA Level 2: Tamper resistance.

        Requirements:
        - All Level 1 requirements
        - Build service generated provenance
        - Artifact is signed or has cryptographic hash
        """
        # First check Level 1
        level_1 = self._check_level_1(sbom_data)
        if not level_1["compliant"]:
            return {
                "compliant": False,
                "description": "Tamper-resistant provenance with signed artifacts",
                "checks": level_1["checks"],
                "issues": level_1["issues"] + ["Level 1 not met"],
            }

        checks = level_1["checks"].copy()
        issues = level_1["issues"].copy()

        # Check for signatures
        is_signed = sbom_data.get("is_signed", False)
        checks["is_signed"] = is_signed

        # Check for component hashes
        components = sbom_data.get("components", [])
        components_with_hashes = sum(
            1 for comp in components if comp.get("hashes")
        )
        has_hashes = len(components) > 0 and components_with_hashes / len(components) >= 0.8
        checks["components_have_hashes"] = has_hashes

        if not is_signed and not has_hashes:
            issues.append(
                "Missing signatures and insufficient component hashes (need 80%+)"
            )

        compliant = all(checks.values())

        return {
            "compliant": compliant,
            "description": "Tamper-resistant provenance with signed artifacts",
            "checks": checks,
            "issues": issues,
        }

    def _check_level_3(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """
        SLSA Level 3: Extra resistance to specific threats.

        Requirements:
        - All Level 2 requirements
        - Build process is isolated
        - Provenance is non-falsifiable
        - Strong cryptographic signatures
        """
        # First check Level 2
        level_2 = self._check_level_2(sbom_data)
        if not level_2["compliant"]:
            return {
                "compliant": False,
                "description": "Auditable build with non-falsifiable provenance",
                "checks": level_2["checks"],
                "issues": level_2["issues"] + ["Level 2 not met"],
            }

        checks = level_2["checks"].copy()
        issues = level_2["issues"].copy()

        # Check for strong signatures (not just hashes)
        is_signed = sbom_data.get("is_signed", False)
        checks["has_strong_signature"] = is_signed
        if not is_signed:
            issues.append("Missing cryptographic signature (required for Level 3)")

        # Check signature algorithm strength
        signature = sbom_data.get("signature")
        if signature:
            algorithm = signature.get("algorithm", "").upper()
            strong_algorithms = ["RSA", "ECDSA", "ED25519"]
            is_strong = any(alg in algorithm for alg in strong_algorithms)
            checks["strong_signature_algorithm"] = is_strong
            if not is_strong:
                issues.append(f"Weak signature algorithm: {algorithm}")
        else:
            checks["strong_signature_algorithm"] = False
            issues.append("No signature algorithm specified")

        # Check for component-level signatures
        components = sbom_data.get("components", [])
        components_signed = sum(
            1 for comp in components if comp.get("hashes") and len(comp.get("hashes", [])) > 0
        )
        high_coverage = len(components) > 0 and components_signed / len(components) >= 0.95
        checks["high_component_hash_coverage"] = high_coverage
        if not high_coverage:
            issues.append("Insufficient component hash coverage (need 95%+ for Level 3)")

        compliant = all(checks.values())

        return {
            "compliant": compliant,
            "description": "Auditable build with non-falsifiable provenance",
            "checks": checks,
            "issues": issues,
        }

    def generate_report(self, validation_results: dict[str, Any]) -> str:
        """
        Generate human-readable SLSA compliance report.

        Args:
            validation_results: Results from validate_sbom()

        Returns:
            Formatted report string
        """
        level = validation_results["achieved_level"]
        report = f"SLSA Framework Compliance Report\n"
        report += "=" * 50 + "\n\n"
        report += f"Achieved Level: {level}\n\n"

        for level_num in range(1, 4):
            level_key = f"level_{level_num}"
            level_data = validation_results[level_key]

            status = "✓ PASS" if level_data["compliant"] else "✗ FAIL"
            report += f"Level {level_num}: {status}\n"
            report += f"  {level_data['description']}\n"

            if level_data.get("checks"):
                report += "  Checks:\n"
                for check_name, passed in level_data["checks"].items():
                    check_status = "✓" if passed else "✗"
                    report += f"    {check_status} {check_name}\n"

            if level_data.get("issues"):
                report += "  Issues:\n"
                for issue in level_data["issues"]:
                    report += f"    - {issue}\n"

            report += "\n"

        return report
