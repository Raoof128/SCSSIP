"""NTIA Minimum Elements for SBOM validation."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class NTIAValidator:
    """
    Validator for NTIA minimum elements.

    NTIA defines 7 baseline requirements for SBOMs:
    1. Supplier Name
    2. Component Name
    3. Version of Component
    4. Other Unique Identifiers
    5. Dependency Relationships
    6. Author of SBOM Data
    7. Timestamp
    """

    REQUIRED_ELEMENTS = [
        "supplier_name",
        "component_name",
        "component_version",
        "unique_identifier",
        "dependency_relationships",
        "sbom_author",
        "timestamp",
    ]

    def __init__(self) -> None:
        """Initialize NTIA validator."""
        pass

    def validate_sbom(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """
        Validate SBOM against NTIA minimum elements.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            Dictionary with validation results
        """
        checks = {}
        issues = []

        # 1. Supplier Name
        supplier = self._check_supplier(sbom_data)
        checks["supplier_name"] = supplier["valid"]
        if not supplier["valid"]:
            issues.append(supplier["issue"])

        # 2-4. Component Name, Version, Unique Identifier
        components_check = self._check_components(sbom_data)
        checks["component_name"] = components_check["has_names"]
        checks["component_version"] = components_check["has_versions"]
        checks["unique_identifier"] = components_check["has_identifiers"]
        issues.extend(components_check["issues"])

        # 5. Dependency Relationships
        dependencies = self._check_dependencies(sbom_data)
        checks["dependency_relationships"] = dependencies["valid"]
        if not dependencies["valid"]:
            issues.append(dependencies["issue"])

        # 6. Author of SBOM Data
        author = self._check_author(sbom_data)
        checks["sbom_author"] = author["valid"]
        if not author["valid"]:
            issues.append(author["issue"])

        # 7. Timestamp
        timestamp_check = self._check_timestamp(sbom_data)
        checks["timestamp"] = timestamp_check["valid"]
        if not timestamp_check["valid"]:
            issues.append(timestamp_check["issue"])

        # Overall compliance
        compliant = all(checks.values())
        compliance_percentage = (
            sum(1 for v in checks.values() if v) / len(checks) * 100
        )

        return {
            "compliant": compliant,
            "compliance_percentage": compliance_percentage,
            "checks": checks,
            "issues": issues,
            "missing_elements": [
                element
                for element, valid in zip(self.REQUIRED_ELEMENTS, checks.values())
                if not valid
            ],
        }

    def _check_supplier(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Check supplier name element."""
        supplier_name = sbom_data.get("supplier_name") or sbom_data.get(
            "manufacturer_name"
        )

        # Also check main component
        main_comp = sbom_data.get("main_component", {})
        if not supplier_name and main_comp:
            supplier_name = main_comp.get("supplier_name") or main_comp.get(
                "publisher"
            )

        if supplier_name:
            return {"valid": True}
        else:
            return {
                "valid": False,
                "issue": "Missing supplier/manufacturer name",
            }

    def _check_components(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Check component name, version, and unique identifier elements."""
        components = sbom_data.get("components", [])

        if not components:
            return {
                "has_names": False,
                "has_versions": False,
                "has_identifiers": False,
                "issues": ["No components found in SBOM"],
            }

        total = len(components)
        has_name = 0
        has_version = 0
        has_identifier = 0
        issues = []

        for comp in components:
            if comp.get("name"):
                has_name += 1

            if comp.get("version"):
                has_version += 1

            # Unique identifier = PURL, CPE, or bom-ref
            if comp.get("purl") or comp.get("cpe") or comp.get("bom_ref"):
                has_identifier += 1

        # Require 95%+ coverage
        threshold = 0.95

        has_names_valid = has_name / total >= threshold
        has_versions_valid = has_version / total >= threshold
        has_identifiers_valid = has_identifier / total >= threshold

        if not has_names_valid:
            issues.append(
                f"Only {has_name}/{total} components have names (need 95%+)"
            )

        if not has_versions_valid:
            issues.append(
                f"Only {has_version}/{total} components have versions (need 95%+)"
            )

        if not has_identifiers_valid:
            issues.append(
                f"Only {has_identifier}/{total} components have unique identifiers (need 95%+)"
            )

        return {
            "has_names": has_names_valid,
            "has_versions": has_versions_valid,
            "has_identifiers": has_identifiers_valid,
            "issues": issues,
        }

    def _check_dependencies(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Check dependency relationships element."""
        dependency_graph = sbom_data.get("dependency_graph", {})

        if dependency_graph and len(dependency_graph) > 0:
            return {"valid": True}
        else:
            return {
                "valid": False,
                "issue": "Missing dependency relationship information",
            }

    def _check_author(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Check SBOM author element."""
        authors = sbom_data.get("authors", [])

        if authors and len(authors) > 0:
            # Check if author has name or email
            for author in authors:
                if author.get("name") or author.get("email"):
                    return {"valid": True}

        return {
            "valid": False,
            "issue": "Missing SBOM author information",
        }

    def _check_timestamp(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Check timestamp element."""
        timestamp = sbom_data.get("timestamp")

        if timestamp:
            return {"valid": True}
        else:
            return {
                "valid": False,
                "issue": "Missing SBOM generation timestamp",
            }

    def generate_report(self, validation_results: dict[str, Any]) -> str:
        """
        Generate human-readable NTIA compliance report.

        Args:
            validation_results: Results from validate_sbom()

        Returns:
            Formatted report string
        """
        status = "COMPLIANT" if validation_results["compliant"] else "NON-COMPLIANT"
        percentage = validation_results["compliance_percentage"]

        report = f"NTIA Minimum Elements Compliance Report\n"
        report += "=" * 50 + "\n\n"
        report += f"Status: {status} ({percentage:.1f}%)\n\n"

        report += "Required Elements:\n"
        for element, valid in validation_results["checks"].items():
            status_icon = "✓" if valid else "✗"
            report += f"  {status_icon} {element.replace('_', ' ').title()}\n"

        if validation_results["issues"]:
            report += "\nIssues:\n"
            for issue in validation_results["issues"]:
                report += f"  - {issue}\n"

        if validation_results["missing_elements"]:
            report += "\nMissing Elements:\n"
            for element in validation_results["missing_elements"]:
                report += f"  - {element.replace('_', ' ').title()}\n"

        return report
