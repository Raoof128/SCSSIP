"""Risk scoring service for SBOMs and components."""

import logging
from typing import Any

from sqlalchemy.orm import Session

from src.common.enums import RiskLevel
from src.database.models import Component, SBOM, SBOMComponent
from src.risk_scoring.calculator import RiskCalculator

logger = logging.getLogger(__name__)


class RiskScoringService:
    """Service for calculating and updating risk scores."""

    def __init__(self, db: Session) -> None:
        """
        Initialize risk scoring service.

        Args:
            db: Database session
        """
        self.db = db
        self.calculator = RiskCalculator()

    def score_component(self, component: Component, sbom_component: SBOMComponent | None = None) -> tuple[float, RiskLevel]:
        """
        Calculate risk score for a component.

        Args:
            component: Component to score
            sbom_component: Optional SBOM-component association for context

        Returns:
            Tuple of (risk_score, risk_level)
        """
        # Gather vulnerability data
        vulnerabilities = [
            {
                "severity": v.severity.value if v.severity else "unknown",
                "cvss_score": v.cvss_score,
                "epss_score": v.epss_score,
            }
            for v in component.vulnerabilities
        ]

        # Gather license data
        licenses = [
            {
                "name": cl.license.name,
                "risk_level": cl.license.risk_level,
                "is_copyleft": cl.license.is_copyleft,
            }
            for cl in component.licenses
        ]

        # Get dependency depth
        depth = sbom_component.dependency_depth if sbom_component else 0

        # Check if component has signatures (via hashes)
        is_signed = len(component.hashes) > 0  # Simplified

        # Calculate risk
        score, level = self.calculator.calculate_component_risk(
            vulnerabilities=vulnerabilities,
            licenses=licenses,
            is_signed=is_signed,
            dependency_depth=depth,
            maintainer_data={},  # TODO: Fetch from repository metadata
        )

        logger.info(
            f"Component {component.name} risk: {score:.2f} ({level.value})"
        )

        return score, level

    def score_sbom(self, sbom: SBOM) -> tuple[float, RiskLevel]:
        """
        Calculate overall risk score for an SBOM.

        Args:
            sbom: SBOM to score

        Returns:
            Tuple of (risk_score, risk_level)
        """
        logger.info(f"Scoring SBOM: {sbom.name}")

        component_risks: list[tuple[float, RiskLevel]] = []

        # Score each component
        for sbom_comp in sbom.components:
            component = sbom_comp.component
            score, level = self.score_component(component, sbom_comp)

            # Update SBOM-component risk
            sbom_comp.risk_score = score
            sbom_comp.risk_level = level

            component_risks.append((score, level))

        # Calculate overall SBOM risk
        overall_score, overall_level = self.calculator.calculate_sbom_risk(
            component_risks
        )

        # Update SBOM record
        sbom.overall_risk_score = overall_score
        sbom.overall_risk_level = overall_level

        # Update vulnerability counts
        self._update_sbom_vuln_counts(sbom)

        self.db.commit()

        logger.info(
            f"SBOM {sbom.name} overall risk: {overall_score:.2f} ({overall_level.value})"
        )

        return overall_score, overall_level

    def score_all_sboms(self) -> dict[str, Any]:
        """
        Score all SBOMs in the database.

        Returns:
            Dictionary with scoring statistics
        """
        sboms = self.db.query(SBOM).all()
        total = len(sboms)

        logger.info(f"Scoring {total} SBOMs")

        risk_distribution = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "minimal": 0,
        }

        for sbom in sboms:
            try:
                score, level = self.score_sbom(sbom)
                risk_distribution[level.value] += 1
            except Exception as e:
                logger.error(f"Failed to score SBOM {sbom.name}: {e}")

        return {
            "total_sboms": total,
            "risk_distribution": risk_distribution,
        }

    def _update_sbom_vuln_counts(self, sbom: SBOM) -> None:
        """Update vulnerability count statistics for SBOM."""
        critical = 0
        high = 0
        medium = 0
        low = 0
        total = 0

        for sbom_comp in sbom.components:
            for vuln in sbom_comp.component.vulnerabilities:
                total += 1
                if vuln.severity:
                    sev = vuln.severity.value
                    if sev == "critical":
                        critical += 1
                    elif sev == "high":
                        high += 1
                    elif sev == "medium":
                        medium += 1
                    elif sev == "low":
                        low += 1

        sbom.total_vulnerabilities = total
        sbom.critical_vulns = critical
        sbom.high_vulns = high
        sbom.medium_vulns = medium
        sbom.low_vulns = low
