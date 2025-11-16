"""Multi-factor risk scoring calculator."""

import logging
from typing import Any

from src.common.config import get_settings
from src.common.enums import LicenseRiskLevel, RiskLevel, VulnerabilitySeverity

logger = logging.getLogger(__name__)
settings = get_settings()


class RiskCalculator:
    """
    Multi-factor risk scoring algorithm.

    Factors:
    - Vulnerability severity/count (40%)
    - License risk (20%)
    - Artifact signing status (20%)
    - Maintainer health (10%)
    - Dependency depth (10%)
    """

    def __init__(self) -> None:
        """Initialize risk calculator with configurable weights."""
        self.vuln_weight = settings.vulnerability_weight
        self.license_weight = settings.license_risk_weight
        self.signing_weight = settings.signing_weight
        self.maintainer_weight = settings.maintainer_health_weight
        self.depth_weight = settings.dependency_depth_weight

    def calculate_component_risk(
        self,
        vulnerabilities: list[dict[str, Any]],
        licenses: list[dict[str, Any]],
        is_signed: bool = False,
        dependency_depth: int = 0,
        maintainer_data: dict[str, Any] | None = None,
    ) -> tuple[float, RiskLevel]:
        """
        Calculate overall risk score for a component.

        Args:
            vulnerabilities: List of vulnerability dictionaries
            licenses: List of license dictionaries
            is_signed: Whether artifact is digitally signed
            dependency_depth: Transitive dependency depth (0 = direct)
            maintainer_data: Optional maintainer health metrics

        Returns:
            Tuple of (risk_score, risk_level)
            Risk score is 0-10, where 10 is highest risk
        """
        # Calculate each factor
        vuln_score = self._calculate_vulnerability_score(vulnerabilities)
        license_score = self._calculate_license_risk_score(licenses)
        signing_score = self._calculate_signing_score(is_signed)
        maintainer_score = self._calculate_maintainer_score(maintainer_data or {})
        depth_score = self._calculate_depth_score(dependency_depth)

        # Weighted average
        total_score = (
            vuln_score * self.vuln_weight
            + license_score * self.license_weight
            + signing_score * self.signing_weight
            + maintainer_score * self.maintainer_weight
            + depth_score * self.depth_weight
        )

        # Clamp to 0-10
        total_score = max(0.0, min(10.0, total_score))

        # Map to risk level
        risk_level = self._score_to_level(total_score)

        logger.debug(
            f"Risk calculation: vuln={vuln_score:.2f}, "
            f"license={license_score:.2f}, signing={signing_score:.2f}, "
            f"maintainer={maintainer_score:.2f}, depth={depth_score:.2f}, "
            f"total={total_score:.2f} ({risk_level.value})"
        )

        return total_score, risk_level

    def _calculate_vulnerability_score(
        self, vulnerabilities: list[dict[str, Any]]
    ) -> float:
        """
        Calculate vulnerability risk score (0-10).

        Considers:
        - Number of vulnerabilities
        - Severity distribution
        - EPSS scores
        - Age of vulnerabilities
        """
        if not vulnerabilities:
            return 0.0

        # Count by severity
        severity_counts = {
            VulnerabilitySeverity.CRITICAL: 0,
            VulnerabilitySeverity.HIGH: 0,
            VulnerabilitySeverity.MEDIUM: 0,
            VulnerabilitySeverity.LOW: 0,
        }

        epss_scores = []

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown")
            try:
                sev_enum = VulnerabilitySeverity(severity.lower())
                if sev_enum in severity_counts:
                    severity_counts[sev_enum] += 1
            except ValueError:
                pass

            # Collect EPSS scores
            epss = vuln.get("epss_score")
            if epss is not None:
                epss_scores.append(epss)

        # Weighted severity score
        # Critical = 10, High = 7, Medium = 4, Low = 1
        severity_score = (
            severity_counts[VulnerabilitySeverity.CRITICAL] * 10.0
            + severity_counts[VulnerabilitySeverity.HIGH] * 7.0
            + severity_counts[VulnerabilitySeverity.MEDIUM] * 4.0
            + severity_counts[VulnerabilitySeverity.LOW] * 1.0
        )

        # Normalize by dividing by expected max (capped at reasonable level)
        # Assume 1 critical = 10, so cap at 10
        severity_score = min(10.0, severity_score)

        # EPSS boost (if available)
        epss_boost = 0.0
        if epss_scores:
            avg_epss = sum(epss_scores) / len(epss_scores)
            # EPSS ranges 0-1, convert to 0-2 boost
            epss_boost = avg_epss * 2.0

        # Combine severity and EPSS
        total = min(10.0, severity_score + epss_boost)

        return total

    def _calculate_license_risk_score(self, licenses: list[dict[str, Any]]) -> float:
        """
        Calculate license risk score (0-10).

        Factors:
        - Copyleft licenses (GPL, AGPL) = HIGH risk
        - Weak copyleft (LGPL, MPL) = MEDIUM risk
        - Permissive (MIT, Apache) = LOW risk
        - Unknown = MEDIUM risk
        """
        if not licenses:
            return 5.0  # Unknown = medium risk

        risk_scores = []

        for lic in licenses:
            risk_level = lic.get("risk_level", "unknown")

            if isinstance(risk_level, str):
                try:
                    risk_level = LicenseRiskLevel(risk_level.lower())
                except ValueError:
                    risk_level = LicenseRiskLevel.UNKNOWN

            # Map to score
            if risk_level == LicenseRiskLevel.HIGH:
                risk_scores.append(10.0)
            elif risk_level == LicenseRiskLevel.MEDIUM:
                risk_scores.append(5.0)
            elif risk_level == LicenseRiskLevel.LOW:
                risk_scores.append(1.0)
            else:
                risk_scores.append(5.0)  # Unknown

        if not risk_scores:
            return 5.0

        # Use highest risk license
        return max(risk_scores)

    def _calculate_signing_score(self, is_signed: bool) -> float:
        """
        Calculate artifact signing risk score (0-10).

        Unsigned artifacts have higher risk.
        """
        if is_signed:
            return 0.0  # Signed = low risk
        else:
            return 7.0  # Unsigned = high risk

    def _calculate_maintainer_score(self, maintainer_data: dict[str, Any]) -> float:
        """
        Calculate maintainer health risk score (0-10).

        Factors:
        - Last commit date (staleness)
        - Number of contributors
        - Repository activity
        """
        if not maintainer_data:
            return 5.0  # Unknown = medium risk

        risk = 0.0

        # Last commit staleness (0-5 points)
        days_since_commit = maintainer_data.get("days_since_last_commit", 0)
        if days_since_commit > 730:  # 2+ years
            risk += 5.0
        elif days_since_commit > 365:  # 1+ year
            risk += 3.0
        elif days_since_commit > 180:  # 6+ months
            risk += 1.0

        # Contributor count (0-3 points)
        contributors = maintainer_data.get("contributor_count", 0)
        if contributors == 0:
            risk += 3.0
        elif contributors == 1:
            risk += 2.0  # Single maintainer = bus factor risk

        # Repository stars/forks (0-2 points)
        stars = maintainer_data.get("stars", 0)
        if stars < 10:
            risk += 2.0
        elif stars < 100:
            risk += 1.0

        return min(10.0, risk)

    def _calculate_depth_score(self, dependency_depth: int) -> float:
        """
        Calculate dependency depth risk score (0-10).

        Deeper transitive dependencies have higher risk
        (harder to track, less visibility).
        """
        # Direct dependency (0) = low risk
        # Depth 1-2 = medium risk
        # Depth 3+ = high risk

        if dependency_depth == 0:
            return 2.0  # Direct = low risk but not zero
        elif dependency_depth == 1:
            return 4.0
        elif dependency_depth == 2:
            return 6.0
        elif dependency_depth == 3:
            return 8.0
        else:
            return 10.0  # 4+ levels deep

    def _score_to_level(self, score: float) -> RiskLevel:
        """Map numeric score to risk level enum."""
        if score >= settings.critical_risk_threshold:
            return RiskLevel.CRITICAL
        elif score >= settings.high_risk_threshold:
            return RiskLevel.HIGH
        elif score >= settings.medium_risk_threshold:
            return RiskLevel.MEDIUM
        elif score >= 2.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL

    def calculate_sbom_risk(
        self, component_risks: list[tuple[float, RiskLevel]]
    ) -> tuple[float, RiskLevel]:
        """
        Calculate overall SBOM risk from component risks.

        Uses weighted approach favoring highest risks.

        Args:
            component_risks: List of (score, level) tuples

        Returns:
            Tuple of (overall_score, overall_level)
        """
        if not component_risks:
            return 0.0, RiskLevel.MINIMAL

        scores = [score for score, _ in component_risks]

        # Use weighted approach:
        # - Highest 10% of components count for 50%
        # - Remaining components count for 50%
        scores_sorted = sorted(scores, reverse=True)
        top_10_percent = max(1, len(scores_sorted) // 10)

        top_avg = sum(scores_sorted[:top_10_percent]) / top_10_percent
        remaining_avg = (
            sum(scores_sorted[top_10_percent:]) / len(scores_sorted[top_10_percent:])
            if len(scores_sorted) > top_10_percent
            else 0.0
        )

        overall_score = top_avg * 0.5 + remaining_avg * 0.5

        return overall_score, self._score_to_level(overall_score)
