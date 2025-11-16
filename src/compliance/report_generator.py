"""PDF and HTML report generation for compliance and risk assessments."""

import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate compliance and risk assessment reports."""

    def __init__(self) -> None:
        """Initialize report generator."""
        pass

    def generate_html_report(
        self,
        sbom_data: dict[str, Any],
        risk_data: dict[str, Any],
        compliance_data: dict[str, Any],
    ) -> str:
        """
        Generate comprehensive HTML report.

        Args:
            sbom_data: SBOM information
            risk_data: Risk assessment data
            compliance_data: Compliance validation data

        Returns:
            HTML report string
        """
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SBOM Security Report - {sbom_data.get('name', 'Unknown')}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 5px;
        }}
        .section {{
            margin: 20px 0;
        }}
        .metric {{
            display: inline-block;
            margin: 10px 20px 10px 0;
            padding: 15px;
            background-color: #ecf0f1;
            border-radius: 5px;
            min-width: 150px;
        }}
        .metric-label {{
            font-size: 12px;
            color: #7f8c8d;
            text-transform: uppercase;
        }}
        .metric-value {{
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
        }}
        .risk-critical {{ color: #c0392b; }}
        .risk-high {{ color: #e67e22; }}
        .risk-medium {{ color: #f39c12; }}
        .risk-low {{ color: #27ae60; }}
        .status-pass {{ color: #27ae60; }}
        .status-fail {{ color: #c0392b; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }}
        th {{
            background-color: #34495e;
            color: white;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
        }}
        .badge-critical {{ background-color: #c0392b; color: white; }}
        .badge-high {{ background-color: #e67e22; color: white; }}
        .badge-medium {{ background-color: #f39c12; color: white; }}
        .badge-low {{ background-color: #27ae60; color: white; }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            font-size: 12px;
            color: #7f8c8d;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Supply Chain Security Assessment Report</h1>
        <p><strong>SBOM:</strong> {sbom_data.get('name', 'Unknown')} v{sbom_data.get('version', 'N/A')}</p>
        <p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

        <h2>Executive Summary</h2>
        <div class="section">
            <div class="metric">
                <div class="metric-label">Risk Level</div>
                <div class="metric-value risk-{risk_data.get('risk_level', 'unknown').lower()}">
                    {risk_data.get('risk_level', 'Unknown').upper()}
                </div>
            </div>
            <div class="metric">
                <div class="metric-label">Risk Score</div>
                <div class="metric-value">{risk_data.get('risk_score', 0):.2f}/10</div>
            </div>
            <div class="metric">
                <div class="metric-label">Components</div>
                <div class="metric-value">{sbom_data.get('total_components', 0)}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Vulnerabilities</div>
                <div class="metric-value">{risk_data.get('total_vulnerabilities', 0)}</div>
            </div>
        </div>

        <h2>Vulnerability Summary</h2>
        <div class="section">
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
                <tr>
                    <td><span class="badge badge-critical">CRITICAL</span></td>
                    <td>{risk_data.get('critical_vulns', 0)}</td>
                </tr>
                <tr>
                    <td><span class="badge badge-high">HIGH</span></td>
                    <td>{risk_data.get('high_vulns', 0)}</td>
                </tr>
                <tr>
                    <td><span class="badge badge-medium">MEDIUM</span></td>
                    <td>{risk_data.get('medium_vulns', 0)}</td>
                </tr>
                <tr>
                    <td><span class="badge badge-low">LOW</span></td>
                    <td>{risk_data.get('low_vulns', 0)}</td>
                </tr>
            </table>
        </div>

        <h2>Compliance Status</h2>
        <div class="section">
            <h3>SLSA Framework</h3>
            <p><strong>Achieved Level:</strong> Level {compliance_data.get('slsa', {}).get('achieved_level', 0)}</p>

            <h3>NTIA Minimum Elements</h3>
            <p class="{'status-pass' if compliance_data.get('ntia', {}).get('compliant') else 'status-fail'}">
                <strong>Status:</strong> {'COMPLIANT' if compliance_data.get('ntia', {}).get('compliant') else 'NON-COMPLIANT'}
                ({compliance_data.get('ntia', {}).get('compliance_percentage', 0):.1f}%)
            </p>
        </div>

        <h2>Top Vulnerable Components</h2>
        <div class="section">
            <table>
                <tr>
                    <th>Component</th>
                    <th>Version</th>
                    <th>Risk</th>
                    <th>Vulnerabilities</th>
                </tr>
"""

        # Add top 10 vulnerable components
        top_components = risk_data.get("top_vulnerable_components", [])[:10]
        for comp in top_components:
            html += f"""
                <tr>
                    <td>{comp.get('name', 'Unknown')}</td>
                    <td>{comp.get('version', 'N/A')}</td>
                    <td><span class="badge badge-{comp.get('risk_level', 'low').lower()}">{comp.get('risk_level', 'Unknown').upper()}</span></td>
                    <td>{comp.get('vuln_count', 0)}</td>
                </tr>
"""

        html += """
            </table>
        </div>

        <h2>Recommendations</h2>
        <div class="section">
            <ul>
"""

        # Generate recommendations
        recommendations = self._generate_recommendations(risk_data, compliance_data)
        for rec in recommendations:
            html += f"                <li>{rec}</li>\n"

        html += """
            </ul>
        </div>

        <div class="footer">
            Generated by SBOM Security Platform | Supply Chain Intelligence
        </div>
    </div>
</body>
</html>
"""

        return html

    def _generate_recommendations(
        self, risk_data: dict[str, Any], compliance_data: dict[str, Any]
    ) -> list[str]:
        """Generate security recommendations based on assessment."""
        recommendations = []

        # Vulnerability recommendations
        critical = risk_data.get("critical_vulns", 0)
        high = risk_data.get("high_vulns", 0)

        if critical > 0:
            recommendations.append(
                f"<strong>URGENT:</strong> Address {critical} CRITICAL vulnerabilities immediately"
            )

        if high > 0:
            recommendations.append(
                f"Address {high} HIGH severity vulnerabilities within 7 days"
            )

        # SLSA recommendations
        slsa_level = compliance_data.get("slsa", {}).get("achieved_level", 0)
        if slsa_level < 2:
            recommendations.append(
                "Implement artifact signing to achieve SLSA Level 2"
            )

        if slsa_level < 3:
            recommendations.append(
                "Use isolated build environments to achieve SLSA Level 3"
            )

        # NTIA recommendations
        if not compliance_data.get("ntia", {}).get("compliant"):
            missing = compliance_data.get("ntia", {}).get("missing_elements", [])
            if missing:
                recommendations.append(
                    f"Complete NTIA minimum elements: {', '.join(missing[:3])}"
                )

        # Risk-based recommendations
        risk_level = risk_data.get("risk_level", "").lower()
        if risk_level in ["critical", "high"]:
            recommendations.append(
                "Consider alternative components with lower risk profiles"
            )
            recommendations.append(
                "Implement runtime application self-protection (RASP)"
            )

        if not recommendations:
            recommendations.append("Continue monitoring for new vulnerabilities")
            recommendations.append("Maintain current security posture")

        return recommendations

    def save_html_report(self, html_content: str, file_path: str) -> None:
        """Save HTML report to file."""
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"Report saved to {file_path}")
