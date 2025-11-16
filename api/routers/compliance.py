"""Compliance validation API endpoints."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from src.compliance.ntia import NTIAValidator
from src.compliance.report_generator import ReportGenerator
from src.compliance.slsa import SLSAValidator
from src.database import SBOM, get_db

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/{sbom_id}/slsa")
def validate_slsa(sbom_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Validate SBOM against SLSA framework."""
    sbom = db.query(SBOM).filter(SBOM.id == sbom_id).first()

    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    validator = SLSAValidator()
    results = validator.validate_sbom(sbom.raw_sbom or {})

    # Update SBOM record
    sbom.slsa_level = results["achieved_level"]
    db.commit()

    return results


@router.get("/{sbom_id}/ntia")
def validate_ntia(sbom_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Validate SBOM against NTIA minimum elements."""
    sbom = db.query(SBOM).filter(SBOM.id == sbom_id).first()

    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    validator = NTIAValidator()
    results = validator.validate_sbom(sbom.raw_sbom or {})

    # Update SBOM record
    sbom.ntia_compliant = results["compliant"]
    db.commit()

    return results


@router.get("/{sbom_id}/report", response_class=HTMLResponse)
def generate_report(sbom_id: int, db: Session = Depends(get_db)) -> str:
    """Generate comprehensive compliance and risk report."""
    sbom = db.query(SBOM).filter(SBOM.id == sbom_id).first()

    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    # Gather data
    sbom_data = {
        "name": sbom.name,
        "version": sbom.version,
        "total_components": sbom.total_components,
    }

    risk_data = {
        "risk_score": sbom.overall_risk_score or 0,
        "risk_level": sbom.overall_risk_level.value if sbom.overall_risk_level else "unknown",
        "total_vulnerabilities": sbom.total_vulnerabilities,
        "critical_vulns": sbom.critical_vulns,
        "high_vulns": sbom.high_vulns,
        "medium_vulns": sbom.medium_vulns,
        "low_vulns": sbom.low_vulns,
        "top_vulnerable_components": [
            {
                "name": sc.component.name,
                "version": sc.component.version,
                "risk_level": sc.risk_level.value if sc.risk_level else "unknown",
                "vuln_count": sc.vuln_count,
            }
            for sc in sorted(
                sbom.components,
                key=lambda x: (x.risk_score or 0),
                reverse=True,
            )[:10]
        ],
    }

    # Validate compliance
    slsa_validator = SLSAValidator()
    ntia_validator = NTIAValidator()

    compliance_data = {
        "slsa": slsa_validator.validate_sbom(sbom.raw_sbom or {}),
        "ntia": ntia_validator.validate_sbom(sbom.raw_sbom or {}),
    }

    # Generate HTML report
    generator = ReportGenerator()
    html = generator.generate_html_report(sbom_data, risk_data, compliance_data)

    return html
