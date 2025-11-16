"""Risk scoring API endpoints."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from src.database import SBOM, get_db
from src.risk_scoring.service import RiskScoringService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/score/{sbom_id}")
def score_sbom(sbom_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Calculate risk score for an SBOM."""
    sbom = db.query(SBOM).filter(SBOM.id == sbom_id).first()

    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    service = RiskScoringService(db)
    score, level = service.score_sbom(sbom)

    return {
        "sbom_id": sbom_id,
        "risk_score": score,
        "risk_level": level.value,
        "vulnerability_counts": {
            "critical": sbom.critical_vulns,
            "high": sbom.high_vulns,
            "medium": sbom.medium_vulns,
            "low": sbom.low_vulns,
        },
    }


@router.get("/{sbom_id}")
def get_risk_assessment(sbom_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Get risk assessment for an SBOM."""
    sbom = db.query(SBOM).filter(SBOM.id == sbom_id).first()

    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    # Get top vulnerable components
    top_components = sorted(
        sbom.components,
        key=lambda sc: (sc.risk_score or 0, sc.vuln_count),
        reverse=True,
    )[:10]

    return {
        "sbom_id": sbom_id,
        "overall_risk_score": sbom.overall_risk_score,
        "overall_risk_level": sbom.overall_risk_level.value if sbom.overall_risk_level else None,
        "total_components": sbom.total_components,
        "total_vulnerabilities": sbom.total_vulnerabilities,
        "top_vulnerable_components": [
            {
                "name": sc.component.name,
                "version": sc.component.version,
                "risk_score": sc.risk_score,
                "risk_level": sc.risk_level.value if sc.risk_level else None,
                "vuln_count": sc.vuln_count,
            }
            for sc in top_components
        ],
    }
