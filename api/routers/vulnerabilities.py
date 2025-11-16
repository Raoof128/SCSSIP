"""Vulnerability correlation API endpoints."""

import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from src.database import Component, Vulnerability, get_db
from src.vulnerability_correlation.service import VulnerabilityCorrelationService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/correlate/{component_id}")
async def correlate_component(
    component_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Correlate component with known vulnerabilities."""
    component = db.query(Component).filter(Component.id == component_id).first()

    if not component:
        raise HTTPException(status_code=404, detail="Component not found")

    service = VulnerabilityCorrelationService(db)

    # Run correlation in background
    background_tasks.add_task(service.correlate_component, component)

    return {
        "status": "started",
        "component_id": component_id,
        "component_name": component.name,
    }


@router.get("/{vuln_id}")
def get_vulnerability(vuln_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Get vulnerability details."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()

    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    return {
        "id": vuln.id,
        "vulnerability_id": vuln.vulnerability_id,
        "cve_id": vuln.cve_id,
        "source": vuln.source,
        "title": vuln.title,
        "description": vuln.description,
        "cvss_score": vuln.cvss_score,
        "severity": vuln.severity.value if vuln.severity else None,
        "epss_score": vuln.epss_score,
        "published_date": vuln.published_date.isoformat() if vuln.published_date else None,
    }


@router.get("/")
def list_vulnerabilities(
    skip: int = 0,
    limit: int = 100,
    severity: str | None = None,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """List vulnerabilities with filtering."""
    query = db.query(Vulnerability)

    if severity:
        query = query.filter(Vulnerability.severity == severity)

    total = query.count()
    vulns = query.offset(skip).limit(limit).all()

    return {
        "total": total,
        "vulnerabilities": [
            {
                "id": v.id,
                "cve_id": v.cve_id,
                "severity": v.severity.value if v.severity else None,
                "cvss_score": v.cvss_score,
                "title": v.title,
            }
            for v in vulns
        ],
    }
