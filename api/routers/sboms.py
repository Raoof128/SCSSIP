"""SBOM management API endpoints."""

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from src.common.config import get_settings
from src.common.enums import ScanStatus
from src.compliance.ntia import NTIAValidator
from src.compliance.slsa import SLSAValidator
from src.database import SBOM, Component, SBOMComponent, get_db
from src.sbom_ingestion import SBOMParserFactory
from src.sbom_ingestion.schemas import ParsedSBOM

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter()


@router.post("/upload", response_model=dict[str, Any])
async def upload_sbom(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Upload and parse an SBOM file.

    Args:
        file: SBOM file (JSON format)
        db: Database session

    Returns:
        Dictionary with SBOM ID and parse results
    """
    try:
        # Read file content
        content = await file.read()

        # Check file size
        max_size = settings.max_sbom_size_mb * 1024 * 1024
        if len(content) > max_size:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Max size: {settings.max_sbom_size_mb}MB",
            )

        # Parse JSON
        try:
            sbom_data = json.loads(content)
        except json.JSONDecodeError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid JSON: {str(e)}",
            )

        # Detect and parse SBOM
        try:
            parser = SBOMParserFactory.create_parser(sbom_data)
            parsed_sbom = parser.parse(sbom_data)
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"SBOM parsing failed: {str(e)}",
            )

        # Store in database
        sbom_id = await _store_sbom(parsed_sbom, db)

        return {
            "sbom_id": sbom_id,
            "name": parsed_sbom.name,
            "version": parsed_sbom.version,
            "format": parsed_sbom.format.value,
            "components_count": len(parsed_sbom.components),
            "status": "success",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/{sbom_id}", response_model=dict[str, Any])
def get_sbom(sbom_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Get SBOM by ID."""
    sbom = db.query(SBOM).filter(SBOM.id == sbom_id).first()

    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    return {
        "id": sbom.id,
        "bom_ref": sbom.bom_ref,
        "name": sbom.name,
        "version": sbom.version,
        "format": sbom.format.value if sbom.format else None,
        "spec_version": sbom.spec_version,
        "scan_status": sbom.scan_status.value if sbom.scan_status else None,
        "total_components": sbom.total_components,
        "total_vulnerabilities": sbom.total_vulnerabilities,
        "critical_vulns": sbom.critical_vulns,
        "high_vulns": sbom.high_vulns,
        "medium_vulns": sbom.medium_vulns,
        "low_vulns": sbom.low_vulns,
        "overall_risk_score": sbom.overall_risk_score,
        "overall_risk_level": sbom.overall_risk_level.value if sbom.overall_risk_level else None,
        "slsa_level": sbom.slsa_level,
        "ntia_compliant": sbom.ntia_compliant,
        "uploaded_at": sbom.uploaded_at.isoformat() if sbom.uploaded_at else None,
        "processed_at": sbom.processed_at.isoformat() if sbom.processed_at else None,
    }


@router.get("/", response_model=dict[str, Any])
def list_sboms(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """List all SBOMs with pagination."""
    total = db.query(SBOM).count()
    sboms = db.query(SBOM).offset(skip).limit(limit).all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "sboms": [
            {
                "id": sbom.id,
                "name": sbom.name,
                "version": sbom.version,
                "total_components": sbom.total_components,
                "total_vulnerabilities": sbom.total_vulnerabilities,
                "risk_level": sbom.overall_risk_level.value if sbom.overall_risk_level else None,
                "uploaded_at": sbom.uploaded_at.isoformat() if sbom.uploaded_at else None,
            }
            for sbom in sboms
        ],
    }


@router.get("/{sbom_id}/components", response_model=dict[str, Any])
def get_sbom_components(
    sbom_id: int,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Get components for an SBOM."""
    sbom = db.query(SBOM).filter(SBOM.id == sbom_id).first()

    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    total = len(sbom.components)
    components = sbom.components[skip : skip + limit]

    return {
        "sbom_id": sbom_id,
        "total": total,
        "components": [
            {
                "id": sc.component.id,
                "name": sc.component.name,
                "version": sc.component.version,
                "type": sc.component.component_type.value if sc.component.component_type else None,
                "purl": sc.component.purl,
                "dependency_depth": sc.dependency_depth,
                "risk_score": sc.risk_score,
                "risk_level": sc.risk_level.value if sc.risk_level else None,
                "vuln_count": sc.vuln_count,
            }
            for sc in components
        ],
    }


@router.delete("/{sbom_id}")
def delete_sbom(sbom_id: int, db: Session = Depends(get_db)) -> dict[str, str]:
    """Delete an SBOM."""
    sbom = db.query(SBOM).filter(SBOM.id == sbom_id).first()

    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    db.delete(sbom)
    db.commit()

    return {"status": "deleted", "sbom_id": str(sbom_id)}


async def _store_sbom(parsed_sbom: ParsedSBOM, db: Session) -> int:
    """Store parsed SBOM in database."""
    # Create SBOM record
    sbom = SBOM(
        bom_ref=parsed_sbom.bom_ref,
        name=parsed_sbom.name,
        version=parsed_sbom.version,
        format=parsed_sbom.format,
        spec_version=parsed_sbom.spec_version,
        serial_number=parsed_sbom.serial_number,
        supplier_name=parsed_sbom.supplier_name,
        manufacturer_name=parsed_sbom.manufacturer_name,
        authors=[
            {"name": a.name, "email": a.email, "phone": a.phone}
            for a in parsed_sbom.authors
        ],
        timestamp=parsed_sbom.timestamp,
        is_signed=parsed_sbom.is_signed,
        scan_status=ScanStatus.COMPLETED,
        total_components=len(parsed_sbom.components),
        raw_sbom=parsed_sbom.raw_data,
    )

    db.add(sbom)
    db.flush()

    # Store components
    for parsed_comp in parsed_sbom.components:
        # Check if component already exists
        component = (
            db.query(Component)
            .filter(
                Component.name == parsed_comp.name,
                Component.version == parsed_comp.version,
            )
            .first()
        )

        if not component:
            component = Component(
                name=parsed_comp.name,
                version=parsed_comp.version,
                component_type=parsed_comp.component_type,
                purl=parsed_comp.purl,
                cpe=parsed_comp.cpe,
                bom_ref=parsed_comp.bom_ref,
                group=parsed_comp.group,
                description=parsed_comp.description,
                publisher=parsed_comp.publisher,
                supplier_name=parsed_comp.supplier_name,
                author=parsed_comp.author,
            )
            db.add(component)
            db.flush()

        # Link to SBOM
        sbom_component = SBOMComponent(
            sbom_id=sbom.id,
            component_id=component.id,
            scope=parsed_comp.scope,
            is_direct_dependency=parsed_comp.is_direct_dependency,
            dependency_depth=parsed_comp.dependency_depth,
        )
        db.add(sbom_component)

    db.commit()

    logger.info(f"Stored SBOM: {sbom.name} (ID: {sbom.id})")

    return sbom.id
