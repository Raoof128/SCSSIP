"""Pydantic schemas for SBOM parsing."""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from src.common.enums import ComponentType, HashAlgorithm, LicenseRiskLevel, SBOMFormat


class ComponentHash(BaseModel):
    """Component hash information."""

    algorithm: HashAlgorithm
    value: str = Field(..., min_length=1, max_length=512)


class License(BaseModel):
    """License information."""

    spdx_id: Optional[str] = None
    name: str
    text: Optional[str] = None
    url: Optional[str] = None
    risk_level: LicenseRiskLevel = LicenseRiskLevel.UNKNOWN
    is_osi_approved: bool = False
    is_copyleft: bool = False


class ExternalReference(BaseModel):
    """External reference for components."""

    type: str
    url: str
    comment: Optional[str] = None
    hashes: list[ComponentHash] = Field(default_factory=list)


class ParsedComponent(BaseModel):
    """Parsed component data."""

    name: str
    version: Optional[str] = None
    component_type: ComponentType
    purl: Optional[str] = None
    cpe: Optional[str] = None
    bom_ref: Optional[str] = None
    group: Optional[str] = None
    description: Optional[str] = None
    publisher: Optional[str] = None
    supplier_name: Optional[str] = None
    author: Optional[str] = None
    hashes: list[ComponentHash] = Field(default_factory=list)
    licenses: list[License] = Field(default_factory=list)
    external_references: list[ExternalReference] = Field(default_factory=list)
    homepage_url: Optional[str] = None
    repository_url: Optional[str] = None

    # Dependency information
    scope: Optional[str] = None
    is_direct_dependency: bool = True
    dependency_depth: int = 0
    dependencies: list[str] = Field(default_factory=list)  # List of bom-refs


class Author(BaseModel):
    """Author/creator information."""

    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None


class Signature(BaseModel):
    """Digital signature information."""

    algorithm: str
    value: str
    public_key: Optional[str] = None
    certificate_path: Optional[str] = None


class ParsedSBOM(BaseModel):
    """Parsed SBOM data in standardized format."""

    # Core metadata
    bom_ref: str
    name: str
    version: Optional[str] = None
    format: SBOMFormat
    spec_version: str
    serial_number: Optional[str] = None

    # Supplier/manufacturer
    supplier_name: Optional[str] = None
    manufacturer_name: Optional[str] = None
    authors: list[Author] = Field(default_factory=list)
    timestamp: Optional[datetime] = None

    # Signature
    is_signed: bool = False
    signature: Optional[Signature] = None

    # Components
    components: list[ParsedComponent] = Field(default_factory=list)
    main_component: Optional[ParsedComponent] = None

    # Dependencies (adjacency list representation)
    dependency_graph: dict[str, list[str]] = Field(default_factory=dict)

    # Raw data
    raw_data: dict[str, Any] = Field(default_factory=dict)

    # Metadata
    tools: list[dict[str, Any]] = Field(default_factory=list)
    compositions: list[dict[str, Any]] = Field(default_factory=list)

    class Config:
        """Pydantic config."""

        arbitrary_types_allowed = True
