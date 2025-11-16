"""SQLAlchemy database models for SBOM platform."""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from src.common.enums import (
    ComponentType,
    HashAlgorithm,
    LicenseRiskLevel,
    RiskLevel,
    SBOMFormat,
    ScanStatus,
    VulnerabilitySeverity,
)
from src.database.base import Base


class SBOM(Base):
    """SBOM (Software Bill of Materials) entity."""

    __tablename__ = "sboms"

    id = Column(Integer, primary_key=True, index=True)
    bom_ref = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(500), nullable=False)
    version = Column(String(100), nullable=True)
    format = Column(Enum(SBOMFormat), nullable=False)
    spec_version = Column(String(20), nullable=False)
    serial_number = Column(String(255), unique=True, index=True, nullable=True)

    # Metadata
    supplier_name = Column(String(500), nullable=True)
    manufacturer_name = Column(String(500), nullable=True)
    authors = Column(JSONB, nullable=True)  # List of author objects
    timestamp = Column(DateTime, nullable=True)

    # Processing
    scan_status = Column(
        Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True
    )
    uploaded_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    processed_at = Column(DateTime, nullable=True)
    scan_duration_seconds = Column(Float, nullable=True)

    # Signature & Provenance
    is_signed = Column(Boolean, default=False, nullable=False)
    signature_algorithm = Column(String(100), nullable=True)
    signature_value = Column(Text, nullable=True)
    signature_verified = Column(Boolean, default=False, nullable=False)

    # Statistics
    total_components = Column(Integer, default=0, nullable=False)
    total_vulnerabilities = Column(Integer, default=0, nullable=False)
    critical_vulns = Column(Integer, default=0, nullable=False)
    high_vulns = Column(Integer, default=0, nullable=False)
    medium_vulns = Column(Integer, default=0, nullable=False)
    low_vulns = Column(Integer, default=0, nullable=False)

    # Risk Assessment
    overall_risk_score = Column(Float, nullable=True)
    overall_risk_level = Column(Enum(RiskLevel), nullable=True)

    # Compliance
    slsa_level = Column(Integer, default=0, nullable=False)
    ntia_compliant = Column(Boolean, default=False, nullable=False)
    compliance_issues = Column(JSONB, nullable=True)  # List of compliance issues

    # Raw data
    raw_sbom = Column(JSONB, nullable=True)  # Original SBOM JSON

    # Relationships
    components = relationship(
        "SBOMComponent", back_populates="sbom", cascade="all, delete-orphan"
    )

    # Indexes
    __table_args__ = (Index("idx_sbom_status_uploaded", "scan_status", "uploaded_at"),)

    def __repr__(self) -> str:
        return f"<SBOM(id={self.id}, name='{self.name}', version='{self.version}')>"


class Component(Base):
    """Software component (package, library, etc.)."""

    __tablename__ = "components"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(500), nullable=False, index=True)
    version = Column(String(200), nullable=True, index=True)
    component_type = Column(Enum(ComponentType), nullable=False)

    # Identifiers
    purl = Column(String(1000), unique=True, index=True, nullable=True)  # Package URL
    cpe = Column(String(500), index=True, nullable=True)  # Common Platform Enumeration
    bom_ref = Column(String(500), nullable=True)

    # Metadata
    group = Column(String(500), nullable=True)  # Maven groupId, npm scope, etc.
    description = Column(Text, nullable=True)
    publisher = Column(String(500), nullable=True)
    supplier_name = Column(String(500), nullable=True)
    author = Column(String(500), nullable=True)

    # External references
    external_references = Column(JSONB, nullable=True)  # List of external refs
    homepage_url = Column(String(1000), nullable=True)
    repository_url = Column(String(1000), nullable=True)

    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Relationships
    hashes = relationship("ComponentHash", back_populates="component", cascade="all, delete-orphan")
    licenses = relationship(
        "ComponentLicense", back_populates="component", cascade="all, delete-orphan"
    )
    sbom_associations = relationship(
        "SBOMComponent", back_populates="component", cascade="all, delete-orphan"
    )
    vulnerabilities = relationship(
        "Vulnerability", secondary="component_vulnerabilities", back_populates="components"
    )

    # Indexes
    __table_args__ = (
        Index("idx_component_name_version", "name", "version"),
        Index("idx_component_type", "component_type"),
    )

    def __repr__(self) -> str:
        return f"<Component(id={self.id}, name='{self.name}', version='{self.version}')>"


class ComponentHash(Base):
    """Component file hashes for integrity verification."""

    __tablename__ = "component_hashes"

    id = Column(Integer, primary_key=True, index=True)
    component_id = Column(Integer, ForeignKey("components.id"), nullable=False)
    algorithm = Column(Enum(HashAlgorithm), nullable=False)
    hash_value = Column(String(512), nullable=False)

    # Relationships
    component = relationship("Component", back_populates="hashes")

    # Constraints
    __table_args__ = (
        UniqueConstraint("component_id", "algorithm", name="uq_component_hash_algorithm"),
        Index("idx_hash_value", "hash_value"),
    )

    def __repr__(self) -> str:
        return f"<ComponentHash(component_id={self.component_id}, algorithm='{self.algorithm}')>"


class License(Base):
    """Software license information."""

    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, index=True)
    spdx_id = Column(String(100), unique=True, index=True, nullable=True)  # SPDX identifier
    name = Column(String(500), nullable=False, index=True)
    text = Column(Text, nullable=True)
    url = Column(String(1000), nullable=True)

    # Risk assessment
    risk_level = Column(Enum(LicenseRiskLevel), default=LicenseRiskLevel.UNKNOWN, nullable=False)
    is_osi_approved = Column(Boolean, default=False, nullable=False)
    is_copyleft = Column(Boolean, default=False, nullable=False)

    # Relationships
    components = relationship("ComponentLicense", back_populates="license")

    def __repr__(self) -> str:
        return f"<License(id={self.id}, name='{self.name}', spdx_id='{self.spdx_id}')>"


class ComponentLicense(Base):
    """Many-to-many relationship between components and licenses."""

    __tablename__ = "component_licenses"

    id = Column(Integer, primary_key=True, index=True)
    component_id = Column(Integer, ForeignKey("components.id"), nullable=False)
    license_id = Column(Integer, ForeignKey("licenses.id"), nullable=False)
    expression = Column(String(500), nullable=True)  # License expression (e.g., "MIT OR Apache-2.0")

    # Relationships
    component = relationship("Component", back_populates="licenses")
    license = relationship("License", back_populates="components")

    # Constraints
    __table_args__ = (
        UniqueConstraint("component_id", "license_id", name="uq_component_license"),
    )

    def __repr__(self) -> str:
        return f"<ComponentLicense(component_id={self.component_id}, license_id={self.license_id})>"


class SBOMComponent(Base):
    """Many-to-many relationship between SBOMs and components with additional metadata."""

    __tablename__ = "sbom_components"

    id = Column(Integer, primary_key=True, index=True)
    sbom_id = Column(Integer, ForeignKey("sboms.id"), nullable=False, index=True)
    component_id = Column(Integer, ForeignKey("components.id"), nullable=False, index=True)

    # Dependency metadata
    scope = Column(String(100), nullable=True)  # runtime, development, test, etc.
    is_direct_dependency = Column(Boolean, default=True, nullable=False)
    dependency_depth = Column(Integer, default=0, nullable=False)  # 0 = direct, 1+ = transitive
    parent_component_id = Column(Integer, ForeignKey("components.id"), nullable=True)

    # Risk assessment (component-specific within this SBOM)
    vuln_count = Column(Integer, default=0, nullable=False)
    risk_score = Column(Float, nullable=True)
    risk_level = Column(Enum(RiskLevel), nullable=True)

    # Relationships
    sbom = relationship("SBOM", back_populates="components")
    component = relationship("Component", foreign_keys=[component_id], back_populates="sbom_associations")
    parent_component = relationship("Component", foreign_keys=[parent_component_id])

    # Constraints
    __table_args__ = (
        UniqueConstraint("sbom_id", "component_id", name="uq_sbom_component"),
        Index("idx_sbom_component_depth", "sbom_id", "dependency_depth"),
    )

    def __repr__(self) -> str:
        return f"<SBOMComponent(sbom_id={self.sbom_id}, component_id={self.component_id})>"


class Vulnerability(Base):
    """Security vulnerability (CVE, GHSA, etc.)."""

    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), unique=True, index=True, nullable=True)  # CVE-YYYY-NNNNN
    vulnerability_id = Column(String(100), unique=True, index=True, nullable=False)  # Generic ID
    source = Column(String(100), nullable=False)  # NVD, OSV, GitHub, etc.

    # Metadata
    title = Column(String(1000), nullable=True)
    description = Column(Text, nullable=True)
    published_date = Column(DateTime, nullable=True, index=True)
    modified_date = Column(DateTime, nullable=True)

    # Severity
    cvss_score = Column(Float, nullable=True, index=True)
    cvss_vector = Column(String(200), nullable=True)
    cvss_version = Column(String(10), nullable=True)  # 2.0, 3.0, 3.1, 4.0
    severity = Column(Enum(VulnerabilitySeverity), nullable=True, index=True)

    # EPSS (Exploit Prediction Scoring System)
    epss_score = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)

    # Affected versions
    affected_versions = Column(JSONB, nullable=True)  # List of version ranges
    patched_versions = Column(JSONB, nullable=True)  # List of patched versions

    # References
    references = relationship(
        "VulnerabilityReference", back_populates="vulnerability", cascade="all, delete-orphan"
    )

    # CWE (Common Weakness Enumeration)
    cwe_ids = Column(JSONB, nullable=True)  # List of CWE IDs

    # Raw data
    raw_data = Column(JSONB, nullable=True)

    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Relationships
    components = relationship(
        "Component", secondary="component_vulnerabilities", back_populates="vulnerabilities"
    )

    # Indexes
    __table_args__ = (
        Index("idx_vuln_severity_score", "severity", "cvss_score"),
        Index("idx_vuln_published", "published_date"),
    )

    def __repr__(self) -> str:
        return f"<Vulnerability(id={self.id}, cve_id='{self.cve_id}', severity='{self.severity}')>"


class VulnerabilityReference(Base):
    """External references for vulnerabilities."""

    __tablename__ = "vulnerability_references"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)
    url = Column(String(2000), nullable=False)
    source = Column(String(200), nullable=True)  # e.g., "CONFIRM", "EXPLOIT", "PATCH"
    tags = Column(JSONB, nullable=True)  # List of tags

    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="references")

    def __repr__(self) -> str:
        return f"<VulnerabilityReference(vuln_id={self.vulnerability_id}, url='{self.url}')>"


# Association table for Component-Vulnerability many-to-many
class ComponentVulnerability(Base):
    """Many-to-many relationship between components and vulnerabilities."""

    __tablename__ = "component_vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    component_id = Column(Integer, ForeignKey("components.id"), nullable=False, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)

    # Matching metadata
    matched_by = Column(String(100), nullable=True)  # purl, cpe, name+version
    confidence = Column(Float, default=1.0, nullable=False)  # 0.0-1.0

    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Constraints
    __table_args__ = (
        UniqueConstraint("component_id", "vulnerability_id", name="uq_component_vulnerability"),
    )

    def __repr__(self) -> str:
        return f"<ComponentVulnerability(component_id={self.component_id}, vuln_id={self.vulnerability_id})>"
