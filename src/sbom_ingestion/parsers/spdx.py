"""SPDX SBOM parser implementation."""

import logging
from datetime import datetime
from typing import Any, Optional

from src.common.enums import ComponentType, HashAlgorithm, LicenseRiskLevel, SBOMFormat
from src.common.exceptions import SBOMParsingError, SBOMValidationError
from src.sbom_ingestion.parsers.base import BaseSBOMParser
from src.sbom_ingestion.schemas import (
    Author,
    ComponentHash,
    ExternalReference,
    License,
    ParsedComponent,
    ParsedSBOM,
)

logger = logging.getLogger(__name__)


class SPDXParser(BaseSBOMParser):
    """Parser for SPDX format SBOMs."""

    SUPPORTED_VERSIONS = ["SPDX-2.2", "SPDX-2.3", "SPDX-3.0"]

    def detect_format(self, sbom_data: dict[str, Any]) -> bool:
        """Detect if this is an SPDX SBOM."""
        return "spdxVersion" in sbom_data or "SPDXID" in sbom_data

    def get_version(self, sbom_data: dict[str, Any]) -> str:
        """Extract SPDX specification version."""
        return sbom_data.get("spdxVersion", "unknown")

    def validate(self, sbom_data: dict[str, Any]) -> bool:
        """Validate SPDX SBOM structure."""
        if not self.detect_format(sbom_data):
            raise SBOMValidationError("Not a valid SPDX SBOM")

        version = self.get_version(sbom_data)
        if version not in self.SUPPORTED_VERSIONS:
            logger.warning(
                f"SPDX version {version} may not be fully supported. "
                f"Supported: {', '.join(self.SUPPORTED_VERSIONS)}"
            )

        # Check required fields
        required_fields = ["spdxVersion", "dataLicense", "SPDXID", "name"]
        missing_fields = [f for f in required_fields if f not in sbom_data]
        if missing_fields:
            raise SBOMValidationError(f"Missing required fields: {', '.join(missing_fields)}")

        return True

    def parse(self, sbom_data: dict[str, Any]) -> ParsedSBOM:
        """Parse SPDX SBOM into standardized format."""
        try:
            # Validate first
            self.validate(sbom_data)

            # Extract core metadata
            spdx_id = sbom_data.get("SPDXID", "SPDXRef-DOCUMENT")
            doc_name = sbom_data.get("name", "Unknown")
            doc_namespace = sbom_data.get("documentNamespace", "")
            version = sbom_data.get("creationInfo", {}).get("created", "1")

            # Parse creation info
            creation_info = sbom_data.get("creationInfo", {})
            authors = self._parse_creators(creation_info.get("creators", []))
            timestamp = self._parse_timestamp(creation_info.get("created"))

            # Parse packages (components)
            components = []
            packages = sbom_data.get("packages", [])
            for pkg_data in packages:
                try:
                    component = self._parse_package(pkg_data)
                    components.append(component)
                except Exception as e:
                    logger.warning(f"Failed to parse package: {e}")
                    continue

            # Find main component (usually the first package or document describes)
            main_component = None
            describes = sbom_data.get("documentDescribes", [])
            if describes and components:
                # Find the component that matches the first described SPDXID
                for comp in components:
                    if comp.bom_ref == describes[0]:
                        main_component = comp
                        break

            if not main_component and components:
                main_component = components[0]

            # Parse relationships to build dependency graph
            dependency_graph = self._parse_relationships(sbom_data.get("relationships", []))

            # Calculate dependency depth
            self._calculate_dependency_depth(components, dependency_graph)

            # Parse files (if present, treat as components)
            files = sbom_data.get("files", [])
            for file_data in files:
                try:
                    file_component = self._parse_file(file_data)
                    components.append(file_component)
                except Exception as e:
                    logger.warning(f"Failed to parse file: {e}")
                    continue

            # Build parsed SBOM
            parsed_sbom = ParsedSBOM(
                bom_ref=spdx_id,
                name=doc_name,
                version=version if main_component is None else main_component.version,
                format=SBOMFormat.SPDX,
                spec_version=self.get_version(sbom_data),
                serial_number=doc_namespace,
                supplier_name=main_component.supplier_name if main_component else None,
                manufacturer_name=main_component.publisher if main_component else None,
                authors=authors,
                timestamp=timestamp,
                is_signed=False,  # SPDX doesn't have built-in signatures
                signature=None,
                components=components,
                main_component=main_component,
                dependency_graph=dependency_graph,
                raw_data=sbom_data,
                tools=[],
                compositions=[],
            )

            logger.info(
                f"Successfully parsed SPDX SBOM: {parsed_sbom.name} "
                f"with {len(components)} packages"
            )

            return parsed_sbom

        except SBOMValidationError:
            raise
        except Exception as e:
            raise SBOMParsingError(f"Failed to parse SPDX SBOM: {str(e)}") from e

    def _parse_package(self, pkg_data: dict[str, Any]) -> ParsedComponent:
        """Parse an SPDX package."""
        # Parse checksums (hashes)
        hashes = self._parse_checksums(pkg_data.get("checksums", []))

        # Parse licenses
        licenses = self._parse_license_info(pkg_data)

        # Parse external references
        external_refs = self._parse_external_refs(pkg_data.get("externalRefs", []))

        # Extract homepage and download location
        homepage_url = pkg_data.get("homepage")
        if homepage_url == "NOASSERTION":
            homepage_url = None

        repository_url = pkg_data.get("downloadLocation")
        if repository_url and repository_url in ["NOASSERTION", "NONE"]:
            repository_url = None

        # Parse supplier
        supplier_name = self._parse_supplier(pkg_data.get("supplier"))

        # Parse originator (author)
        author = self._parse_supplier(pkg_data.get("originator"))

        # Determine component type (SPDX doesn't have explicit types)
        component_type = ComponentType.LIBRARY

        # Extract PURL from external refs
        purl = None
        for ref in external_refs:
            if ref.type == "purl":
                purl = ref.url
                break

        # Extract CPE from external refs
        cpe = None
        for ref in external_refs:
            if ref.type.startswith("cpe"):
                cpe = ref.url
                break

        return ParsedComponent(
            name=pkg_data.get("name", "unknown"),
            version=pkg_data.get("versionInfo"),
            component_type=component_type,
            purl=purl,
            cpe=cpe,
            bom_ref=pkg_data.get("SPDXID"),
            group=None,
            description=pkg_data.get("description"),
            publisher=pkg_data.get("supplier"),
            supplier_name=supplier_name,
            author=author,
            hashes=hashes,
            licenses=licenses,
            external_references=external_refs,
            homepage_url=homepage_url,
            repository_url=repository_url,
        )

    def _parse_file(self, file_data: dict[str, Any]) -> ParsedComponent:
        """Parse an SPDX file as a component."""
        hashes = self._parse_checksums(file_data.get("checksums", []))

        # Parse file license
        licenses = []
        license_concluded = file_data.get("licenseConcluded")
        if license_concluded and license_concluded != "NOASSERTION":
            risk_level = self._assess_license_risk(license_concluded)
            licenses.append(
                License(
                    spdx_id=license_concluded,
                    name=license_concluded,
                    risk_level=risk_level,
                    is_copyleft=self._is_copyleft(license_concluded),
                )
            )

        return ParsedComponent(
            name=file_data.get("fileName", "unknown"),
            version=None,
            component_type=ComponentType.FILE,
            purl=None,
            cpe=None,
            bom_ref=file_data.get("SPDXID"),
            group=None,
            description=file_data.get("comment"),
            publisher=None,
            supplier_name=None,
            author=None,
            hashes=hashes,
            licenses=licenses,
            external_references=[],
            homepage_url=None,
            repository_url=None,
        )

    def _parse_checksums(self, checksums_data: list[dict[str, Any]]) -> list[ComponentHash]:
        """Parse SPDX checksums."""
        hashes = []
        for checksum in checksums_data:
            alg = checksum.get("algorithm", "").lower().replace("-", "")
            try:
                algorithm = HashAlgorithm(alg)
                hashes.append(
                    ComponentHash(
                        algorithm=algorithm,
                        value=checksum.get("checksumValue", ""),
                    )
                )
            except ValueError:
                logger.warning(f"Unknown checksum algorithm: {alg}")
                continue
        return hashes

    def _parse_license_info(self, pkg_data: dict[str, Any]) -> list[License]:
        """Parse license information from package."""
        licenses = []

        # License concluded
        license_concluded = pkg_data.get("licenseConcluded")
        if license_concluded and license_concluded != "NOASSERTION":
            risk_level = self._assess_license_risk(license_concluded)
            licenses.append(
                License(
                    spdx_id=license_concluded,
                    name=license_concluded,
                    risk_level=risk_level,
                    is_copyleft=self._is_copyleft(license_concluded),
                )
            )

        # License declared
        license_declared = pkg_data.get("licenseDeclared")
        if (
            license_declared
            and license_declared != "NOASSERTION"
            and license_declared != license_concluded
        ):
            risk_level = self._assess_license_risk(license_declared)
            licenses.append(
                License(
                    spdx_id=license_declared,
                    name=license_declared,
                    risk_level=risk_level,
                    is_copyleft=self._is_copyleft(license_declared),
                )
            )

        return licenses

    def _parse_external_refs(
        self, refs_data: list[dict[str, Any]]
    ) -> list[ExternalReference]:
        """Parse SPDX external references."""
        references = []
        for ref_data in refs_data:
            ref_type = ref_data.get("referenceType", "other").lower()
            locator = ref_data.get("referenceLocator", "")
            comment = ref_data.get("comment")

            if locator:
                references.append(
                    ExternalReference(
                        type=ref_type,
                        url=locator,
                        comment=comment,
                        hashes=[],
                    )
                )

        return references

    def _parse_creators(self, creators: list[str]) -> list[Author]:
        """Parse SPDX creator strings."""
        authors = []
        for creator in creators:
            # Creator format: "Tool: name-version" or "Person: name (email)" or "Organization: name"
            if ":" not in creator:
                continue

            creator_type, creator_info = creator.split(":", 1)
            creator_info = creator_info.strip()

            if creator_type.strip() in ["Person", "Organization"]:
                # Extract name and email
                name = creator_info
                email = None

                if "(" in creator_info and ")" in creator_info:
                    name = creator_info.split("(")[0].strip()
                    email = creator_info.split("(")[1].split(")")[0].strip()

                authors.append(Author(name=name, email=email))

        return authors

    def _parse_supplier(self, supplier_str: Optional[str]) -> Optional[str]:
        """Parse SPDX supplier/originator string."""
        if not supplier_str or supplier_str in ["NOASSERTION", "NONE"]:
            return None

        # Format: "Organization: name" or "Person: name"
        if ":" in supplier_str:
            return supplier_str.split(":", 1)[1].strip()

        return supplier_str

    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse SPDX timestamp."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            logger.warning(f"Failed to parse timestamp: {timestamp_str}")
            return None

    def _parse_relationships(self, relationships: list[dict[str, Any]]) -> dict[str, list[str]]:
        """Parse SPDX relationships to build dependency graph."""
        graph = {}

        for rel in relationships:
            spdx_id = rel.get("spdxElementId")
            related_id = rel.get("relatedSpdxElement")
            rel_type = rel.get("relationshipType", "")

            # We're interested in DEPENDS_ON, CONTAINS, etc.
            if rel_type in ["DEPENDS_ON", "DEPENDENCY_OF"]:
                if spdx_id not in graph:
                    graph[spdx_id] = []
                graph[spdx_id].append(related_id)
            elif rel_type == "CONTAINS":
                # Parent contains child
                if spdx_id not in graph:
                    graph[spdx_id] = []
                graph[spdx_id].append(related_id)

        return graph

    def _calculate_dependency_depth(
        self, components: list[ParsedComponent], graph: dict[str, list[str]]
    ) -> None:
        """Calculate dependency depth for each component using BFS."""
        # Build reverse graph to find roots
        has_dependents = set()
        for deps in graph.values():
            has_dependents.update(deps)

        # Find root components
        roots = []
        for comp in components:
            if comp.bom_ref and comp.bom_ref not in has_dependents:
                roots.append(comp.bom_ref)

        # BFS to calculate depth
        depths = {}
        queue = [(root, 0) for root in roots]
        visited = set()

        while queue:
            ref, depth = queue.pop(0)
            if ref in visited:
                continue
            visited.add(ref)
            depths[ref] = depth

            if ref in graph:
                for dep_ref in graph[ref]:
                    if dep_ref not in visited:
                        queue.append((dep_ref, depth + 1))

        # Update components
        for comp in components:
            if comp.bom_ref and comp.bom_ref in depths:
                comp.dependency_depth = depths[comp.bom_ref]
                comp.is_direct_dependency = depths[comp.bom_ref] == 0

    def _assess_license_risk(self, license_str: str) -> LicenseRiskLevel:
        """Assess license risk level."""
        upper_license = license_str.upper()

        # High risk: Strong copyleft
        if any(cl in upper_license for cl in ["GPL", "AGPL"]):
            return LicenseRiskLevel.HIGH

        # Medium risk: Weak copyleft
        if any(cl in upper_license for cl in ["LGPL", "MPL", "EPL", "EUPL"]):
            return LicenseRiskLevel.MEDIUM

        # Low risk: Permissive
        if any(pl in upper_license for pl in ["MIT", "BSD", "APACHE", "ISC", "CC0"]):
            return LicenseRiskLevel.LOW

        return LicenseRiskLevel.UNKNOWN

    def _is_copyleft(self, license_str: str) -> bool:
        """Check if license is copyleft."""
        upper_license = license_str.upper()
        copyleft_licenses = ["GPL", "AGPL", "LGPL", "MPL", "EPL", "EUPL"]
        return any(cl in upper_license for cl in copyleft_licenses)
