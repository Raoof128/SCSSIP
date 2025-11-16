"""CycloneDX SBOM parser implementation."""

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
    Signature,
)

logger = logging.getLogger(__name__)

# Known copyleft licenses
COPYLEFT_LICENSES = {"GPL", "AGPL", "LGPL", "MPL", "OSL", "EUPL"}


class CycloneDXParser(BaseSBOMParser):
    """Parser for CycloneDX format SBOMs."""

    SUPPORTED_VERSIONS = ["1.4", "1.5", "1.6"]

    def detect_format(self, sbom_data: dict[str, Any]) -> bool:
        """Detect if this is a CycloneDX SBOM."""
        return "bomFormat" in sbom_data and sbom_data["bomFormat"] == "CycloneDX"

    def get_version(self, sbom_data: dict[str, Any]) -> str:
        """Extract CycloneDX specification version."""
        return sbom_data.get("specVersion", "unknown")

    def validate(self, sbom_data: dict[str, Any]) -> bool:
        """Validate CycloneDX SBOM structure."""
        if not self.detect_format(sbom_data):
            raise SBOMValidationError("Not a valid CycloneDX SBOM")

        version = self.get_version(sbom_data)
        if version not in self.SUPPORTED_VERSIONS:
            raise SBOMValidationError(
                f"Unsupported CycloneDX version: {version}. "
                f"Supported: {', '.join(self.SUPPORTED_VERSIONS)}"
            )

        # Check required fields
        required_fields = ["bomFormat", "specVersion", "version"]
        missing_fields = [f for f in required_fields if f not in sbom_data]
        if missing_fields:
            raise SBOMValidationError(f"Missing required fields: {', '.join(missing_fields)}")

        return True

    def parse(self, sbom_data: dict[str, Any]) -> ParsedSBOM:
        """Parse CycloneDX SBOM into standardized format."""
        try:
            # Validate first
            self.validate(sbom_data)

            # Extract metadata
            metadata = sbom_data.get("metadata", {})
            serial_number = sbom_data.get("serialNumber")
            version = sbom_data.get("version", 1)

            # Parse main component (metadata.component)
            main_component = None
            if "component" in metadata:
                main_component = self._parse_component(metadata["component"])

            # Generate bom_ref
            bom_ref = serial_number or f"cdx-{datetime.utcnow().timestamp()}"

            # Parse authors
            authors = self._parse_authors(metadata)

            # Parse timestamp
            timestamp = self._parse_timestamp(metadata.get("timestamp"))

            # Parse components
            components = []
            if "components" in sbom_data:
                for comp_data in sbom_data["components"]:
                    try:
                        component = self._parse_component(comp_data)
                        components.append(component)
                    except Exception as e:
                        logger.warning(f"Failed to parse component: {e}")
                        continue

            # Parse dependencies
            dependency_graph = self._parse_dependencies(sbom_data.get("dependencies", []))

            # Calculate dependency depth for each component
            self._calculate_dependency_depth(components, dependency_graph)

            # Parse signature
            is_signed = False
            signature = None
            if "signature" in metadata:
                is_signed = True
                signature = self._parse_signature(metadata["signature"])

            # Extract supplier/manufacturer
            supplier_name = None
            manufacturer_name = None
            if main_component:
                supplier_name = main_component.supplier_name
                manufacturer_name = main_component.publisher

            # Build parsed SBOM
            parsed_sbom = ParsedSBOM(
                bom_ref=bom_ref,
                name=main_component.name if main_component else "Unknown",
                version=main_component.version if main_component else None,
                format=SBOMFormat.CYCLONEDX,
                spec_version=self.get_version(sbom_data),
                serial_number=serial_number,
                supplier_name=supplier_name,
                manufacturer_name=manufacturer_name,
                authors=authors,
                timestamp=timestamp,
                is_signed=is_signed,
                signature=signature,
                components=components,
                main_component=main_component,
                dependency_graph=dependency_graph,
                raw_data=sbom_data,
                tools=metadata.get("tools", []),
                compositions=sbom_data.get("compositions", []),
            )

            logger.info(
                f"Successfully parsed CycloneDX SBOM: {parsed_sbom.name} "
                f"with {len(components)} components"
            )

            return parsed_sbom

        except SBOMValidationError:
            raise
        except Exception as e:
            raise SBOMParsingError(f"Failed to parse CycloneDX SBOM: {str(e)}") from e

    def _parse_component(self, comp_data: dict[str, Any]) -> ParsedComponent:
        """Parse a single component."""
        # Map CycloneDX type to our enum
        comp_type_str = comp_data.get("type", "library").lower()
        try:
            component_type = ComponentType(comp_type_str)
        except ValueError:
            component_type = ComponentType.LIBRARY

        # Parse hashes
        hashes = self._parse_hashes(comp_data.get("hashes", []))

        # Parse licenses
        licenses = self._parse_licenses(comp_data.get("licenses", []))

        # Parse external references
        external_refs = self._parse_external_references(
            comp_data.get("externalReferences", [])
        )

        # Extract URLs from external references
        homepage_url = None
        repository_url = None
        for ref in external_refs:
            if ref.type == "website":
                homepage_url = ref.url
            elif ref.type in ["vcs", "repository"]:
                repository_url = ref.url

        # Parse supplier
        supplier_name = None
        if "supplier" in comp_data:
            supplier = comp_data["supplier"]
            supplier_name = supplier.get("name")

        # Parse publisher
        publisher = comp_data.get("publisher")

        # Parse author
        author = None
        if "author" in comp_data:
            author = comp_data["author"]

        return ParsedComponent(
            name=comp_data.get("name", "unknown"),
            version=comp_data.get("version"),
            component_type=component_type,
            purl=comp_data.get("purl"),
            cpe=comp_data.get("cpe"),
            bom_ref=comp_data.get("bom-ref"),
            group=comp_data.get("group"),
            description=comp_data.get("description"),
            publisher=publisher,
            supplier_name=supplier_name,
            author=author,
            hashes=hashes,
            licenses=licenses,
            external_references=external_refs,
            homepage_url=homepage_url,
            repository_url=repository_url,
        )

    def _parse_hashes(self, hashes_data: list[dict[str, Any]]) -> list[ComponentHash]:
        """Parse hash information."""
        hashes = []
        for hash_data in hashes_data:
            alg = hash_data.get("alg", "").lower().replace("-", "")
            try:
                algorithm = HashAlgorithm(alg)
                hashes.append(
                    ComponentHash(
                        algorithm=algorithm,
                        value=hash_data.get("content", ""),
                    )
                )
            except ValueError:
                logger.warning(f"Unknown hash algorithm: {alg}")
                continue
        return hashes

    def _parse_licenses(self, licenses_data: list[dict[str, Any]]) -> list[License]:
        """Parse license information."""
        licenses = []
        for license_data in licenses_data:
            # CycloneDX can have license or expression
            if "license" in license_data:
                lic = license_data["license"]
                spdx_id = lic.get("id")
                name = lic.get("name", spdx_id or "Unknown")
                url = lic.get("url")
                text = lic.get("text", {}).get("content")

                # Determine risk level
                risk_level = self._assess_license_risk(spdx_id or name)

                # Check if copyleft
                is_copyleft = self._is_copyleft(spdx_id or name)

                licenses.append(
                    License(
                        spdx_id=spdx_id,
                        name=name,
                        text=text,
                        url=url,
                        risk_level=risk_level,
                        is_copyleft=is_copyleft,
                    )
                )
            elif "expression" in license_data:
                # Handle SPDX expressions (e.g., "MIT OR Apache-2.0")
                expression = license_data["expression"]
                licenses.append(
                    License(
                        name=expression,
                        risk_level=LicenseRiskLevel.UNKNOWN,
                    )
                )

        return licenses

    def _parse_external_references(
        self, refs_data: list[dict[str, Any]]
    ) -> list[ExternalReference]:
        """Parse external references."""
        references = []
        for ref_data in refs_data:
            ref_type = ref_data.get("type", "other")
            url = ref_data.get("url", "")
            comment = ref_data.get("comment")
            hashes = self._parse_hashes(ref_data.get("hashes", []))

            if url:
                references.append(
                    ExternalReference(
                        type=ref_type,
                        url=url,
                        comment=comment,
                        hashes=hashes,
                    )
                )

        return references

    def _parse_authors(self, metadata: dict[str, Any]) -> list[Author]:
        """Parse author information from metadata."""
        authors = []
        if "authors" in metadata:
            for author_data in metadata["authors"]:
                authors.append(
                    Author(
                        name=author_data.get("name"),
                        email=author_data.get("email"),
                        phone=author_data.get("phone"),
                    )
                )
        return authors

    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO 8601 timestamp."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            logger.warning(f"Failed to parse timestamp: {timestamp_str}")
            return None

    def _parse_signature(self, sig_data: dict[str, Any]) -> Signature:
        """Parse signature information."""
        return Signature(
            algorithm=sig_data.get("algorithm", "unknown"),
            value=sig_data.get("value", ""),
            public_key=sig_data.get("publicKey", {}).get("value"),
            certificate_path=sig_data.get("certificatePath"),
        )

    def _parse_dependencies(self, deps_data: list[dict[str, Any]]) -> dict[str, list[str]]:
        """Parse dependency graph."""
        graph = {}
        for dep in deps_data:
            ref = dep.get("ref")
            depends_on = dep.get("dependsOn", [])
            if ref:
                graph[ref] = depends_on
        return graph

    def _calculate_dependency_depth(
        self, components: list[ParsedComponent], graph: dict[str, list[str]]
    ) -> None:
        """Calculate dependency depth for each component using BFS."""
        # Build reverse graph to find roots
        has_dependents = set()
        for deps in graph.values():
            has_dependents.update(deps)

        # Find root components (no one depends on them or not in graph)
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

            # Add dependencies
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
        return any(cl in upper_license for cl in COPYLEFT_LICENSES)
