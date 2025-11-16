#!/usr/bin/env python3
"""
Simple CLI script to parse and validate SBOMs.

Usage:
    python scripts/parse_sbom.py examples/sboms/log4shell-cyclonedx.json
"""

import argparse
import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.sbom_ingestion import SBOMParserFactory


def main() -> None:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Parse and validate SBOM files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("sbom_file", help="Path to SBOM file (JSON)")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )
    parser.add_argument(
        "--validate-only", action="store_true", help="Only validate, don't parse"
    )

    args = parser.parse_args()

    # Load SBOM file
    sbom_path = Path(args.sbom_file)
    if not sbom_path.exists():
        print(f"❌ Error: File not found: {sbom_path}")
        sys.exit(1)

    try:
        with open(sbom_path) as f:
            sbom_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON: {e}")
        sys.exit(1)

    # Parse SBOM
    try:
        sbom_parser = SBOMParserFactory.create_parser(sbom_data)
        print(f"✅ Detected format: {sbom_parser.__class__.__name__}")

        # Validate
        is_valid = sbom_parser.validate(sbom_data)
        version = sbom_parser.get_version(sbom_data)
        print(f"✅ Valid: {is_valid}")
        print(f"📋 Spec version: {version}")

        if args.validate_only:
            return

        # Parse
        parsed = sbom_parser.parse(sbom_data)

        print(f"\n📦 SBOM: {parsed.name} v{parsed.version}")
        print(f"🔧 Format: {parsed.format.value}")
        print(f"📅 Timestamp: {parsed.timestamp}")
        print(f"📊 Total components: {len(parsed.components)}")

        if args.verbose:
            print("\n📋 Components:")
            for i, comp in enumerate(parsed.components, 1):
                print(f"\n  {i}. {comp.name} {comp.version or '(no version)'}")
                print(f"     Type: {comp.component_type.value}")
                if comp.purl:
                    print(f"     PURL: {comp.purl}")
                if comp.cpe:
                    print(f"     CPE: {comp.cpe}")
                print(f"     Depth: {comp.dependency_depth} ({'direct' if comp.is_direct_dependency else 'transitive'})")
                if comp.licenses:
                    licenses = ", ".join(l.name for l in comp.licenses)
                    print(f"     Licenses: {licenses}")
                if comp.hashes:
                    print(f"     Hashes: {len(comp.hashes)}")

            print(f"\n🔗 Dependency graph:")
            for ref, deps in parsed.dependency_graph.items():
                if deps:
                    print(f"  {ref} → {len(deps)} dependencies")

        print(f"\n✅ Successfully parsed SBOM!")

    except Exception as e:
        print(f"❌ Error parsing SBOM: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
