"""Pytest configuration and fixtures."""

import json
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def sample_cyclonedx_sbom() -> dict[str, Any]:
    """Load sample CycloneDX SBOM."""
    sbom_path = Path(__file__).parent.parent / "examples" / "sboms" / "log4shell-cyclonedx.json"
    with open(sbom_path) as f:
        return json.load(f)


@pytest.fixture
def sample_spdx_sbom() -> dict[str, Any]:
    """Load sample SPDX SBOM."""
    sbom_path = Path(__file__).parent.parent / "examples" / "sboms" / "log4shell-spdx.json"
    with open(sbom_path) as f:
        return json.load(f)


@pytest.fixture
def secure_cyclonedx_sbom() -> dict[str, Any]:
    """Load secure CycloneDX SBOM."""
    sbom_path = Path(__file__).parent.parent / "examples" / "sboms" / "secure-app-cyclonedx.json"
    with open(sbom_path) as f:
        return json.load(f)
