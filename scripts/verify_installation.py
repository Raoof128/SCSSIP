#!/usr/bin/env python3
"""
Verification script for threat hunting platform installation.
Checks dependencies, imports, and basic functionality.
"""

import sys
import subprocess
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def check_python_version():
    """Check Python version is 3.10+."""
    print("Checking Python version...")
    if sys.version_info < (3, 10):
        print(f"  ✗ Python 3.10+ required, found {sys.version}")
        return False
    print(f"  ✓ Python {sys.version_info.major}.{sys.version_info.minor}")
    return True


def check_dependencies():
    """Check required packages are installed."""
    print("\nChecking dependencies...")

    required = [
        'fastapi',
        'uvicorn',
        'pandas',
        'numpy',
        'scikit-learn',
        'loguru',
        'pydantic',
        'click',
    ]

    optional = [
        'tensorflow',
        'elasticsearch',
        'kafka',
        'redis',
    ]

    all_ok = True

    for package in required:
        try:
            __import__(package)
            print(f"  ✓ {package}")
        except ImportError:
            print(f"  ✗ {package} (REQUIRED)")
            all_ok = False

    for package in optional:
        try:
            __import__(package)
            print(f"  ✓ {package}")
        except ImportError:
            print(f"  ⚠ {package} (optional)")

    return all_ok


def check_imports():
    """Check project modules can be imported."""
    print("\nChecking project imports...")

    modules = [
        'src.analytics.feature_extractor',
        'src.analytics.models.isolation_forest_detector',
        'src.analytics.models.statistical_detector',
        'src.data_ingestion.adapters.base_adapter',
        'src.data_ingestion.adapters.sample_data_generator',
        'src.threat_hunting.lead_generator',
        'src.threat_hunting.enrichment.attack_mapper',
        'src.api.main',
    ]

    all_ok = True

    for module in modules:
        try:
            __import__(module)
            print(f"  ✓ {module}")
        except Exception as e:
            print(f"  ✗ {module}: {str(e)}")
            all_ok = False

    return all_ok


def check_config_files():
    """Check configuration files exist."""
    print("\nChecking configuration files...")

    files = [
        'config/production.yaml',
        'config/development.yaml',
        '.env',
        'docker-compose.yml',
        'requirements.txt',
    ]

    all_ok = True

    for file in files:
        file_path = project_root / file
        if file_path.exists():
            print(f"  ✓ {file}")
        else:
            print(f"  ✗ {file} (missing)")
            all_ok = False

    return all_ok


def main():
    """Run all verification checks."""
    print("=" * 60)
    print("Threat Hunting Platform - Installation Verification")
    print("=" * 60)

    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("Project Imports", check_imports),
        ("Configuration Files", check_config_files),
    ]

    results = []

    for name, check_func in checks:
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n✗ {name} check failed: {e}")
            results.append((name, False))

    print("\n" + "=" * 60)
    print("VERIFICATION SUMMARY")
    print("=" * 60)

    all_passed = True
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:10s} {name}")
        if not result:
            all_passed = False

    print("=" * 60)

    if all_passed:
        print("\n✓ All checks passed! System is ready.")
        return 0
    else:
        print("\n✗ Some checks failed. Please fix issues above.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
