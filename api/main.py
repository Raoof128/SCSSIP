"""FastAPI main application."""

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routers import compliance, risk, sboms, vulnerabilities
from src.common.config import get_settings
from src.database.base import init_db

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore
    """Application lifespan events."""
    # Startup
    logger.info("Starting SBOM Security Platform...")
    logger.info(f"Environment: {settings.environment}")

    # Initialize database
    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")

    yield

    # Shutdown
    logger.info("Shutting down SBOM Security Platform...")


# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
    Supply Chain Security & SBOM Intelligence Platform

    ## Features

    * **SBOM Ingestion**: Parse CycloneDX and SPDX formats
    * **Vulnerability Correlation**: NVD, OSV, GitHub Advisory integration
    * **Risk Scoring**: Multi-factor algorithm (vulnerability, license, signing, depth)
    * **Compliance**: SLSA L1-L3 and NTIA minimum elements validation
    * **Reporting**: HTML/PDF compliance and risk reports

    ## Complete Platform Capabilities

    - SBOM parsing (CycloneDX 1.4-1.6, SPDX 2.2-3.0)
    - Component extraction with PURL/CPE matching
    - Vulnerability correlation from 3+ feeds (NVD, OSV, GitHub)
    - EPSS exploit prediction scores
    - Multi-factor risk scoring (5 factors)
    - SLSA framework validation (Levels 0-3)
    - NTIA compliance checking
    - Automated security reports
    """,
    lifespan=lifespan,
    debug=settings.debug,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["Health"])
async def root() -> dict[str, str]:
    """Root endpoint - health check."""
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
    }


@app.get("/health", tags=["Health"])
async def health() -> dict[str, Any]:
    """Detailed health check."""
    # TODO: Add database and redis health checks
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "components": {
            "database": "healthy",  # TODO: Implement actual check
            "cache": "healthy",  # TODO: Implement actual check
        },
    }


@app.get("/api/v1/info", tags=["Info"])
async def info() -> dict[str, Any]:
    """Get platform information and capabilities."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "supported_sbom_formats": [
            {"format": "CycloneDX", "versions": ["1.4", "1.5", "1.6"]},
            {"format": "SPDX", "versions": ["2.2", "2.3", "3.0"]},
        ],
        "features": {
            "sbom_parsing": True,
            "vulnerability_correlation": True,
            "risk_scoring": True,
            "compliance_checking": True,
            "reporting": True,
        },
        "vulnerability_sources": ["NVD", "OSV", "GitHub Advisory"],
        "compliance_frameworks": ["SLSA (L0-L3)", "NTIA Minimum Elements"],
        "phase": "Complete Platform - All Phases Implemented",
    }


# Include API routers
app.include_router(sboms.router, prefix="/api/v1/sboms", tags=["SBOMs"])
app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(risk.router, prefix="/api/v1/risk", tags=["Risk Scoring"])
app.include_router(compliance.router, prefix="/api/v1/compliance", tags=["Compliance"])

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level="info",
    )
