"""FastAPI main application."""

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from api.middleware import LoggingMiddleware, MetricsMiddleware, setup_logging
from api.routers import compliance, risk, sboms, vulnerabilities
from src.common.config import get_settings
from src.database.base import get_db, init_db

# Get settings
settings = get_settings()

# Setup logging
setup_logging(log_level=settings.log_level, json_format=(settings.environment == "production"))

logger = logging.getLogger(__name__)


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

# Configure middleware
# CORS (must be last)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add logging middleware
app.add_middleware(LoggingMiddleware)

# Add metrics middleware
# Note: We don't actually need to store the instance for /metrics endpoint
# as middleware instances are managed by FastAPI
app.add_middleware(MetricsMiddleware)


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
    """Detailed health check with database connectivity test."""
    components_status = {}
    overall_healthy = True

    # Check database connectivity
    try:
        db = next(get_db())
        db.execute(text("SELECT 1"))
        components_status["database"] = "healthy"
    except Exception as e:
        components_status["database"] = f"unhealthy: {str(e)}"
        overall_healthy = False
        logger.error(f"Database health check failed: {e}")

    # TODO: Add Redis health check when Redis is implemented
    components_status["cache"] = "not_configured"

    # Check external API endpoints (optional - can be slow)
    # components_status["nvd_api"] = "healthy" if check_nvd_api() else "unhealthy"

    status_code = 200 if overall_healthy else 503

    return {
        "status": "healthy" if overall_healthy else "unhealthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "components": components_status,
        "status_code": status_code,
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


@app.get("/metrics", tags=["Monitoring"])
async def get_metrics() -> dict[str, Any]:
    """
    Get application metrics (requests, errors, response times).

    This endpoint provides operational metrics for monitoring.
    In production, consider using Prometheus format instead.

    Note: Metrics are collected by the MetricsMiddleware.
    For production, integrate with Prometheus/Grafana.
    """
    # TODO: Integrate with Prometheus or return actual metrics from middleware
    # For now, return basic info
    return {
        "status": "metrics_collection_active",
        "note": "Metrics are being collected. Integrate with Prometheus for detailed metrics."
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
