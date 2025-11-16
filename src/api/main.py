"""
FastAPI application main entry point.
Provides REST API for threat hunting platform.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
import time

from api.v1 import anomalies, entities, threats, models, metrics

# Create FastAPI application
app = FastAPI(
    title="Advanced Threat Hunting Platform",
    description="Behavioral analytics and ML-driven threat detection platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests."""
    start_time = time.time()

    # Process request
    response = await call_next(request)

    # Log request details
    duration = time.time() - start_time
    logger.info(
        f"{request.method} {request.url.path} - "
        f"Status: {response.status_code} - "
        f"Duration: {duration:.3f}s"
    )

    return response


# Health check endpoint
@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint for load balancers and monitoring."""
    return {
        "status": "healthy",
        "service": "threat-hunting-platform",
        "version": "1.0.0"
    }


# Root endpoint
@app.get("/", tags=["System"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Advanced Threat Hunting Platform",
        "version": "1.0.0",
        "description": "Behavioral analytics and ML-driven threat detection",
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "api": "/api/v1"
        }
    }


# Include API routers
app.include_router(anomalies.router, prefix="/api/v1", tags=["Anomalies"])
app.include_router(entities.router, prefix="/api/v1", tags=["Entities"])
app.include_router(threats.router, prefix="/api/v1", tags=["Threats"])
app.include_router(models.router, prefix="/api/v1", tags=["Models"])
app.include_router(metrics.router, prefix="/api/v1", tags=["Metrics"])


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle uncaught exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": str(exc),
            "path": str(request.url.path)
        }
    )


# Startup event
@app.on_event("startup")
async def startup_event():
    """Execute on application startup."""
    logger.info("Starting Advanced Threat Hunting Platform API")
    logger.info("Initializing components...")

    # TODO: Initialize database connections, load models, etc.
    logger.info("API ready to accept requests")


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Execute on application shutdown."""
    logger.info("Shutting down Advanced Threat Hunting Platform API")

    # TODO: Close database connections, cleanup resources
    logger.info("Shutdown complete")
