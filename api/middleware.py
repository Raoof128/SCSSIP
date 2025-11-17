"""API middleware for logging, metrics, and request tracking."""

import logging
import time
from typing import Callable
from uuid import uuid4

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for structured request/response logging."""

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Log request and response details."""
        # Generate request ID for tracing
        request_id = str(uuid4())
        request.state.request_id = request_id

        # Log incoming request
        logger.info(
            "Incoming request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
            },
        )

        # Track request processing time
        start_time = time.time()

        try:
            response = await call_next(request)
            process_time = (time.time() - start_time) * 1000  # Convert to ms

            # Log response
            logger.info(
                "Request completed",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "process_time_ms": round(process_time, 2),
                },
            )

            # Add custom headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time"] = str(round(process_time, 2))

            return response

        except Exception as e:
            process_time = (time.time() - start_time) * 1000

            # Log error
            logger.error(
                "Request failed",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "process_time_ms": round(process_time, 2),
                },
                exc_info=True,
            )

            raise


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware for collecting application metrics."""

    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.request_count = {}
        self.error_count = {}
        self.response_times = {}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Collect metrics for each request."""
        path = request.url.path
        method = request.method
        route_key = f"{method} {path}"

        # Track request count
        self.request_count[route_key] = self.request_count.get(route_key, 0) + 1

        # Measure response time
        start_time = time.time()

        try:
            response = await call_next(request)

            # Track response time
            duration = (time.time() - start_time) * 1000
            if route_key not in self.response_times:
                self.response_times[route_key] = []
            self.response_times[route_key].append(duration)

            # Track errors
            if response.status_code >= 400:
                self.error_count[route_key] = self.error_count.get(route_key, 0) + 1

            return response

        except Exception as e:
            # Track exceptions
            self.error_count[route_key] = self.error_count.get(route_key, 0) + 1
            raise

    def get_metrics(self) -> dict:
        """Get current metrics."""
        metrics = {
            "total_requests": sum(self.request_count.values()),
            "total_errors": sum(self.error_count.values()),
            "requests_by_route": self.request_count.copy(),
            "errors_by_route": self.error_count.copy(),
            "avg_response_times": {
                route: sum(times) / len(times)
                for route, times in self.response_times.items()
                if times
            },
        }
        return metrics


def setup_logging(log_level: str = "INFO", json_format: bool = False):
    """Configure application logging."""
    if json_format:
        # JSON logging for production (parseable by log aggregators)
        import json_logging

        json_logging.init_fastapi(enable_json=True)
        json_logging.init_request_instrument()
    else:
        # Human-readable logging for development
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    # Set log levels for specific loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
