"""GRC Guardian API - Main application."""

import time
from pathlib import Path
from typing import Callable

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from .logging_config import logger
from .routes import router
from .schemas import ErrorResponse

# Create FastAPI app
app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    description=settings.api_description,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS middleware - allow frontend to call API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Middleware for logging and timing
@app.middleware("http")
async def log_requests(request: Request, call_next: Callable) -> Response:
    """Log all incoming requests and measure response time."""
    start_time = time.time()

    # Log request
    logger.info(
        "Incoming request",
        extra={
            "method": request.method,
            "path": request.url.path,
            "client_ip": request.client.host if request.client else "unknown",
        },
    )

    # Process request
    response = await call_next(request)

    # Calculate duration
    duration_ms = int((time.time() - start_time) * 1000)

    # Add rate limit headers if available
    if hasattr(request.state, "rate_limit_remaining"):
        response.headers["X-RateLimit-Remaining"] = str(
            request.state.rate_limit_remaining
        )
        response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_requests)
        response.headers["X-RateLimit-Window"] = str(
            settings.rate_limit_window_seconds
        )

    # Log response
    logger.info(
        "Request completed",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
        },
    )

    return response


# Exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Handle validation errors with detailed messages."""
    logger.warning(
        "Validation error",
        extra={
            "errors": exc.errors(),
            "body": exc.body,
        },
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=ErrorResponse(
            error="ValidationError",
            message="Request validation failed. Check your input.",
        ).model_dump(mode="json"),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions."""
    logger.error(
        f"Unhandled exception: {exc}",
        extra={
            "method": request.method,
            "path": request.url.path,
        },
        exc_info=True,
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="InternalServerError",
            message="An unexpected error occurred. Please try again later.",
        ).model_dump(mode="json"),
    )


# Include routers
app.include_router(router, prefix="/api/v1")


# Startup and shutdown events
@app.on_event("startup")
async def startup_event() -> None:
    """Run on application startup."""
    logger.info(
        "GRC Guardian API starting up",
        extra={
            "version": settings.api_version,
            "log_level": settings.log_level,
        },
    )


@app.on_event("shutdown")
async def shutdown_event() -> None:
    """Run on application shutdown."""
    logger.info("GRC Guardian API shutting down")


# Root endpoint - serve dashboard
@app.get("/")
async def root():
    """Serve the compliance dashboard."""
    frontend_path = Path(__file__).parent.parent.parent / "frontend" / "index.html"

    if frontend_path.exists():
        return FileResponse(frontend_path)
    else:
        # Fallback to API info if dashboard not found
        return {
            "name": settings.api_title,
            "version": settings.api_version,
            "status": "running",
            "docs": "/docs",
            "health": "/api/v1/health",
            "dashboard": "Dashboard not found. Check frontend/index.html"
        }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level=settings.log_level.lower(),
    )
