"""Structured JSON logging configuration."""

import json
import logging
import sys
from datetime import datetime
from typing import Any

from .config import settings


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data: dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add run_id if present
        if hasattr(record, "run_id"):
            log_data["run_id"] = record.run_id

        # Add extra fields
        if hasattr(record, "extra"):
            log_data.update(record.extra)

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add context from record
        for key in ["method", "path", "status_code", "duration_ms", "client_ip"]:
            if hasattr(record, key):
                log_data[key] = getattr(record, key)

        return json.dumps(log_data)


def setup_logging() -> logging.Logger:
    """Configure structured logging for the application."""
    logger = logging.getLogger("grc_guardian")
    logger.setLevel(getattr(logging, settings.log_level.upper()))

    # Remove existing handlers
    logger.handlers.clear()

    # Create console handler
    handler = logging.StreamHandler(sys.stdout)

    # Use JSON formatter if configured
    if settings.json_logs:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
        )

    logger.addHandler(handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return logger


# Global logger instance
logger = setup_logging()


class LoggerAdapter(logging.LoggerAdapter):
    """Logger adapter that adds run_id to all log messages."""

    def process(
        self, msg: str, kwargs: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        """Add run_id to the log record."""
        extra = kwargs.get("extra", {})
        if "run_id" in self.extra:
            extra["run_id"] = self.extra["run_id"]
        kwargs["extra"] = extra
        return msg, kwargs


def get_logger_with_run_id(run_id: str) -> LoggerAdapter:
    """Get a logger instance with run_id context."""
    return LoggerAdapter(logger, {"run_id": run_id})
