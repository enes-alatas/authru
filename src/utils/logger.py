"""Logging utilities for the Authru."""

import json
import logging
import os
from typing import Any, Dict


class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured JSON logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON.

        Args:
            record: Log record to format.

        Returns:
            str: JSON formatted log message.
        """
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add extra fields if present
        if hasattr(record, "extra"):
            log_entry.update(record.extra)

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, ensure_ascii=False)


def get_logger(name: str) -> logging.Logger:
    """Get a configured logger instance.

    Args:
        name: Logger name (typically __name__).

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(name)

    # Only configure if not already configured
    if not logger.handlers:
        # Get log level from environment
        log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
        logger.setLevel(getattr(logging, log_level, logging.INFO))

        # Create console handler
        handler = logging.StreamHandler()
        handler.setLevel(logger.level)

        # Set formatter based on environment
        if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
            # Use structured logging in Lambda
            formatter = StructuredFormatter()
        else:
            # Use simple formatting for local development
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )

        handler.setFormatter(formatter)
        logger.addHandler(handler)

        # Prevent duplicate logs
        logger.propagate = False

    return logger


def log_request(logger: logging.Logger, event: Dict[str, Any]) -> None:
    """Log incoming request details.

    Args:
        logger: Logger instance.
        event: Lambda event object.
    """
    request_info = {
        "method": event.get("httpMethod"),
        "path": event.get("path"),
        "source_ip": event.get("requestContext", {})
        .get("identity", {})
        .get("sourceIp"),
        "user_agent": event.get("headers", {}).get("User-Agent"),
        "request_id": event.get("requestContext", {}).get("requestId"),
    }

    logger.info("Incoming request", extra=request_info)


def log_response(logger: logging.Logger, status_code: int, response_size: int) -> None:
    """Log response details.

    Args:
        logger: Logger instance.
        status_code: HTTP status code.
        response_size: Response body size in bytes.
    """
    response_info = {"status_code": status_code, "response_size": response_size}

    logger.info("Outgoing response", extra=response_info)
