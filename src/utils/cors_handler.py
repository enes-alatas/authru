"""CORS utilities for the Authru."""

from typing import Dict, List, Optional
from urllib.parse import urlparse

from config.models import SecurityConfig
from services.models import ProxyResponse
from utils.logger import get_logger

logger = get_logger(__name__)


class CORSError(Exception):
    """Raised when CORS validation fails."""

class CORSHandler:
    """Handles CORS validation and header generation."""

    def __init__(self, security_config: SecurityConfig):
        """Initialize CORS handler.

        Args:
            security_config: Security configuration containing CORS settings.
        """
        self.security_config = security_config

    def validate_origin(self, origin: Optional[str]) -> bool:
        """Validate if the request origin is allowed.

        Args:
            origin: Origin header from the request.

        Returns:
            bool: True if origin is allowed, False otherwise.
        """
        if not self.security_config.cors_enabled:
            return True

        if not origin:
            # No origin header - could be same-origin or non-browser request
            logger.debug("No origin header present")
            return True

        # Check if origin is in allowed list
        if origin in self.security_config.allowed_origins:
            logger.debug(f"Origin {origin} is explicitly allowed")
            return True

        # Check for wildcard patterns (basic support)
        for allowed_origin in self.security_config.allowed_origins:
            if allowed_origin == "*":
                logger.debug("Wildcard origin allowed")
                return True

            # Basic subdomain matching (*.example.com)
            if allowed_origin.startswith("*."):
                domain = allowed_origin[2:]  # Remove *.
                origin_parsed = urlparse(origin)
                if (
                    origin_parsed.netloc.endswith(f".{domain}")
                    or origin_parsed.netloc == domain
                ):
                    logger.debug(
                        f"Origin {origin} matches wildcard pattern {allowed_origin}"
                    )
                    return True

        logger.warning(f"Origin {origin} is not allowed")
        return False

    def get_cors_headers(
        self, origin: Optional[str]
    ) -> Dict[str, str]:
        """Get CORS headers for the response.

        Args:
            origin: Origin header from the request.

        Returns:
            Dict[str, str]: CORS headers to include in response.
        """
        headers = {}

        if not self.security_config.cors_enabled:
            return headers

        # Set Access-Control-Allow-Origin
        if self.validate_origin(origin):
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
            else:
                # If no origin and we allow it, set to first allowed origin or *
                if "*" in self.security_config.allowed_origins:
                    headers["Access-Control-Allow-Origin"] = "*"
                elif self.security_config.allowed_origins:
                    headers[
                        "Access-Control-Allow-Origin"
                    ] = self.security_config.allowed_origins[0]

        # Set other CORS headers
        headers[
            "Access-Control-Allow-Methods"
        ] = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
        headers[
            "Access-Control-Allow-Headers"
        ] = "Content-Type, Authorization, X-Requested-With, Accept, Origin"

        if self.security_config.allow_credentials:
            headers["Access-Control-Allow-Credentials"] = "true"

        # Cache preflight for 24 hours
        headers["Access-Control-Max-Age"] = "86400"

        return headers

    def handle_preflight(self, origin: Optional[str]) -> ProxyResponse:
        """Handle CORS preflight request.

        Args:
            origin: Origin header from the request.

        Returns:
            Dict: Lambda response for preflight request.
        """
        cors_headers = {"Content-Type": "application/json"}
        if not self.validate_origin(origin):
            return ProxyResponse(status_code=403, headers=cors_headers, body='{"error": "Origin not allowed"}')  

        cors_headers |= self.get_cors_headers(origin)

        return ProxyResponse(status_code=200, headers=cors_headers, body='{"message": "CORS preflight successful"}')
