"""Proxy service for forwarding requests to third-party APIs."""
from multiprocessing import AuthenticationError
import re
from cachetools import TTLCache, cachedmethod
import requests
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse

from config.models import ProxyConfig, RouteConfig
from services.auth_service import AuthService
from config.config_loader import ConfigLoader
from services.models import ProxyResponse
from utils.cors_handler import CORSHandler
from utils.logger import get_logger

logger = get_logger(__name__)


class ProxyError(Exception):
    """Raised when proxy operations fail."""


class ProxyService:
    """Service for proxying requests to third-party APIs."""

    DEFAULT_TIMEOUT = 30
    _HOP_BY_HOP_HEADERS = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
    
    def __init__(self):
        self._auth_service = AuthService(region="eu-west-1")
        self._config_loader = ConfigLoader()
        self._cache = TTLCache(maxsize=100, ttl=600)

    def forward_request(
        self,
        event: Dict[str, Any],
    ) -> ProxyResponse:
        """Forward a request to the target API.

        Args:
            route: Route configuration for the target API.
            path: Request path (without the matched pattern prefix).
            method: HTTP method.
            headers: Request headers.
            query_params: Query parameters.
            body: Request body (if any).

        Returns:
            Tuple of (status_code, response_headers, response_body).

        Raises:
            ProxyError: If the request forwarding fails.
        """
        try:
            config = self._get_config()
            cors_handler = CORSHandler(config.security)
            path = event.get("path", "/")
            query_params = event.get("queryStringParameters")
            body = event.get("body")
            route = self._matching_route(config.routes, path)
            if not route:
                # No matching route found
                return ProxyResponse(status_code=404, headers={}, body="No matching route found")
            method = event.get("httpMethod")
            headers = event.get("headers", {})
            origin = headers.get("Origin") or headers.get("origin")
            if method == "OPTIONS":
                return cors_handler.handle_preflight(origin)
            headers.update(cors_handler.get_cors_headers(origin))
            headers = self._add_auth(route, headers)
            target_url = self._build_target_url(route, path)
            forwarded_headers = self._prepare_headers(headers)
            timeout = self.DEFAULT_TIMEOUT
            if route.policies:
                timeout = route.policies.timeout / 1000  # Convert ms to seconds
            logger.info(
                "Forwarding %s request to %s", method, target_url,
                extra={
                    "route_name": route.name,
                    "method": method,
                    "target_url": target_url,
                    "timeout": timeout,
                },
            )
            response = requests.request(
                method=method,
                url=target_url,
                headers=forwarded_headers,
                params=query_params,
                data=body,
                timeout=timeout,
                allow_redirects=False,  # Don't follow redirects automatically
            )

            # Prepare response headers (remove hop-by-hop headers)
            response_headers = self._prepare_headers(dict(response.headers))
            response_headers.update(cors_handler.get_cors_headers(origin))
            logger.info(
                "Received response from %s", target_url,
                extra={
                    "route_name": route.name,
                    "status_code": response.status_code,
                    "response_size": len(response.content),
                },
            )

            return ProxyResponse(status_code=response.status_code,
                                 headers=response_headers,
                                 body=response.text)
        except Exception as e:
            logger.error("Unexpected error forwarding request: %s", e)
            raise ProxyError("Unexpected error: %s", e) from e

    @cachedmethod(cache=lambda self: self._cache)
    def _get_config(self) -> ProxyConfig:
        config = self._config_loader.load_config()
        logger.info("Configuration loaded and validated")
        return config

    @cachedmethod(cache=lambda self: self._cache,
                  key=lambda self, routes, path: path)
    def _matching_route(self, routes: list[RouteConfig], path: str) -> RouteConfig:
        for route in routes:
            route_pattern = route.path_pattern.replace("*", ".*")
            if re.match(route_pattern, path):
                return route
        return None

    def _add_auth(self,
                  route: RouteConfig,
                  headers: Dict[str, str]) -> Dict[str, str]:
        auth_header = headers.get("Authorization") or headers.get("authorization")
        if not auth_header:
        # Add Basic Authentication from Parameter Store
            new_auth_header = self._auth_service.get_auth_header(
                route.authentication
            )
            headers["Authorization"] = new_auth_header
            logger.info("Added authentication header for route: %s", route.name)
        else:
            logger.info("Request already has authorization header for route: %s", route.name)
        return headers

    def _build_target_url(self, route: RouteConfig, path: str) -> str:
        """Build the target URL for the API request.

        Args:
            route: Route configuration.
            path: Request path to append.

        Returns:
            str: Complete target URL.
        """
        forwarded_path = self._extract_forwarded_path(route.path_pattern, path)
        # Join base URL with path
        target_url = urljoin(route.target_base_url.rstrip("/") + "/", forwarded_path)
        return target_url

    @staticmethod
    def _extract_forwarded_path(pattern: str, full_path: str) -> str:
        """Extract the path to forward by removing the matched pattern prefix.

        Args:
            pattern: Route path pattern (e.g., "/api/v1/*").
            full_path: Full request path.

        Returns:
            str: Path to forward to the target API.
        """
        # Remove the pattern prefix (everything before the *)
        if "*" in pattern:
            prefix = pattern.split("*")[0]
            if full_path.startswith(prefix):
                forwarded_path = full_path[len(prefix) :]
                # Ensure path starts with /
                if not forwarded_path.startswith("/"):
                    forwarded_path = "/" + forwarded_path
                return forwarded_path

        # If no wildcard, forward the entire path
        return full_path

    @classmethod
    def _prepare_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        """Prepare headers by removing hop-by-hop headers.

        Args:
            headers: Original headers.

        Returns:
            Dict[str, str]: Cleaned headers for forwarding.
        """
        forwarded_headers = {}
        for key, value in headers.items():
            if key.lower() not in cls._HOP_BY_HOP_HEADERS:
                forwarded_headers[key] = value

        return forwarded_headers
