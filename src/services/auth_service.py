"""Authentication service for retrieving and managing API tokens."""

import base64
import boto3
from cachetools import TTLCache, cachedmethod

from config.models import AuthenticationConfig, AuthenticationScheme
from utils.logger import get_logger

logger = get_logger(__name__)

class AuthenticationError(Exception):
    """Raised when authentication operations fail."""

class AuthService:
    """Service for managing API authentication tokens."""

    def __init__(self, region: str = "eu-west-1"):
        """Initialize the authentication service.

        Args:
            config: Authentication configuration.
        """
        self.ssm_client = boto3.client("ssm", region_name=region)
        # Simple in-memory cache with 10 minutes TTL: no SLA for now
        # in case of any need to invalidate the cache manually other solutions
        # would have been necessary.
        self._header_cache = TTLCache(maxsize=1000, ttl=600)

    def get_auth_header(self, config: AuthenticationConfig) -> str:
        """Retrieve authentication header based on configuration.

        Args:
            config: Authentication configuration containing scheme and parameter info.

        Returns:
            str: Formatted Authorization header value.

        Raises:
            AuthenticationError: If authentication type is unsupported.
        """
        if config.scheme == AuthenticationScheme.BEARER:
            return self.get_bearer_header(config.parameter_name)
        elif config.scheme == AuthenticationScheme.BASIC:
            return self.get_basic_auth_header(config.parameter_name)
        else:
            raise AuthenticationError(f"Unsupported authentication scheme: {config.scheme}")

    @cachedmethod(cache=lambda self: self._header_cache)
    def get_bearer_header(self, parameter_name: str) -> str:
        """Retrieve and format a bearer token from Parameter Store.

        Results are cached in memory for Lambda function reuse to avoid
        repeated AWS API calls.

        Args:
            parameter_name: AWS Parameter Store parameter name containing
                the bearer token value.

        Returns:
            str: Formatted Authorization header value (Bearer token).
        """
        credentials = self._get_parameter(parameter_name)
        encoded_auth = self._encode_auth_string(credentials)
        bearer_token = f"{AuthenticationScheme.BEARER.value} {encoded_auth}"
        logger.info(
            "Successfully retrieved bearer token for parameter: %s",
            parameter_name
        )
        return bearer_token

    @cachedmethod(cache=lambda self: self._header_cache)
    def get_basic_auth_header(self, parameter_name: str) -> str:
        """Retrieve and format basic auth credentials from Parameter Store.

        Results are cached in memory for Lambda function reuse to avoid
        repeated AWS API calls.

        Args:
            parameter_name: AWS Parameter Store parameter name containing
                credentials in 'username:password' format.

        Returns:
            str: Formatted Authorization header value (Basic auth credentials).
        """
        credentials = self._get_parameter(parameter_name)
        basic_auth_credentials = self._build_basic_auth_string(credentials)
        logger.info(
            "Successfully retrieved basic auth credentials for parameter: %s",
            parameter_name
        )
        return basic_auth_credentials

    def _get_parameter(self, parameter_name: str) -> str:
        """Retrieve a parameter value from AWS Parameter Store.

        Args:
            parameter_name: Parameter name to retrieve.

        Returns:
            str: Parameter value.

        Raises:
            AuthenticationError: If parameter retrieval fails.
        """
        try:
            response = self.ssm_client.get_parameter(
                Name=parameter_name, WithDecryption=True
            )
            return response["Parameter"]["Value"]
        except Exception as e:
            logger.error(
                "Failed to retrieve parameter '%s': %s",
                parameter_name,
                str(e)
            )
            raise AuthenticationError(
                f"Failed to retrieve parameter '{parameter_name}': {str(e)}"
            ) from e

    def _build_basic_auth_string(self, credentials: str) -> str:
        """Build a Basic authentication header string.

        Args:
            credentials: Credentials string in 'username:password' format.

        Returns:
            str: Formatted Basic auth header value.

        Raises:
            AuthenticationError: If credentials format is invalid.
        """
        if ":" not in credentials:
            raise AuthenticationError(
                "Invalid credential format. Expected format: 'username:password'"
            )
        return f"{AuthenticationScheme.BASIC.value} {self._encode_auth_string(credentials)}"

    @staticmethod
    def _encode_auth_string(auth_string: str) -> str:
        """Encode a string to base64 for authentication headers.

        Args:
            auth_string: String to encode.

        Returns:
            str: Base64-encoded string.
        """
        return base64.b64encode(auth_string.encode("utf-8")).decode("ascii")

    def clear_cache(self) -> None:
        """Clear the header cache. Useful for testing or token rotation."""
        self._header_cache.clear()
        logger.info("Header cache cleared")

    def get_cached_header_count(self) -> int:
        """Get the number of cached headers. Useful for monitoring."""
        return self._header_cache.currsize
