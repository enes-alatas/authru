"""Configuration loader for the Authru."""

import json
import os
from typing import Dict, Any

try:
    import boto3

    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

from .models import (
    AuthenticationScheme,
    ProxyConfig,
    RouteConfig,
    AuthenticationConfig,
    PolicyConfig,
    SecurityConfig,
    MonitoringConfig,
)

from utils.logger import get_logger

logger = get_logger(__name__)


class ConfigurationError(Exception):
    """Raised when configuration is invalid or cannot be loaded."""


class ConfigLoader:
    """Loads and validates proxy configuration from S3 or local file."""

    def __init__(
        self,
        s3_bucket: str = None,
        s3_key: str = None,
        config_path: str = None,
    ) -> None:
        """
        Initialize the config loader.

        Args:
            s3_bucket: S3 bucket name for configuration.
            s3_key: S3 key for configuration file.
            s3_client: S3 client for configuration file.
            config_path: Path to the local configuration file (fallback).
        """
        # S3 configuration (priority)
        self._s3_bucket = s3_bucket or os.environ.get("AUTHRU_CONFIG_S3_BUCKET")
        self._s3_key = s3_key or os.environ.get("AUTHRU_CONFIG_S3_KEY")
        self._s3_client = None
        # Local file configuration (fallback)
        self.config_path = config_path or os.environ.get(
            "AUTHRU_CONFIG_PATH", "/config/routes.json"
        )
        if self._check_s3_config():
            self._initialize_s3_client()

    def _initialize_s3_client(self) -> None:
        if not BOTO3_AVAILABLE:
            logger.warning(
                "S3 configuration provided but boto3 is not available. "
                "Install boto3 to use S3 config source."
            )
            return
        try:
            self._s3_client = boto3.client("s3")
        except Exception as e:
            # Log warning but don't fail - will fall back to local file
            logger.warning("Failed to initialize S3 client: %s", e)

    def _check_s3_config(self) -> bool:
        return self._s3_bucket and self._s3_key

    def load_config(self) -> ProxyConfig:
        """
        Load and validate the proxy configuration.

        Tries to load from S3 first (if configured), then falls back to local
        file.

        Returns:
            `ProxyConfig`: The validated configuration object.

        Raises:
            `ConfigurationError`: If configuration is invalid or cannot be
            loaded.
        """
        config_data = None

        # Try S3 first if configured
        if self._s3_client and self._check_s3_config():
            try:
                config_data = self._load_from_s3()
            except Exception as e:
                logger.warning(
                    "Failed to load config from S3 (bucket=%s, key=%s), "
                    "falling back to local file. Reason: %s",
                    self._s3_bucket, self._s3_key, str(e)
                )

        # Fall back to local file if S3 not configured or failed
        if config_data is None:
            config_data = self._load_from_file()
        return self._parse_config(config_data)

    def _load_from_s3(self) -> Dict[str, Any]:
        """Load configuration from S3.

        Returns:
            `Dict`: Configuration data.

        Raises:
            `ConfigurationError`: If S3 load fails.
        """
        try:
            response = self._s3_client.get_object(
                Bucket=self._s3_bucket, Key=self._s3_key
            )
            config_content = response["Body"].read().decode("utf-8")
            return json.loads(config_content)
        except Exception as e:
            raise ConfigurationError("Unexpected error loading from S3") from e

    def _load_from_file(self) -> Dict[str, Any]:
        """Load configuration from local file.

        Returns:
            `Dict`: Configuration data.

        Raises:
            `ConfigurationError`: If file load fails.
        """
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            raise ConfigurationError(
                f"Configuration file not found: {self.config_path}"
            )
        except json.JSONDecodeError as e:
            raise ConfigurationError("Invalid JSON in configuration file") from e

    def _parse_config(self, config_data: Dict[str, Any]) -> ProxyConfig:
        """Parse configuration data into structured objects.

        Args:
            config_data: Raw configuration dictionary.

        Returns:
            `ProxyConfig`: Parsed configuration object.

        Raises:
            `ConfigurationError`: If configuration structure is invalid.
        """
        try:
            routes = self._parse_routes_configs(config_data.get("routes", []))
            security_config = self._security_config(config_data.get("security", {}))
            monitoring_config = self._monitoring_config(
                config_data.get("monitoring", {})
            )
            return ProxyConfig(
                routes=routes, security=security_config, monitoring=monitoring_config
            )
        except KeyError as e:
            raise ConfigurationError("Missing required configuration key") from e

    def _parse_routes_configs(self,
                              routes_data: list[dict[str, Any]]
                              ) -> list[RouteConfig]:
        """Parse a list of routes configuration.

        Args:
            routes_data: Raw routes configuration list.

        Returns:
            `list[RouteConfig]`: Parsed routes configuration list.

        Raises:
            `ConfigurationError`: If routes structure is invalid.
        """
        if len(routes_data) == 0:
            raise ConfigurationError("At least one route must be configured")
        return [self._parse_route_config(route_data)
                for route_data in routes_data]

    def _parse_route_config(self, route_data: dict[str, Any]) -> RouteConfig:
        """Parse a single route configuration.

        Args:
            route_data: Raw route configuration dictionary.

        Returns:
            `RouteConfig`: Parsed route configuration object.

        Raises:
            `ConfigurationError`: If route structure is invalid.
        """
        auth_config = self._auth_config(route_data["authentication"])
        policy_config = self._policy_config(route_data.get("policies", {}))
        route_config = RouteConfig(
            name=route_data.get("name"),
            path_pattern=route_data.get("pathPattern"),
            target_base_url=route_data.get("targetBaseUrl"),
            authentication=auth_config,
            policies=policy_config,
        )
        self._validate_route_config(route_config)
        return route_config


    @staticmethod
    def _validate_route_config(route: RouteConfig) -> None:
        if not route.name:
            raise ConfigurationError("Route name cannot be empty")
        if not route.path_pattern:
            raise ConfigurationError("Route path pattern cannot be empty")
        if not route.target_base_url:
            raise ConfigurationError("Route target base URL cannot be empty")
        if not route.authentication.parameter_name:
            raise ConfigurationError(
                "Authentication parameter name cannot be empty"
            )

    def _auth_config(self, auth_data: dict[str, Any]) -> AuthenticationConfig:
        """Parse an authentication configuration.

        Args:
            auth_data: Raw authentication configuration dictionary.

        Returns:
            `AuthenticationConfig`: Parsed authentication configuration object.
        """
        auth_config = AuthenticationConfig(
            scheme=AuthenticationScheme(auth_data["scheme"]),
            parameter_name=auth_data["parameterName"]
        )
        self._validate_auth_config(auth_config)
        return auth_config

    @staticmethod
    def _validate_auth_config(auth_config: AuthenticationConfig) -> None:
        if auth_config.parameter_name == "":
            raise ConfigurationError("Authentication parameter name cannot be empty")
        if auth_config.scheme not in AuthenticationScheme:
            raise ConfigurationError("Authentication scheme must be one of " + ", ".join(AuthenticationScheme))

    def _policy_config(self, policy_data: dict[str, Any]) -> PolicyConfig:
        """Parse a policy configuration.

        Args:
            policy_data: Raw policy configuration dictionary.

        Returns:
            `PolicyConfig`: Parsed policy configuration object.
        """
        policy_config = PolicyConfig(timeout=policy_data.get("timeout"),
                                     retries=policy_data.get("retries"))
        self._validate_policy_config(policy_config)
        return policy_config

    @staticmethod
    def _validate_policy_config(policy_config: PolicyConfig) -> None:
        try:
            assert isinstance(policy_config.timeout, int)
            assert policy_config.timeout > 0
            assert policy_config.timeout <= 300000
        except Exception as e:
            raise ConfigurationError(
                "Policy timeout must be an integer between 0 and 300000"
            ) from e
        try:
            assert isinstance(policy_config.retries, int)
            assert policy_config.retries >= 0
            assert policy_config.retries <= 10
        except Exception as e:
            raise ConfigurationError("Policy retries must be an integer "
                                     "between 0 and 10") from e

    def _security_config(self, security_data: dict[str, Any]) -> SecurityConfig:
        """Parse a security configuration.

        Args:
            security_data: Raw security configuration dictionary.

        Returns:
            `SecurityConfig`: Parsed security configuration object.
        """
        security_config = SecurityConfig(   
            allowed_origins=security_data.get("allowedOrigins"),
            cors_enabled=security_data.get("corsEnabled"),
            allow_credentials=security_data.get("allowCredentials"),
        )
        self._validate_security_config(security_config)
        return security_config

    @staticmethod
    def _validate_security_config(security_config: SecurityConfig) -> None:
        if security_config.cors_enabled and not security_config.allowed_origins:
            raise ConfigurationError("CORS is enabled but no allowed origins specified")

    def _monitoring_config(self, monitoring_data: dict[str, Any]) -> MonitoringConfig:
        """Parse a monitoring configuration.

        Args:
            monitoring_data: Raw monitoring configuration dictionary.

        Returns:
            `MonitoringConfig`: Parsed monitoring configuration object.
        """
        return MonitoringConfig(
            log_retention_days=monitoring_data.get("logRetentionDays"),
            log_level=monitoring_data.get("logLevel"),
            enable_metrics=monitoring_data.get("enableMetrics"),
            enable_tracing=monitoring_data.get("enableTracing"),
        )
