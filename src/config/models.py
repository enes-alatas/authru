"""Configuration models for the Authru."""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional



class AuthenticationScheme(Enum):
    """Scheme of authentication."""
    BEARER = "Bearer"
    API_KEY = "ApiKey"
    BASIC = "Basic"

    def __str__(self):
        return self.value

    def __eq__(self, other):
        return str(self) == str(other)

@dataclass
class AuthenticationConfig:
    """Configuration for API authentication."""

    scheme: AuthenticationScheme  # "Bearer", "ApiKey", etc.
    parameter_name: str  # AWS Parameter Store parameter name

@dataclass
class PolicyConfig:
    """Configuration for request policies."""

    timeout: int = 30000  # Timeout in milliseconds
    retries: int = 3  # Number of retry attempts


@dataclass
class RouteConfig:
    """Configuration for a single API route."""

    name: str
    path_pattern: str
    target_base_url: str
    authentication: AuthenticationConfig
    policies: Optional[PolicyConfig] = None


@dataclass
class SecurityConfig:
    """Security configuration for CORS and origin validation."""

    allowed_origins: List[str]
    cors_enabled: bool = True
    allow_credentials: bool = False


@dataclass
class MonitoringConfig:
    """Monitoring and logging configuration."""

    log_retention_days: int = 7
    log_level: str = "INFO"
    enable_metrics: bool = True
    enable_tracing: bool = False


@dataclass
class ProxyConfig:
    """Main configuration for the proxy."""

    routes: List[RouteConfig]
    security: SecurityConfig
    monitoring: MonitoringConfig
