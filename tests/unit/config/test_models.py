"""Unit tests for configuration models.

This module contains comprehensive tests for all configuration model classes,
covering initialization, validation, default values, and edge cases.
"""

import pytest

from src.config.models import (
    AuthenticationConfig,
    PolicyConfig,
    RouteConfig,
    SecurityConfig,
    MonitoringConfig,
    ProxyConfig,
    AuthenticationScheme,
)


# Test constants
TEST_AUTH_TYPE = AuthenticationScheme.BEARER
TEST_AUTH_PARAM = "/authru/tokens/test-api"

TEST_ROUTE_NAME = "test-api"
TEST_PATH_PATTERN = "/api/v1/*"
TEST_TARGET_URL = "https://api.example.com"

TEST_TIMEOUT = 30000
TEST_RETRIES = 3

TEST_ORIGINS = ["https://example.com", "https://app.example.com"]
TEST_SINGLE_ORIGIN = ["https://example.com"]



class TestAuthenticationConfig:
    """Test cases for AuthenticationConfig class.
    
    Tests cover initialization, field validation, and edge cases
    for authentication configuration.
    """

    def test_authentication_config_initialization(self):
        """Test successful AuthenticationConfig initialization.
        
        Verifies that an AuthenticationConfig object is correctly
        created with all required fields.
        """
        auth_config = AuthenticationConfig(
            scheme=TEST_AUTH_TYPE,
            parameter_name=TEST_AUTH_PARAM
        )

        assert auth_config.scheme == TEST_AUTH_TYPE
        assert auth_config.parameter_name == TEST_AUTH_PARAM


class TestPolicyConfig:
    """Test cases for PolicyConfig class.
    
    Tests cover initialization, default values, field validation,
    and edge cases for policy configuration.
    """

    _DEFAULT_TIMEOUT = 30000
    _DEFAULT_RETRIES = 3
    def test_policy_config_initialization_with_values(self):
        """Test PolicyConfig initialization with explicit values.
        
        Verifies that a PolicyConfig object is correctly created
        with explicit timeout and retries values.
        """
        policy_config = PolicyConfig(
            timeout=TEST_TIMEOUT,
            retries=TEST_RETRIES
        )

        assert policy_config.timeout == TEST_TIMEOUT
        assert policy_config.retries == TEST_RETRIES

    def test_policy_config_default_values(self):
        """Test PolicyConfig initialization with default values.
        
        Verifies that PolicyConfig uses correct default values
        when no explicit values are provided.
        """
        policy_config = PolicyConfig()

        assert policy_config.timeout == self._DEFAULT_TIMEOUT
        assert policy_config.retries == self._DEFAULT_RETRIES

    @pytest.mark.parametrize("policy_config, expected", [
        (PolicyConfig(timeout=TEST_TIMEOUT), (TEST_TIMEOUT, _DEFAULT_RETRIES)),
        (PolicyConfig(retries=TEST_RETRIES), (_DEFAULT_TIMEOUT, TEST_RETRIES)),
    ])
    def test_policy_config_partial_defaults(self, policy_config, expected):
        """Test PolicyConfig initialization with partial defaults.
        
        Verifies that PolicyConfig correctly uses defaults for
        unspecified fields while using provided values for others.
        """
        assert policy_config.timeout == expected[0]
        assert policy_config.retries == expected[1]


class TestRouteConfig:
    """Test cases for RouteConfig class.
    
    Tests cover initialization, required fields, optional fields,
    and edge cases for route configuration.
    """

    def test_route_config_initialization_with_policies(self):
        """Test RouteConfig initialization with all fields.
        
        Verifies that a RouteConfig object is correctly created
        with all required and optional fields.
        """
        auth_config = AuthenticationConfig(
            scheme=TEST_AUTH_TYPE,
            parameter_name=TEST_AUTH_PARAM
        )
        policy_config = PolicyConfig(
            timeout=TEST_TIMEOUT,
            retries=TEST_RETRIES
        )

        route_config = RouteConfig(
            name=TEST_ROUTE_NAME,
            path_pattern=TEST_PATH_PATTERN,
            target_base_url=TEST_TARGET_URL,
            authentication=auth_config,
            policies=policy_config
        )

        assert route_config.name == TEST_ROUTE_NAME
        assert route_config.path_pattern == TEST_PATH_PATTERN
        assert route_config.target_base_url == TEST_TARGET_URL
        assert route_config.authentication == auth_config
        assert route_config.policies == policy_config

    def test_route_config_initialization_without_policies(self):
        """Test RouteConfig initialization without policies.
        
        Verifies that a RouteConfig object is correctly created
        with only required fields, using None for optional policies.
        """
        auth_config = AuthenticationConfig(
            scheme=TEST_AUTH_TYPE,
            parameter_name=TEST_AUTH_PARAM
        )

        route_config = RouteConfig(
            name=TEST_ROUTE_NAME,
            path_pattern=TEST_PATH_PATTERN,
            target_base_url=TEST_TARGET_URL,
            authentication=auth_config
        )

        assert route_config.name == TEST_ROUTE_NAME
        assert route_config.path_pattern == TEST_PATH_PATTERN
        assert route_config.target_base_url == TEST_TARGET_URL
        assert route_config.authentication == auth_config
        assert route_config.policies is None

class TestSecurityConfig:
    """Test cases for SecurityConfig class.
    
    Tests cover initialization, default values, field validation,
    and edge cases for security configuration.
    """

    _DEFAULT_CORS_ENABLED = True
    _DEFAULT_ALLOW_CREDENTIALS = False

    def test_security_config_initialization_with_values(self):
        """Test SecurityConfig initialization with explicit values.
        
        Verifies that a SecurityConfig object is correctly created
        with explicit values for all fields.
        """
        security_config = SecurityConfig(
            allowed_origins=TEST_ORIGINS,
            cors_enabled=True,
            allow_credentials=True
        )

        assert security_config.allowed_origins == TEST_ORIGINS
        assert security_config.cors_enabled is True
        assert security_config.allow_credentials is True

    def test_security_config_default_values(self):
        """Test SecurityConfig initialization with default values.
        
        Verifies that SecurityConfig uses correct default values
        when only required fields are provided.
        """
        security_config = SecurityConfig(allowed_origins=TEST_ORIGINS)

        assert security_config.allowed_origins == TEST_ORIGINS
        assert security_config.cors_enabled is True  # Default value
        assert security_config.allow_credentials is False  # Default value

    @pytest.mark.parametrize("security_config, expected", [
        (SecurityConfig(allowed_origins=TEST_ORIGINS), (TEST_ORIGINS, _DEFAULT_CORS_ENABLED, _DEFAULT_ALLOW_CREDENTIALS)),
        (SecurityConfig(allowed_origins=TEST_ORIGINS, cors_enabled=True), (TEST_ORIGINS, True, _DEFAULT_ALLOW_CREDENTIALS)),
        (SecurityConfig(allowed_origins=TEST_ORIGINS, allow_credentials=True), (TEST_ORIGINS, _DEFAULT_CORS_ENABLED, True)),
    ])
    def test_security_config_partial_defaults(self, security_config, expected):
        """Test SecurityConfig initialization with partial defaults.
        
        Verifies that SecurityConfig correctly uses defaults for
        unspecified fields while using provided values for others.
        """
        assert security_config.allowed_origins == expected[0]
        assert security_config.cors_enabled is expected[1]
        assert security_config.allow_credentials is expected[2]

    def test_security_config_empty_origins(self):
        """Test SecurityConfig with empty origins list.
        
        Verifies that SecurityConfig can be created with an
        empty list for allowed_origins.
        """
        security_config = SecurityConfig(allowed_origins=[])

        assert security_config.allowed_origins == []
        assert security_config.cors_enabled is self._DEFAULT_CORS_ENABLED
        assert security_config.allow_credentials is self._DEFAULT_ALLOW_CREDENTIALS



class TestMonitoringConfig:
    """Test cases for MonitoringConfig class.
    
    Tests cover initialization, default values, field validation,
    and edge cases for monitoring configuration.
    """
    _DEFAULT_ENABLE_METRICS = True
    _DEFAULT_ENABLE_TRACING = False
    _TEST_LOG_LEVEL = "INFO"
    _TEST_LOG_RETENTION = 7
    _DEFAULT_LOG_RETENTION = 7
    _DEFAULT_LOG_LEVEL = "INFO"

    def test_monitoring_config_initialization_with_values(self):
        """Test MonitoringConfig initialization with explicit values.
        
        Verifies that a MonitoringConfig object is correctly created
        with explicit values for all fields.
        """
        monitoring_config = MonitoringConfig(
            log_retention_days=self._TEST_LOG_RETENTION,
            log_level=self._TEST_LOG_LEVEL,
            enable_metrics=True,
            enable_tracing=True
        )

        assert monitoring_config.log_retention_days == self._TEST_LOG_RETENTION
        assert monitoring_config.log_level == self._TEST_LOG_LEVEL
        assert monitoring_config.enable_metrics is True
        assert monitoring_config.enable_tracing is True

    @pytest.mark.parametrize("monitoring_config, expected", [
        (MonitoringConfig(log_retention_days=_TEST_LOG_RETENTION), (_TEST_LOG_RETENTION, _DEFAULT_LOG_LEVEL, True, False)),
        (MonitoringConfig(log_level=_TEST_LOG_LEVEL), (_DEFAULT_LOG_RETENTION,_TEST_LOG_LEVEL, True, False)),
        (MonitoringConfig(enable_metrics=True), (_DEFAULT_LOG_RETENTION, _DEFAULT_LOG_LEVEL, True, False)),
        (MonitoringConfig(enable_tracing=True), (_DEFAULT_LOG_RETENTION, _DEFAULT_LOG_LEVEL, True, True)),
    ])
    def test_monitoring_config_partial_defaults(self, monitoring_config, expected):
        """Test MonitoringConfig initialization with partial defaults.
        
        Verifies that MonitoringConfig correctly uses defaults for
        unspecified fields while using provided values for others.
        """
        assert monitoring_config.log_retention_days == expected[0]
        assert monitoring_config.log_level == expected[1]
        assert monitoring_config.enable_metrics is expected[2]
        assert monitoring_config.enable_tracing is expected[3]

    def test_monitoring_config_different_log_levels(self):
        """Test MonitoringConfig with different log levels.
        
        Verifies that MonitoringConfig works correctly with
        various log level values.
        """
        log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

        for level in log_levels:
            monitoring_config = MonitoringConfig(log_level=level)
            assert monitoring_config.log_level == level


class TestProxyConfig:
    """Test cases for ProxyConfig class.
    
    Tests cover initialization, required fields, field validation,
    and edge cases for the main proxy configuration.
    """

    def test_proxy_config_initialization(self, sample_config):
        """Test ProxyConfig initialization with complete configuration.
        
        Verifies that a ProxyConfig object is correctly created
        with all required fields and proper structure.
        """
        config = sample_config

        assert isinstance(config, ProxyConfig)
        assert len(config.routes) == 1
        assert isinstance(config.routes[0], RouteConfig)
        assert isinstance(config.security, SecurityConfig)
        assert isinstance(config.monitoring, MonitoringConfig)

    def test_proxy_config_multiple_routes(self):
        """Test ProxyConfig with multiple routes.
        
        Verifies that ProxyConfig can handle multiple routes
        in the routes list.
        """
        auth_config1 = AuthenticationConfig(
            scheme=AuthenticationScheme.BEARER,
            parameter_name="/authru/tokens/api1"
        )
        auth_config2 = AuthenticationConfig(
            scheme=AuthenticationScheme.API_KEY,
            parameter_name="/authru/tokens/api2"
        )

        route1 = RouteConfig(
            name="api1",
            path_pattern="/api/v1/*",
            target_base_url="https://api1.example.com",
            authentication=auth_config1
        )
        route2 = RouteConfig(
            name="api2",
            path_pattern="/api/v2/*",
            target_base_url="https://api2.example.com",
            authentication=auth_config2
        )

        security_config = SecurityConfig(allowed_origins=TEST_ORIGINS)
        monitoring_config = MonitoringConfig()

        proxy_config = ProxyConfig(
            routes=[route1, route2],
            security=security_config,
            monitoring=monitoring_config
        )

        assert len(proxy_config.routes) == 2
        assert proxy_config.routes[0].name == "api1"
        assert proxy_config.routes[1].name == "api2"
        assert proxy_config.security == security_config
        assert proxy_config.monitoring == monitoring_config

    def test_proxy_config_empty_routes(self):
        """Test ProxyConfig with empty routes list.
        
        Verifies that ProxyConfig can be created with an
        empty routes list.
        """
        security_config = SecurityConfig(allowed_origins=TEST_ORIGINS)
        monitoring_config = MonitoringConfig()

        proxy_config = ProxyConfig(
            routes=[],
            security=security_config,
            monitoring=monitoring_config
        )

        assert len(proxy_config.routes) == 0
        assert proxy_config.security == security_config
        assert proxy_config.monitoring == monitoring_config

    def test_proxy_config_routes_without_policies(self):
        """Test ProxyConfig with routes that have no policies.
        
        Verifies that ProxyConfig works correctly when routes
        are configured without policy configurations.
        """
        auth_config = AuthenticationConfig(
            scheme=TEST_AUTH_TYPE,
            parameter_name=TEST_AUTH_PARAM
        )

        route = RouteConfig(
            name=TEST_ROUTE_NAME,
            path_pattern=TEST_PATH_PATTERN,
            target_base_url=TEST_TARGET_URL,
            authentication=auth_config
            # No policies specified
        )

        security_config = SecurityConfig(allowed_origins=TEST_ORIGINS)
        monitoring_config = MonitoringConfig()

        proxy_config = ProxyConfig(
            routes=[route],
            security=security_config,
            monitoring=monitoring_config
        )

        assert len(proxy_config.routes) == 1
        assert proxy_config.routes[0].policies is None

    def test_proxy_config_minimal_security(self):
        """Test ProxyConfig with minimal security configuration.
        
        Verifies that ProxyConfig works with minimal security
        configuration using only required fields.
        """
        auth_config = AuthenticationConfig(
            scheme=TEST_AUTH_TYPE,
            parameter_name=TEST_AUTH_PARAM
        )

        route = RouteConfig(
            name=TEST_ROUTE_NAME,
            path_pattern=TEST_PATH_PATTERN,
            target_base_url=TEST_TARGET_URL,
            authentication=auth_config
        )

        # Minimal security config with only required field
        security_config = SecurityConfig(allowed_origins=[])
        monitoring_config = MonitoringConfig()

        proxy_config = ProxyConfig(
            routes=[route],
            security=security_config,
            monitoring=monitoring_config
        )

        assert proxy_config.security.allowed_origins == []
        assert proxy_config.security.cors_enabled is True  # Default
        assert proxy_config.security.allow_credentials is False  # Default


    def test_proxy_config_field_access(self, sample_config):
        """Test ProxyConfig field access and structure.
        
        Verifies that all fields in ProxyConfig can be accessed
        and have the expected types and values.
        """
        config = sample_config

        # Test routes access
        assert hasattr(config, 'routes')
        assert isinstance(config.routes, list)
        assert len(config.routes) > 0

        # Test security access
        assert hasattr(config, 'security')
        assert isinstance(config.security, SecurityConfig)
        assert hasattr(config.security, 'allowed_origins')
        assert hasattr(config.security, 'cors_enabled')
        assert hasattr(config.security, 'allow_credentials')

        # Test monitoring access
        assert hasattr(config, 'monitoring')
        assert isinstance(config.monitoring, MonitoringConfig)
        assert hasattr(config.monitoring, 'log_retention_days')
        assert hasattr(config.monitoring, 'log_level')
        assert hasattr(config.monitoring, 'enable_metrics')
        assert hasattr(config.monitoring, 'enable_tracing')

