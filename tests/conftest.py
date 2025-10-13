"""Pytest configuration and fixtures for Authru tests."""

import json
import os
import pytest
from unittest.mock import Mock, patch

from src.config.models import (
    ProxyConfig,
    RouteConfig,
    AuthenticationConfig,
    PolicyConfig,
    SecurityConfig,
    MonitoringConfig,
    AuthenticationScheme,
)


@pytest.fixture
def sample_config():
    """Sample configuration for testing."""
    return ProxyConfig(
        routes=[
            RouteConfig(
                name="test-api",
                path_pattern="/api/v1/*",
                target_base_url="https://api.example.com",
                authentication=AuthenticationConfig(
                    scheme=AuthenticationScheme.BEARER, parameter_name="/authru/tokens/test-api"
                ),
                policies=PolicyConfig(timeout=30000, retries=3),
            )
        ],
        security=SecurityConfig(
            allowed_origins=["https://example.com"],
            cors_enabled=True,
            allow_credentials=False,
        ),
        monitoring=MonitoringConfig(
            log_retention_days=7,
            log_level="INFO",
            enable_metrics=True,
            enable_tracing=False,
        ),
    )


@pytest.fixture
def sample_config_json():
    """Sample configuration as JSON string."""
    return json.dumps(
        {
            "routes": [
                {
                    "name": "test-api",
                    "pathPattern": "/api/v1/*",
                    "targetBaseUrl": "https://api.example.com",
                    "authentication": {
                        "scheme": "Bearer",
                        "parameterName": "/authru/tokens/test-api",
                    },
                    "policies": {"timeout": 30000, "retries": 3},
                }
            ],
            "security": {
                "allowedOrigins": ["https://example.com"],
                "corsEnabled": True,
                "allowCredentials": False,
            },
            "monitoring": {
                "logRetentionDays": 7,
                "logLevel": "INFO",
                "enableMetrics": True,
                "enableTracing": False,
            },
        }
    )

@pytest.fixture
def sample_config_data_dict(sample_config_json):
    """Sample configuration as dictionary."""
    return json.loads(sample_config_json)

@pytest.fixture
def sample_lambda_event():
    """Sample Lambda event for testing."""
    return {
        "httpMethod": "GET",
        "path": "/api/v1/users",
        "headers": {
            "Host": "api.example.com",
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json",
            "Origin": "https://example.com",
        },
        "queryStringParameters": {"limit": "10", "offset": "0"},
        "body": None,
        "requestContext": {
            "requestId": "test-request-id",
            "identity": {"sourceIp": "192.168.1.1"},
        },
    }


@pytest.fixture
def sample_lambda_context():
    """Sample Lambda context for testing."""
    context = Mock()
    context.function_name = "authru-test"
    context.function_version = "$LATEST"
    context.invoked_function_arn = (
        "arn:aws:lambda:eu-west-1:123456789012:function:authru-test"
    )
    context.memory_limit_in_mb = "256"
    context.remaining_time_in_millis = lambda: 30000
    context.aws_request_id = "test-request-id"
    return context


@pytest.fixture
def mock_ssm_client():
    """Mock SSM client for testing."""
    with patch("boto3.client") as mock_client:
        mock_ssm = Mock()
        mock_ssm.get_parameter.return_value = {
            "Parameter": {"Value": "testuser:testpass"}
        }
        mock_client.return_value = mock_ssm
        yield mock_ssm


@pytest.fixture
def mock_requests():
    """Mock requests library for testing."""
    with patch("requests.Session") as mock_session_class:
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.text = '{"success": true}'
        mock_session.request.return_value = mock_response
        mock_session_class.return_value = mock_session
        yield mock_session


@pytest.fixture(autouse=True)
def setup_test_environment():
    """Set up test environment variables."""
    os.environ["LOG_LEVEL"] = "DEBUG"
    os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"
    yield
    # Cleanup
    if "LOG_LEVEL" in os.environ:
        del os.environ["LOG_LEVEL"]
    if "AWS_DEFAULT_REGION" in os.environ:
        del os.environ["AWS_DEFAULT_REGION"]
