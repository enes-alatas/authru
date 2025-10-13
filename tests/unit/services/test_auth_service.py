"""Unit tests for authentication service.

This module contains comprehensive tests for the AuthService class,
including token retrieval, caching, error handling, and edge cases.
"""

import base64
import pytest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError

from src.config.models import AuthenticationConfig, AuthenticationScheme
from src.services.auth_service import AuthService, AuthenticationError


class TestAuthService:
    """Test cases for AuthService class."""

    def test_get_auth_header_bearer(self, mock_ssm_client):
        """Test get_auth_header with bearer authentication type.

        Verifies that:
        - AuthenticationConfig is properly handled
        - Bearer type correctly delegates to get_bearer_token
        - Proper Authorization header is returned
        """
        auth_service = AuthService()
        auth_service.ssm_client = mock_ssm_client

        config = AuthenticationConfig(
            scheme=AuthenticationScheme.BEARER,
            parameter_name="/authru/tokens/test-api"
        )
        token = auth_service.get_auth_header(config)

        expected_auth = base64.b64encode(b"testuser:testpass").decode("ascii")
        expected_token = f"Bearer {expected_auth}"

        assert token == expected_token, "Should return Bearer token"

    def test_get_auth_header_basic(self, mock_ssm_client):
        """Test get_auth_header with basic authentication type.

        Verifies that:
        - AuthenticationConfig is properly handled
        - Basic type correctly delegates to get_basic_auth_credentials
        - Proper Authorization header is returned
        """
        auth_service = AuthService()
        auth_service.ssm_client = mock_ssm_client

        config = AuthenticationConfig(
            scheme=AuthenticationScheme.BASIC,
            parameter_name="/authru/tokens/test-api"
        )
        token = auth_service.get_auth_header(config)

        expected_auth = base64.b64encode(b"testuser:testpass").decode("ascii")
        expected_token = f"Basic {expected_auth}"

        assert token == expected_token, "Should return Basic auth credentials"

    def test_get_auth_header_unsupported_type(self, mock_ssm_client):
        """Test get_auth_header with unsupported authentication type.

        Verifies that:
        - Invalid authentication types are rejected
        - AuthenticationError is raised with clear message
        """
        auth_service = AuthService()
        auth_service.ssm_client = mock_ssm_client

        # Create a mock config with invalid type
        config = Mock()
        config.scheme = "invalid_type"
        config.parameter_name = "/authru/tokens/test-api"

        with pytest.raises(
            AuthenticationError,
            match="Unsupported authentication scheme"
        ):
            auth_service.get_auth_header(config)

    def test_get_bearer_token_success(self, mock_ssm_client):
        """Test successful bearer token retrieval.

        Verifies that:
        - Token is correctly retrieved from AWS Parameter Store
        - Token is properly base64 encoded
        - Bearer prefix is correctly added
        - SSM client is called with correct parameters
        """
        auth_service = AuthService()
        auth_service.ssm_client = mock_ssm_client

        token = auth_service.get_bearer_header("/authru/tokens/test-api")

        expected_auth = base64.b64encode(b"testuser:testpass").decode("ascii")
        expected_token = f"Bearer {expected_auth}"

        assert token == expected_token, "Token format should match expected Bearer token"
        mock_ssm_client.get_parameter.assert_called_once_with(
            Name="/authru/tokens/test-api", WithDecryption=True
        )

    def test_get_auth_header_bearer_cached(self, mock_ssm_client):
        """Test bearer token caching.

        Verifies that:
        - First call retrieves token from AWS Parameter Store
        - Subsequent calls use cached value without hitting AWS
        - Both calls return identical tokens
        - SSM client is only invoked once
        """
        auth_service = AuthService()
        auth_service.ssm_client = mock_ssm_client
        config = AuthenticationConfig(
            scheme=AuthenticationScheme.BEARER,
            parameter_name="/authru/tokens/test-api"
        )

        # First call - should hit AWS Parameter Store
        token1 = auth_service.get_auth_header(config)

        # Second call - should use cache
        token2 = auth_service.get_auth_header(config)

        assert token1 == token2, "Cached token should match original token"
        assert mock_ssm_client.get_parameter.call_count == 1, (
            "SSM should only be called once due to caching"
        )

    def test_get_auth_header_bearer_parameter_not_found(self):
        """Test bearer token retrieval when parameter doesn't exist.

        Verifies that:
        - AWS ParameterNotFound error is caught
        - AuthenticationError is raised with appropriate context
        """
        with patch("boto3.client") as mock_client:
            mock_ssm = Mock()
            mock_ssm.get_parameter.side_effect = ClientError(
                error_response={"Error": {"Code": "ParameterNotFound"}},
                operation_name="GetParameter",
            )
            mock_client.return_value = mock_ssm

            auth_service = AuthService()

            with pytest.raises(
                AuthenticationError,
                match="Failed to retrieve parameter"
            ):
                auth_service.get_bearer_header("/nonexistent/parameter")

    def test_get_bearer_token_access_denied(self):
        """Test bearer token retrieval with access denied.

        Verifies that:
        - AWS AccessDenied error is caught
        - AuthenticationError is raised with appropriate context
        - Error provides meaningful feedback for IAM permission issues
        """
        with patch("boto3.client") as mock_client:
            mock_ssm = Mock()
            mock_ssm.get_parameter.side_effect = ClientError(
                error_response={"Error": {"Code": "AccessDenied"}},
                operation_name="GetParameter",
            )
            mock_client.return_value = mock_ssm

            auth_service = AuthService()

            with pytest.raises(
                AuthenticationError,
                match="Failed to retrieve parameter"
            ):
                auth_service.get_bearer_header("/authru/tokens/test-api")

    def test_get_basic_auth_credentials_invalid_format(self):
        """Test basic auth credentials retrieval with invalid credential format.

        Verifies that:
        - Credentials without ':' separator are rejected
        - AuthenticationError is raised with clear format message
        - Expected format is communicated in error message
        """
        with patch("boto3.client") as mock_client:
            mock_ssm = Mock()
            mock_ssm.get_parameter.return_value = {
                "Parameter": {"Value": "invalid-format-no-colon"}
            }
            mock_client.return_value = mock_ssm

            auth_service = AuthService()

            with pytest.raises(
                AuthenticationError,
                match="Invalid credential format"
            ):
                auth_service.get_basic_auth_header("/authru/tokens/test-api")

    def test_clear_cache(self, mock_ssm_client):
        """Test cache clearing functionality.

        Verifies that:
        - Cache is populated after token retrieval
        - clear_cache() removes all cached tokens
        - Cached token count returns to zero after clearing
        """
        auth_service = AuthService()
        auth_service.ssm_client = mock_ssm_client

        # Add something to cache
        auth_service.get_basic_auth_header("/authru/tokens/test-api")
        assert auth_service.get_cached_header_count() == 1, (
            "Cache should contain one token"
        )

        # Clear cache
        auth_service.clear_cache()
        assert auth_service.get_cached_header_count() == 0, (
            "Cache should be empty after clearing"
        )

    def test_get_cached_header_count(self, mock_ssm_client):
        """Test cached header count functionality.

        Verifies that:
        - Initial cache is empty
        - Count increments correctly as headers are added
        - Multiple different parameters are cached separately
        """
        auth_service = AuthService()
        auth_service.ssm_client = mock_ssm_client

        assert auth_service.get_cached_header_count() == 0, (
            "Initial cache should be empty"
        )

        # Add first header to cache
        auth_service.get_basic_auth_header("/authru/tokens/api1")
        assert auth_service.get_cached_header_count() == 1, (
            "Cache should contain one header after first retrieval"
        )

        # Mock different parameter for second header
        mock_ssm_client.get_parameter.return_value = {
            "Parameter": {"Value": "user2:pass2"}
        }
        auth_service.get_basic_auth_header("/authru/tokens/api2")
        assert auth_service.get_cached_header_count() == 2, (
            "Cache should contain two headers after second retrieval"
        )

    def test_get_basic_auth_credentials_with_colon_in_password(self, mock_ssm_client):
        """Test basic auth credentials creation when password contains colon.

        This is an important edge case since the credentials format is
        'username:password', and passwords may legitimately contain colons.
        The split operation should only split on the first colon.

        Verifies that:
        - Credentials with multiple colons are parsed correctly
        - Only the first colon is used as the username/password separator
        - Resulting Basic auth header is properly formatted
        """
        mock_ssm_client.get_parameter.return_value = {
            "Parameter": {"Value": "user:pass:with:colons"}
        }

        auth_service = AuthService()
        auth_service.ssm_client = mock_ssm_client

        token = auth_service.get_basic_auth_header("/authru/tokens/test-api")

        expected_auth = base64.b64encode(b"user:pass:with:colons").decode("ascii")
        expected_token = f"Basic {expected_auth}"

        assert token == expected_token, (
            "Token should correctly handle colons in password"
        )
