"""Unit tests for CORS handler."""

import pytest

from src.utils.cors_handler import CORSHandler
from src.config.models import SecurityConfig


class TestCORSHandler:
    """Test cases for CORSHandler class."""

    def test_validate_origin_cors_disabled(self):
        """Test origin validation when CORS is disabled."""
        security_config = SecurityConfig(allowed_origins=[], cors_enabled=False)
        cors_handler = CORSHandler(security_config)

        # Should allow any origin when CORS is disabled
        assert cors_handler.validate_origin("https://evil.com") is True
        assert cors_handler.validate_origin(None) is True

    def test_validate_origin_no_origin_header(self):
        """Test origin validation with no origin header."""
        security_config = SecurityConfig(
            allowed_origins=["https://example.com"], cors_enabled=True
        )
        cors_handler = CORSHandler(security_config)

        # Should allow requests with no origin (same-origin or non-browser)
        assert cors_handler.validate_origin(None) is True

    def test_validate_origin_explicit_match(self):
        """Test origin validation with explicit match."""
        security_config = SecurityConfig(
            allowed_origins=["https://example.com", "https://app.example.com"],
            cors_enabled=True,
        )
        cors_handler = CORSHandler(security_config)

        assert cors_handler.validate_origin("https://example.com") is True
        assert cors_handler.validate_origin("https://app.example.com") is True
        assert cors_handler.validate_origin("https://evil.com") is False

    def test_validate_origin_wildcard(self):
        """Test origin validation with wildcard."""
        security_config = SecurityConfig(allowed_origins=["*"], cors_enabled=True)
        cors_handler = CORSHandler(security_config)

        assert cors_handler.validate_origin("https://example.com") is True
        assert cors_handler.validate_origin("https://evil.com") is True
        assert cors_handler.validate_origin("http://localhost:3000") is True

    def test_validate_origin_subdomain_wildcard(self):
        """Test origin validation with subdomain wildcard."""
        security_config = SecurityConfig(
            allowed_origins=["*.example.com"], cors_enabled=True
        )
        cors_handler = CORSHandler(security_config)

        assert cors_handler.validate_origin("https://app.example.com") is True
        assert cors_handler.validate_origin("https://api.example.com") is True
        assert (
            cors_handler.validate_origin("https://example.com") is True
        )  # Root domain
        assert cors_handler.validate_origin("https://evil.com") is False
        assert cors_handler.validate_origin("https://fakeexample.com") is False

    def test_get_cors_headers_cors_disabled(self):
        """Test CORS headers when CORS is disabled."""
        security_config = SecurityConfig(allowed_origins=[], cors_enabled=False)
        cors_handler = CORSHandler(security_config)

        headers = cors_handler.get_cors_headers("https://example.com")
        assert headers == {}

    def test_get_cors_headers_valid_origin(self):
        """Test CORS headers with valid origin."""
        security_config = SecurityConfig(
            allowed_origins=["https://example.com"],
            cors_enabled=True,
            allow_credentials=True,
        )
        cors_handler = CORSHandler(security_config)

        headers = cors_handler.get_cors_headers("https://example.com")

        assert headers["Access-Control-Allow-Origin"] == "https://example.com"
        assert (
            headers["Access-Control-Allow-Methods"]
            == "GET, POST, PUT, DELETE, PATCH, OPTIONS"
        )
        assert "Content-Type" in headers["Access-Control-Allow-Headers"]
        assert headers["Access-Control-Allow-Credentials"] == "true"
        assert headers["Access-Control-Max-Age"] == "86400"

    def test_get_cors_headers_no_credentials(self):
        """Test CORS headers without credentials."""
        security_config = SecurityConfig(
            allowed_origins=["https://example.com"],
            cors_enabled=True,
            allow_credentials=False,
        )
        cors_handler = CORSHandler(security_config)

        headers = cors_handler.get_cors_headers("https://example.com")

        assert "Access-Control-Allow-Credentials" not in headers

    def test_get_cors_headers_wildcard_origin(self):
        """Test CORS headers with wildcard origin."""
        security_config = SecurityConfig(allowed_origins=["*"], cors_enabled=True)
        cors_handler = CORSHandler(security_config)

        headers = cors_handler.get_cors_headers(None)
        assert headers["Access-Control-Allow-Origin"] == "*"

    def test_handle_preflight_valid_origin(self):
        """Test preflight handling with valid origin."""
        security_config = SecurityConfig(
            allowed_origins=["https://example.com"], cors_enabled=True
        )
        cors_handler = CORSHandler(security_config)

        response = cors_handler.handle_preflight("https://example.com")

        assert response.status_code == 200
        assert (
            response.headers["Access-Control-Allow-Origin"] == "https://example.com"
        )
        assert "CORS preflight successful" in response.body

    def test_handle_preflight_invalid_origin(self):
        """Test preflight handling with invalid origin."""
        security_config = SecurityConfig(
            allowed_origins=["https://example.com"], cors_enabled=True
        )
        cors_handler = CORSHandler(security_config)

        response = cors_handler.handle_preflight("https://evil.com")

        assert response.status_code == 403
        assert "Origin not allowed" in response.body
