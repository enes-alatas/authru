"""Integration tests for the proxy handler."""

from unittest.mock import patch

from src.handlers.proxy_handler import lambda_handler
from src.services.models import ProxyResponse

class TestProxyHandlerIntegration:
    """Integration test cases for the proxy handler."""

    @patch("src.handlers.proxy_handler.proxy_service")
    def test_successful_proxy_request(
        self,
        mock_proxy_service,
        sample_lambda_event,
        sample_lambda_context,
    ):
        """Test successful proxy request flow."""
        # Setup mocks
        mock_proxy_service.forward_request.return_value = ProxyResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"data": "success"}',
        )

        # Execute
        response = lambda_handler(sample_lambda_event, sample_lambda_context)

        # Verify
        assert response["statusCode"] == 200
        assert "application/json" in response["headers"]["Content-Type"]
        assert "success" in response["body"]

        # Verify proxy service was called
        mock_proxy_service.forward_request.assert_called_once_with(sample_lambda_event)

    @patch("src.handlers.proxy_handler.proxy_service")
    def test_request_with_existing_auth(
        self,
        mock_proxy_service, 
        sample_lambda_event,
        sample_lambda_context,
    ):
        """Test request that already has authorization header."""
        # Add authorization header to event
        sample_lambda_event["headers"]["Authorization"] = "Bearer existing-token"

        # Setup mocks
        mock_proxy_service.forward_request.return_value = ProxyResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"data": "success"}',
        )

        # Execute
        response = lambda_handler(sample_lambda_event, sample_lambda_context)

        # Verify
        assert response["statusCode"] == 200

    @patch("src.handlers.proxy_handler.proxy_service")
    def test_invalid_origin_request(
        self,
        mock_proxy_service,
        sample_lambda_event,
        sample_lambda_context,
    ):
        """Test request with invalid origin."""
        # Change origin to invalid one
        sample_lambda_event["headers"]["Origin"] = "https://evil.com"

        mock_proxy_service.forward_request.return_value = ProxyResponse(
            status_code=403,
            headers={"Content-Type": "application/json"},
            body='{"error": "Origin not allowed"}',
        )

        # Execute
        response = lambda_handler(sample_lambda_event, sample_lambda_context)

        # Verify
        assert response["statusCode"] == 403
        assert "Origin not allowed" in response["body"]

