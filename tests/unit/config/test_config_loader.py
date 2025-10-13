"""Unit tests for configuration loader.

This module contains comprehensive tests for the ConfigLoader class,
covering both local file and S3-based configuration loading scenarios.
"""

import json
import logging
from unittest.mock import MagicMock, mock_open, patch

import pytest
from botocore.exceptions import ClientError

from src.config.config_loader import ConfigLoader, ConfigurationError
from src.config.models import ProxyConfig, AuthenticationScheme


# Test constants
DEFAULT_CONFIG_PATH = "/config/routes.json"
TEST_CONFIG_PATH = "/test/config.json"
NONEXISTENT_CONFIG_PATH = "/nonexistent/config.json"
TEST_S3_BUCKET = "test-bucket"
TEST_S3_KEY = "config/routes.json"
TEST_ROUTE_NAME = "test-api"
TEST_PATH_PATTERN = "/api/v1/*"
TEST_TARGET_URL = "https://api.example.com"
TEST_AUTH_TYPE = AuthenticationScheme.BEARER
TEST_AUTH_PARAM = "/authru/tokens/test-api"
TEST_TIMEOUT = 30000
TEST_RETRIES = 3
TEST_LOG_LEVEL = "INFO"

# Policy validation test values
NEGATIVE_TIMEOUT = -1000
ZERO_TIMEOUT = 0
EXCESSIVE_TIMEOUT = 400000
NEGATIVE_RETRIES = -1
EXCESSIVE_RETRIES = 11
VALID_TIMEOUT = 30000
VALID_RETRIES = 3
ZERO_RETRIES = 0


class TestConfigLoader:
    """Test cases for ConfigLoader class.
    
    Tests cover successful configuration loading, error handling,
    validation, and edge cases for local file-based configuration.
    """

    def test_load_config_success(self, sample_config_json):
        """Test successful configuration loading from local file.
        
        Verifies that a valid JSON configuration file is correctly
        parsed into a ProxyConfig object with all expected attributes.
        """
        with patch("builtins.open", mock_open(read_data=sample_config_json)):
            loader = ConfigLoader(config_path=TEST_CONFIG_PATH)
            config = loader.load_config()

            # Verify configuration structure
            assert isinstance(config, ProxyConfig)
            assert len(config.routes) == 1
            
            # Verify route configuration
            route = config.routes[0]
            assert route.name == TEST_ROUTE_NAME
            assert route.path_pattern == TEST_PATH_PATTERN
            assert route.target_base_url == TEST_TARGET_URL
            assert route.authentication.scheme == TEST_AUTH_TYPE
            assert route.authentication.parameter_name == TEST_AUTH_PARAM
            assert route.policies.timeout == TEST_TIMEOUT
            assert route.policies.retries == TEST_RETRIES
            
            # Verify security configuration
            assert config.security.cors_enabled is True
            assert config.security.allowed_origins == ["https://example.com"]
            
            # Verify monitoring configuration
            assert config.monitoring.log_level == TEST_LOG_LEVEL

    def test_load_config_file_not_found(self):
        """Test configuration loading when file doesn't exist.
        
        Ensures that a ConfigurationError is raised with an appropriate
        error message when the specified configuration file is not found.
        """
        with patch("builtins.open", side_effect=FileNotFoundError):
            loader = ConfigLoader(config_path=NONEXISTENT_CONFIG_PATH)

            with pytest.raises(
                ConfigurationError, match=f"Configuration file not found: {NONEXISTENT_CONFIG_PATH}"
            ):
                loader.load_config()

    def test_load_config_empty_file(self):
        """Test configuration loading with empty file.
        
        Verifies that a ConfigurationError is raised when attempting
        to load an empty configuration file.
        """
        with patch("builtins.open", mock_open(read_data="")):
            loader = ConfigLoader(config_path=TEST_CONFIG_PATH)
            with pytest.raises(ConfigurationError, match="Invalid JSON"):
                loader.load_config()

    def test_load_config_invalid_json(self):
        """Test configuration loading with invalid JSON.
        
        Ensures that a ConfigurationError is raised with an appropriate
        error message when the configuration file contains invalid JSON.
        """
        invalid_json = '{"routes": [invalid json}'

        with patch("builtins.open", mock_open(read_data=invalid_json)):
            loader = ConfigLoader(config_path=TEST_CONFIG_PATH)

            with pytest.raises(ConfigurationError, match="Invalid JSON in configuration file"):
                loader.load_config()

    def test_parse_config_missing_required_field(self, sample_config_json):
        """Test configuration parsing with missing required fields.
        
        Verifies that a ConfigurationError is raised when a required
        field (pathPattern) is missing from the route configuration.
        """
        config_data = json.loads(sample_config_json)
        config_data["routes"][0].pop("pathPattern")
        config_data = json.dumps(config_data)
        with patch("builtins.open", mock_open(read_data=config_data)):
            loader = ConfigLoader(config_path=TEST_CONFIG_PATH)

            with pytest.raises(
                ConfigurationError, match="Route path pattern cannot be empty"
            ):
                loader.load_config()

    def test_validate_config_no_routes(self, sample_config_json):
        """Test configuration validation with no routes.
        
        Ensures that a ConfigurationError is raised when the configuration
        contains an empty routes array, as at least one route is required.
        """
        config_data = json.loads(sample_config_json)
        config_data["routes"] = []
        config_data = json.dumps(config_data)
        with patch("builtins.open", mock_open(read_data=config_data)):
            loader = ConfigLoader(config_path=TEST_CONFIG_PATH)
            with pytest.raises(
                ConfigurationError, match="At least one route must be configured"
            ):
                loader.load_config()

    def test_validate_config_cors_no_origins(self, sample_config_json):
        """Test configuration validation with CORS enabled but no origins.
        
        Verifies that a ConfigurationError is raised when CORS is enabled
        but no allowed origins are specified in the configuration.
        """
        config_data = json.loads(sample_config_json)
        config_data["security"]["allowedOrigins"] = []
        config_data = json.dumps(config_data)
        with patch("builtins.open", mock_open(read_data=config_data)):
            loader = ConfigLoader(config_path=TEST_CONFIG_PATH)
            with pytest.raises(
                ConfigurationError, match="CORS is enabled but no allowed origins specified"
            ):
                loader.load_config()

    def test_default_config_path_from_env(self):
        """Test default configuration path from environment variable.
        
        Verifies that the ConfigLoader correctly reads the configuration
        path from the AUTHRU_CONFIG_PATH environment variable.
        """
        custom_path = "/custom/path.json"
        with patch.dict("os.environ", {"AUTHRU_CONFIG_PATH": custom_path}):
            loader = ConfigLoader()
            assert loader.config_path == custom_path

    def test_default_config_path_fallback(self):
        """Test default configuration path fallback.
        
        Ensures that the ConfigLoader falls back to the default path
        /config/routes.json when no environment variable is set.
        """
        with patch.dict("os.environ", {}, clear=True):
            loader = ConfigLoader()
            assert loader.config_path == DEFAULT_CONFIG_PATH

    @pytest.mark.parametrize(
        "invalid_timeout",
        [NEGATIVE_TIMEOUT, ZERO_TIMEOUT, EXCESSIVE_TIMEOUT, "invalid_type"]
    )
    def test_policy_config_validation_invalid_timeout(
            self, sample_config_data_dict, invalid_timeout
        ):
        """Test policy configuration validation with negative timeout.
        
        Verifies that a ConfigurationError is raised when the timeout
        value is negative, as it must be between 0 and 300000.
        """
        sample_config_data_dict["routes"][0]["policies"]["timeout"] = invalid_timeout
        config_data = json.dumps(sample_config_data_dict)
        with patch("builtins.open", mock_open(read_data=config_data)):
            loader = ConfigLoader(config_path=TEST_CONFIG_PATH)
            with pytest.raises(
                ConfigurationError, match="Policy timeout must be an integer between 0 and 300000"
            ):
                loader.load_config()

    @pytest.mark.parametrize(
        "invalid_retries",
        [NEGATIVE_RETRIES, EXCESSIVE_RETRIES, "invalid_type"]
    )
    def test_policy_config_validation_invalid_retries(
            self, sample_config_data_dict, invalid_retries
        ):
        """Test policy configuration validation with negative retries.
        
        Ensures that a ConfigurationError is raised when the retries
        value is negative, as it must be between 0 and 10.
        """
        sample_config_data_dict["routes"][0]["policies"]["retries"] = invalid_retries
        config_data = json.dumps(sample_config_data_dict)
        with patch("builtins.open", mock_open(read_data=config_data)):
            loader = ConfigLoader("/test/config.json")
            with pytest.raises(
                ConfigurationError, match="Policy retries must be an integer between 0 and 10"
            ):
                loader.load_config()

    def test_policy_config_validation_valid_values(self, sample_config_data_dict):
        """Test policy configuration validation with valid values.
        
        Verifies that valid timeout and retries values are correctly
        parsed and stored in the configuration object.
        """
        sample_config_data_dict["routes"][0]["policies"]["timeout"] = VALID_TIMEOUT
        sample_config_data_dict["routes"][0]["policies"]["retries"] = VALID_RETRIES
        config_data = json.dumps(sample_config_data_dict)
        with patch("builtins.open", mock_open(read_data=config_data)):
            loader = ConfigLoader(config_path=TEST_CONFIG_PATH)
            config = loader.load_config()
            assert config.routes[0].policies.timeout == VALID_TIMEOUT
            assert config.routes[0].policies.retries == VALID_RETRIES

    def test_policy_config_validation_zero_retries(self, sample_config_data_dict):
        """Test policy configuration validation with zero retries (valid).
        
        Ensures that zero retries is considered a valid value and
        is correctly parsed in the configuration object.
        """
        sample_config_data_dict["routes"][0]["policies"]["retries"] = ZERO_RETRIES
        config_data = json.dumps(sample_config_data_dict)
        with patch("builtins.open", mock_open(read_data=config_data)):
            loader = ConfigLoader(config_path=TEST_CONFIG_PATH)
            config = loader.load_config()
            assert config.routes[0].policies.retries == ZERO_RETRIES

class TestConfigLoaderS3:
    """Test cases for S3 configuration loading.
    
    Tests cover S3-based configuration loading, fallback mechanisms,
    error handling, and integration with boto3 client.
    """
    
    def _setup_s3_environment(self, bucket: str = TEST_S3_BUCKET, key: str = TEST_S3_KEY):
        """Helper method to set up S3 environment variables.
        
        Args:
            bucket: S3 bucket name
            key: S3 key for configuration file
        """
        return patch.dict(
            "os.environ",
            {
                "AUTHRU_CONFIG_S3_BUCKET": bucket,
                "AUTHRU_CONFIG_S3_KEY": key,
            },
        )

    @patch("src.config.config_loader.boto3")
    def test_load_config_from_s3_success(self, mock_boto3, sample_config_json):
        """Test successful configuration loading from S3.
        
        Verifies that a valid configuration is correctly loaded from S3
        and parsed into a ProxyConfig object with all expected attributes.
        """
        # Setup S3 mock
        mock_s3_client = MagicMock()
        mock_boto3.client.return_value = mock_s3_client

        mock_response = {
            "Body": MagicMock(read=lambda: sample_config_json.encode("utf-8"))
        }
        mock_s3_client.get_object.return_value = mock_response

        # Create loader with S3 config
        with self._setup_s3_environment():
            loader = ConfigLoader()
            config = loader.load_config()

            # Verify
            assert isinstance(config, ProxyConfig)
            assert len(config.routes) == 1
            mock_s3_client.get_object.assert_called_once_with(
                Bucket=TEST_S3_BUCKET, Key=TEST_S3_KEY
            )

    @patch("src.config.config_loader.boto3")
    def test_load_config_from_s3_fallback_to_file(self, mock_boto3, sample_config_json):
        """Test S3 load failure falls back to local file.
        
        Ensures that when S3 loading fails (e.g., NoSuchKey error),
        the system gracefully falls back to loading from a local file.
        """
        # Setup S3 mock to fail
        mock_s3_client = MagicMock()
        mock_boto3.client.return_value = mock_s3_client
        mock_s3_client.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey"}}, "GetObject"
        )

        # Create loader with S3 config but also provide local file
        with self._setup_s3_environment():
            with patch("builtins.open", mock_open(read_data=sample_config_json)):
                loader = ConfigLoader()
                config = loader.load_config()

                # Verify fallback occurred
                assert isinstance(config, ProxyConfig)
                assert len(config.routes) == 1

    @patch("src.config.config_loader.boto3")
    def test_s3_client_initialization(self, mock_boto3):
        """Test S3 client is initialized when S3 config is provided.
        
        Verifies that the S3 client is properly initialized when
        S3 bucket and key environment variables are set.
        """
        mock_s3_client = MagicMock()
        mock_boto3.client.return_value = mock_s3_client

        with self._setup_s3_environment(key="routes.json"):
            loader = ConfigLoader()

            assert loader._s3_bucket == TEST_S3_BUCKET
            assert loader._s3_key == "routes.json"
            assert loader._s3_client is not None
            mock_boto3.client.assert_called_once_with("s3")

    def test_no_s3_client_without_config(self):
        """Test S3 client is not initialized without S3 config.
        
        Ensures that the S3 client remains None when no S3 configuration
        environment variables are provided.
        """
        with patch.dict("os.environ", {}, clear=True):
            loader = ConfigLoader()

            assert loader._s3_bucket is None
            assert loader._s3_key is None
            assert loader._s3_client is None

    @patch("src.config.config_loader.BOTO3_AVAILABLE", False)
    def test_boto3_not_available_logs_warning(self, caplog, sample_config_json):
        """Test that a warning is logged when boto3 is not available.
        
        Verifies that a warning is logged when S3 configuration is provided
        but boto3 is not available, and the system falls back to local file.
        """
        with self._setup_s3_environment(key="routes.json"):
            with patch("builtins.open", mock_open(read_data=sample_config_json)):
                # Set up logging capture
                logger = logging.getLogger("src.config.config_loader")
                old_propagate = logger.propagate
                logger.propagate = True
                caplog.set_level(logging.WARNING)
                
                loader = ConfigLoader()
                config = loader.load_config()
                
                # Restore logger settings
                logger.propagate = old_propagate
                
                # Verify the warning was logged
                warning_message = (
                    "S3 configuration provided but boto3 is not available. "
                    "Install boto3 to use S3 config source."
                )
                assert warning_message in caplog.text
                
                # Verify that config was still loaded from local file
                assert isinstance(config, ProxyConfig)
                assert len(config.routes) == 1
                assert config.routes[0].name == TEST_ROUTE_NAME

    @patch("src.config.config_loader.boto3")
    def test_s3_invalid_json(self, mock_boto3, caplog, sample_config_json):
        """Test S3 load with invalid JSON raises error.
        
        Ensures that when S3 returns invalid JSON, an error is logged
        and the system falls back to loading from a local file.
        """
        mock_s3_client = MagicMock()
        mock_boto3.client.return_value = mock_s3_client

        # Return invalid JSON
        mock_response = {"Body": MagicMock(read=lambda: b'{"invalid": json}')}
        mock_s3_client.get_object.return_value = mock_response
        error_message = (
            f"Failed to load config from S3 (bucket={TEST_S3_BUCKET}, "
            "key=routes.json), falling back to local file. Reason: Unexpected "
            "error loading from S3"
        )
        with self._setup_s3_environment(key="routes.json"):
            with patch("builtins.open", mock_open(read_data=sample_config_json)):
                loader = ConfigLoader()
                import logging

                logger = logging.getLogger("src.config.config_loader")
                old = logger.propagate
                logger.propagate = True
                caplog.set_level(logging.WARNING)
                loader.load_config()
                logger.propagate = old
                assert error_message in caplog.text

    @patch("src.config.config_loader.boto3")
    def test_s3_config_priority_over_local(self, mock_boto3, sample_config_json):
        """Test S3 configuration has priority over local file.
        
        Verifies that when both S3 and local configurations are available,
        the S3 configuration takes priority and is loaded instead of the local one.
        """
        mock_s3_client = MagicMock()
        mock_boto3.client.return_value = mock_s3_client

        # S3 returns different config
        s3_config = json.loads(sample_config_json)
        s3_config["routes"][0]["name"] = "s3-api"
        s3_json = json.dumps(s3_config)

        mock_response = {"Body": MagicMock(read=lambda: s3_json.encode("utf-8"))}
        mock_s3_client.get_object.return_value = mock_response

        # Local file has different config
        local_config = json.loads(sample_config_json)
        local_config["routes"][0]["name"] = "local-api"

        with self._setup_s3_environment(key="routes.json"):
            with patch("builtins.open", mock_open(read_data=json.dumps(local_config))):
                loader = ConfigLoader()
                config = loader.load_config()

                # Should have loaded from S3, not local
                assert config.routes[0].name == "s3-api"
                mock_s3_client.get_object.assert_called_once()
