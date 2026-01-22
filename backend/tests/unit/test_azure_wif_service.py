"""Unit tests for Azure Workload Identity Federation service.

Tests cover:
1. Cognito JWT token generation via GetOpenIdTokenForDeveloperIdentity
2. Error handling for Cognito API errors
3. Thread pool execution for asyncio compatibility
4. Azure credential creation with Cognito JWTs
5. WIF validation returning Cognito Identity ID
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Ensure the backend app is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


class TestCognitoJWTGeneration:
    """Tests for Cognito JWT token generation."""

    @pytest.mark.asyncio
    async def test_get_cognito_jwt_success(self):
        """Test successful Cognito JWT generation."""
        from app.services.azure_wif_service import get_cognito_jwt, CognitoJWTResult

        mock_response = {
            "Token": "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.test.signature",
            "IdentityId": "eu-west-2:12345678-1234-1234-1234-123456789abc",
        }

        mock_client = MagicMock()
        mock_client.get_open_id_token_for_developer_identity.return_value = (
            mock_response
        )

        with patch("boto3.client", return_value=mock_client), patch(
            "app.services.azure_wif_service.get_settings"
        ) as mock_settings:
            mock_settings.return_value.cognito_identity_pool_id = (
                "eu-west-2:pool-id-123"
            )
            mock_settings.return_value.aws_region = "eu-west-2"

            result = await get_cognito_jwt(
                cloud_account_id="test-cloud-account-123",
            )

            assert isinstance(result, CognitoJWTResult)
            assert result.token == mock_response["Token"]
            assert result.identity_id == mock_response["IdentityId"]

            # Verify correct API call
            mock_client.get_open_id_token_for_developer_identity.assert_called_once_with(
                IdentityPoolId="eu-west-2:pool-id-123",
                Logins={"a13e-azure-wif": "test-cloud-account-123"},
                TokenDuration=3600,
            )

    @pytest.mark.asyncio
    async def test_get_cognito_jwt_with_existing_identity_id(self):
        """Test Cognito JWT generation with existing Identity ID."""
        from app.services.azure_wif_service import get_cognito_jwt

        mock_response = {
            "Token": "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.test.signature",
            "IdentityId": "eu-west-2:existing-identity-123",
        }

        mock_client = MagicMock()
        mock_client.get_open_id_token_for_developer_identity.return_value = (
            mock_response
        )

        with patch("boto3.client", return_value=mock_client), patch(
            "app.services.azure_wif_service.get_settings"
        ) as mock_settings:
            mock_settings.return_value.cognito_identity_pool_id = (
                "eu-west-2:pool-id-123"
            )
            mock_settings.return_value.aws_region = "eu-west-2"

            result = await get_cognito_jwt(
                cloud_account_id="test-cloud-account-123",
                existing_identity_id="eu-west-2:existing-identity-123",
            )

            assert result.identity_id == "eu-west-2:existing-identity-123"

            # Verify IdentityId was passed
            call_args = mock_client.get_open_id_token_for_developer_identity.call_args
            assert call_args[1]["IdentityId"] == "eu-west-2:existing-identity-123"

    @pytest.mark.asyncio
    async def test_get_cognito_jwt_pool_not_configured(self):
        """Test error when Cognito Identity Pool is not configured."""
        from app.services.azure_wif_service import get_cognito_jwt, AzureWIFError

        with patch("app.services.azure_wif_service.get_settings") as mock_settings:
            mock_settings.return_value.cognito_identity_pool_id = None

            with pytest.raises(AzureWIFError) as exc_info:
                await get_cognito_jwt(cloud_account_id="test-123")

            assert "COGNITO_IDENTITY_POOL_ID" in str(exc_info.value)


class TestCognitoJWTErrorHandling:
    """Tests for Cognito JWT error handling."""

    @pytest.mark.asyncio
    async def test_get_cognito_jwt_throttling(self):
        """Test handling of TooManyRequestsException."""
        from app.services.azure_wif_service import get_cognito_jwt, AzureWIFError
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.get_open_id_token_for_developer_identity.side_effect = ClientError(
            {"Error": {"Code": "TooManyRequestsException", "Message": "Rate exceeded"}},
            "GetOpenIdTokenForDeveloperIdentity",
        )

        with patch("boto3.client", return_value=mock_client), patch(
            "app.services.azure_wif_service.get_settings"
        ) as mock_settings:
            mock_settings.return_value.cognito_identity_pool_id = (
                "eu-west-2:pool-id-123"
            )
            mock_settings.return_value.aws_region = "eu-west-2"

            with pytest.raises(AzureWIFError) as exc_info:
                await get_cognito_jwt(cloud_account_id="test-123")

            assert "TooManyRequestsException" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_cognito_jwt_resource_not_found(self):
        """Test handling of ResourceNotFoundException."""
        from app.services.azure_wif_service import get_cognito_jwt, AzureWIFError
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.get_open_id_token_for_developer_identity.side_effect = ClientError(
            {
                "Error": {
                    "Code": "ResourceNotFoundException",
                    "Message": "Identity pool not found",
                }
            },
            "GetOpenIdTokenForDeveloperIdentity",
        )

        with patch("boto3.client", return_value=mock_client), patch(
            "app.services.azure_wif_service.get_settings"
        ) as mock_settings:
            mock_settings.return_value.cognito_identity_pool_id = (
                "eu-west-2:invalid-pool"
            )
            mock_settings.return_value.aws_region = "eu-west-2"

            with pytest.raises(AzureWIFError) as exc_info:
                await get_cognito_jwt(cloud_account_id="test-123")

            assert "ResourceNotFoundException" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_cognito_jwt_not_authorized(self):
        """Test handling of NotAuthorizedException."""
        from app.services.azure_wif_service import get_cognito_jwt, AzureWIFError
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.get_open_id_token_for_developer_identity.side_effect = ClientError(
            {"Error": {"Code": "NotAuthorizedException", "Message": "Not authorized"}},
            "GetOpenIdTokenForDeveloperIdentity",
        )

        with patch("boto3.client", return_value=mock_client), patch(
            "app.services.azure_wif_service.get_settings"
        ) as mock_settings:
            mock_settings.return_value.cognito_identity_pool_id = (
                "eu-west-2:pool-id-123"
            )
            mock_settings.return_value.aws_region = "eu-west-2"

            with pytest.raises(AzureWIFError) as exc_info:
                await get_cognito_jwt(cloud_account_id="test-123")

            assert "NotAuthorizedException" in str(exc_info.value)


class TestThreadPoolExecution:
    """Tests for asyncio thread pool execution."""

    @pytest.mark.asyncio
    async def test_runs_in_thread_pool(self):
        """Test that boto3 calls run in thread pool to avoid blocking."""
        from app.services.azure_wif_service import get_cognito_jwt

        mock_response = {
            "Token": "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.test.signature",
            "IdentityId": "eu-west-2:12345678-1234-1234-1234-123456789abc",
        }

        mock_client = MagicMock()
        mock_client.get_open_id_token_for_developer_identity.return_value = (
            mock_response
        )

        with patch("boto3.client", return_value=mock_client), patch(
            "app.services.azure_wif_service.get_settings"
        ) as mock_settings, patch("asyncio.get_event_loop") as mock_loop:
            mock_settings.return_value.cognito_identity_pool_id = (
                "eu-west-2:pool-id-123"
            )
            mock_settings.return_value.aws_region = "eu-west-2"

            # Create a real coroutine that returns the mock response
            async def mock_run_in_executor(executor, func):
                return func()

            mock_loop.return_value.run_in_executor = mock_run_in_executor

            result = await get_cognito_jwt(cloud_account_id="test-123")

            # Verify the result came through
            assert result.token == mock_response["Token"]


class TestAzureCredentialWithCognitoJWT:
    """Tests for Azure credential creation with Cognito JWTs."""

    @pytest.mark.asyncio
    async def test_get_azure_credential_returns_identity_id(self):
        """Test that get_azure_credential returns Cognito Identity ID."""
        from app.services.azure_wif_service import (
            get_azure_credential,
            AzureWIFConfiguration,
            CognitoJWTResult,
        )

        mock_jwt_result = CognitoJWTResult(
            token="eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.test.signature",
            identity_id="eu-west-2:12345678-1234-1234-1234-123456789abc",
        )

        wif_config = AzureWIFConfiguration(
            tenant_id="test-tenant-id",
            client_id="test-client-id",
            subscription_id="test-subscription-id",
        )

        with patch("app.services.azure_wif_service.get_cognito_jwt") as mock_get_jwt:
            mock_get_jwt.return_value = mock_jwt_result

            credential, identity_id = await get_azure_credential(
                wif_config=wif_config,
                cloud_account_id="test-cloud-account",
            )

            assert identity_id == mock_jwt_result.identity_id
            assert credential is not None


class TestAzureWIFConfiguration:
    """Tests for Azure WIF configuration dataclass."""

    def test_from_dict_success(self):
        """Test AzureWIFConfiguration.from_dict with valid data."""
        from app.services.azure_wif_service import AzureWIFConfiguration

        data = {
            "tenant_id": "test-tenant-id",
            "client_id": "test-client-id",
            "subscription_id": "test-subscription-id",
        }

        config = AzureWIFConfiguration.from_dict(data)

        assert config.tenant_id == "test-tenant-id"
        assert config.client_id == "test-client-id"
        assert config.subscription_id == "test-subscription-id"

    def test_from_dict_missing_keys(self):
        """Test AzureWIFConfiguration.from_dict raises on missing keys."""
        from app.services.azure_wif_service import AzureWIFConfiguration

        data = {
            "tenant_id": "test-tenant-id",
            # Missing client_id and subscription_id
        }

        with pytest.raises(ValueError) as exc_info:
            AzureWIFConfiguration.from_dict(data)

        assert "Missing required keys" in str(exc_info.value)

    def test_from_dict_empty_data(self):
        """Test AzureWIFConfiguration.from_dict raises on empty data."""
        from app.services.azure_wif_service import AzureWIFConfiguration

        with pytest.raises(ValueError) as exc_info:
            AzureWIFConfiguration.from_dict({})

        assert "empty" in str(exc_info.value).lower()

    def test_from_dict_none_data(self):
        """Test AzureWIFConfiguration.from_dict raises on None data."""
        from app.services.azure_wif_service import AzureWIFConfiguration

        with pytest.raises(ValueError) as exc_info:
            AzureWIFConfiguration.from_dict(None)

        assert "empty" in str(exc_info.value).lower()

    def test_to_dict(self):
        """Test AzureWIFConfiguration.to_dict serialisation."""
        from app.services.azure_wif_service import AzureWIFConfiguration

        config = AzureWIFConfiguration(
            tenant_id="test-tenant-id",
            client_id="test-client-id",
            subscription_id="test-subscription-id",
        )

        result = config.to_dict()

        assert result == {
            "tenant_id": "test-tenant-id",
            "client_id": "test-client-id",
            "subscription_id": "test-subscription-id",
        }


class TestCognitoJWTResult:
    """Tests for CognitoJWTResult dataclass."""

    def test_dataclass_attributes(self):
        """Test CognitoJWTResult has expected attributes."""
        from app.services.azure_wif_service import CognitoJWTResult

        result = CognitoJWTResult(
            token="test-token",
            identity_id="eu-west-2:test-identity",
        )

        assert result.token == "test-token"
        assert result.identity_id == "eu-west-2:test-identity"


class TestModuleExports:
    """Tests for module exports."""

    def test_public_api_exports(self):
        """Test that all expected symbols are exported."""
        from app.services import azure_wif_service

        expected_exports = [
            "AzureWIFConfiguration",
            "AzureWIFError",
            "CognitoJWTResult",
            "get_azure_credential",
            "get_aws_sts_token",  # Deprecated but kept for backwards compatibility
            "get_cognito_jwt",
            "validate_wif_configuration",
        ]

        for export in expected_exports:
            assert hasattr(azure_wif_service, export), f"Missing export: {export}"
            assert export in azure_wif_service.__all__, f"Not in __all__: {export}"
