"""Unit tests for MFA secret encryption security (CWE-311 fix)."""

from unittest.mock import MagicMock, patch
import pytest
from cryptography.fernet import Fernet

from app.models.user import User


@pytest.fixture
def user():
    """Create a test user."""
    user = User()
    user.id = "test-user-id"
    return user


@pytest.fixture
def valid_encryption_key():
    """Generate a valid Fernet encryption key."""
    return Fernet.generate_key().decode()


class TestMFASecretEncryptionSecurity:
    """Tests for MFA secret encryption security checks."""

    def test_mfa_secret_getter_no_value_returns_none(self, user):
        """Getting MFA secret when none is set should return None."""
        user._mfa_secret_encrypted = None
        assert user.mfa_secret is None

    @patch("app.models.user.get_settings")
    def test_mfa_secret_getter_production_no_key_raises(self, mock_settings, user):
        """In production, accessing MFA secret without encryption key should raise."""
        mock_settings.return_value = MagicMock(
            credential_encryption_key=None,
            environment="production",
        )
        user._mfa_secret_encrypted = "some-secret"

        with pytest.raises(RuntimeError, match="encryption key in production"):
            _ = user.mfa_secret

    @patch("app.models.user.get_settings")
    def test_mfa_secret_getter_prod_alias_no_key_raises(self, mock_settings, user):
        """In prod (alias), accessing MFA secret without encryption key should raise."""
        mock_settings.return_value = MagicMock(
            credential_encryption_key=None,
            environment="prod",
        )
        user._mfa_secret_encrypted = "some-secret"

        with pytest.raises(RuntimeError, match="encryption key in production"):
            _ = user.mfa_secret

    @patch("app.models.user.get_settings")
    @patch("app.models.user.logger")
    def test_mfa_secret_getter_development_no_key_warns(
        self, mock_logger, mock_settings, user
    ):
        """In development, accessing MFA secret without key should warn and return value."""
        mock_settings.return_value = MagicMock(
            credential_encryption_key=None,
            environment="development",
        )
        user._mfa_secret_encrypted = "plaintext-secret"

        result = user.mfa_secret

        assert result == "plaintext-secret"
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args
        assert call_args[0][0] == "mfa_secret_unencrypted_access"

    @patch("app.models.user.get_settings")
    def test_mfa_secret_getter_with_valid_key_decrypts(
        self, mock_settings, user, valid_encryption_key
    ):
        """With valid key, getter should decrypt the secret."""
        mock_settings.return_value = MagicMock(
            credential_encryption_key=MagicMock(
                get_secret_value=lambda: valid_encryption_key
            ),
            environment="production",
        )

        # Encrypt a secret first
        fernet = Fernet(valid_encryption_key.encode())
        encrypted = fernet.encrypt(b"my-totp-secret").decode()
        user._mfa_secret_encrypted = encrypted

        result = user.mfa_secret

        assert result == "my-totp-secret"

    @patch("app.models.user.get_settings")
    def test_mfa_secret_getter_decryption_fails_production_raises(
        self, mock_settings, user, valid_encryption_key
    ):
        """In production, decryption failure should raise, not fall back to plaintext."""
        mock_settings.return_value = MagicMock(
            credential_encryption_key=MagicMock(
                get_secret_value=lambda: valid_encryption_key
            ),
            environment="production",
        )
        # Store garbage that can't be decrypted
        user._mfa_secret_encrypted = "not-a-valid-encrypted-value"

        with pytest.raises(RuntimeError, match="decryption failed in production"):
            _ = user.mfa_secret

    @patch("app.models.user.get_settings")
    @patch("app.models.user.logger")
    def test_mfa_secret_getter_decryption_fails_development_warns(
        self, mock_logger, mock_settings, user, valid_encryption_key
    ):
        """In development, decryption failure should warn and return plaintext."""
        mock_settings.return_value = MagicMock(
            credential_encryption_key=MagicMock(
                get_secret_value=lambda: valid_encryption_key
            ),
            environment="development",
        )
        # Store value that can't be decrypted (legacy plaintext)
        user._mfa_secret_encrypted = "legacy-plaintext-secret"

        result = user.mfa_secret

        assert result == "legacy-plaintext-secret"
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args
        assert call_args[0][0] == "mfa_secret_decryption_failed"


class TestMFASecretSetterSecurity:
    """Tests for MFA secret setter security checks."""

    def test_mfa_secret_setter_none_clears_value(self, user):
        """Setting MFA secret to None should clear it."""
        user._mfa_secret_encrypted = "some-value"
        user.mfa_secret = None
        assert user._mfa_secret_encrypted is None

    @patch("app.models.user.get_settings")
    def test_mfa_secret_setter_production_no_key_raises(self, mock_settings, user):
        """In production, storing MFA secret without encryption key should raise."""
        mock_settings.return_value = MagicMock(
            credential_encryption_key=None,
            environment="production",
        )

        with pytest.raises(RuntimeError, match="encryption key in production"):
            user.mfa_secret = "new-totp-secret"

    @patch("app.models.user.get_settings")
    def test_mfa_secret_setter_prod_alias_no_key_raises(self, mock_settings, user):
        """In prod (alias), storing MFA secret without encryption key should raise."""
        mock_settings.return_value = MagicMock(
            credential_encryption_key=None,
            environment="prod",
        )

        with pytest.raises(RuntimeError, match="encryption key in production"):
            user.mfa_secret = "new-totp-secret"

    @patch("app.models.user.get_settings")
    @patch("app.models.user.logger")
    def test_mfa_secret_setter_development_no_key_warns(
        self, mock_logger, mock_settings, user
    ):
        """In development, storing MFA secret without key should warn and store plaintext."""
        mock_settings.return_value = MagicMock(
            credential_encryption_key=None,
            environment="development",
        )

        user.mfa_secret = "new-secret"

        assert user._mfa_secret_encrypted == "new-secret"
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args
        assert call_args[0][0] == "mfa_secret_storing_unencrypted"

    @patch("app.models.user.get_settings")
    def test_mfa_secret_setter_with_valid_key_encrypts(
        self, mock_settings, user, valid_encryption_key
    ):
        """With valid key, setter should encrypt the secret."""
        mock_settings.return_value = MagicMock(
            credential_encryption_key=MagicMock(
                get_secret_value=lambda: valid_encryption_key
            ),
            environment="production",
        )

        user.mfa_secret = "my-totp-secret"

        # Verify it's encrypted (not plaintext)
        assert user._mfa_secret_encrypted != "my-totp-secret"
        # Verify we can decrypt it
        fernet = Fernet(valid_encryption_key.encode())
        decrypted = fernet.decrypt(user._mfa_secret_encrypted.encode()).decode()
        assert decrypted == "my-totp-secret"


class TestMFASecretRoundtrip:
    """Tests for MFA secret encryption/decryption roundtrip."""

    @patch("app.models.user.get_settings")
    def test_roundtrip_encryption_decryption(
        self, mock_settings, user, valid_encryption_key
    ):
        """Setting and getting MFA secret should preserve the value."""
        mock_settings.return_value = MagicMock(
            credential_encryption_key=MagicMock(
                get_secret_value=lambda: valid_encryption_key
            ),
            environment="production",
        )

        original_secret = "JBSWY3DPEHPK3PXP"  # Standard TOTP secret format
        user.mfa_secret = original_secret
        retrieved_secret = user.mfa_secret

        assert retrieved_secret == original_secret

    @patch("app.models.user.get_settings")
    def test_staging_environment_works_with_key(
        self, mock_settings, user, valid_encryption_key
    ):
        """Staging environment should work normally with encryption key."""
        mock_settings.return_value = MagicMock(
            credential_encryption_key=MagicMock(
                get_secret_value=lambda: valid_encryption_key
            ),
            environment="staging",
        )

        user.mfa_secret = "staging-secret"
        assert user.mfa_secret == "staging-secret"

    @patch("app.models.user.get_settings")
    def test_test_environment_works_without_key(self, mock_settings, user):
        """Test environment should work without encryption key (convenience)."""
        mock_settings.return_value = MagicMock(
            credential_encryption_key=None,
            environment="test",
        )

        user.mfa_secret = "test-secret"
        assert user.mfa_secret == "test-secret"
