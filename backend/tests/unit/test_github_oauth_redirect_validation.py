"""Tests for GitHub OAuth redirect URI validation (CWE-601 fix).

This test verifies that the open redirect vulnerability is fixed by
ensuring only whitelisted redirect URIs are accepted.
"""

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

import app.api.routes.github_oauth as oauth_module
from app.api.routes.github_oauth import validate_redirect_uri


class TestRedirectUriValidation:
    """Test cases for redirect URI validation."""

    def test_valid_production_uri_accepted(self, monkeypatch):
        """Valid production URI should be accepted."""
        mock_settings = MagicMock()
        mock_settings.environment = "production"
        monkeypatch.setattr(oauth_module, "settings", mock_settings)

        # Should not raise
        result = validate_redirect_uri("https://app.a13e.com/auth/callback")
        assert result is True

    def test_valid_staging_uri_accepted(self, monkeypatch):
        """Valid staging URI should be accepted."""
        mock_settings = MagicMock()
        mock_settings.environment = "staging"
        monkeypatch.setattr(oauth_module, "settings", mock_settings)

        result = validate_redirect_uri("https://staging.a13e.com/auth/callback")
        assert result is True

    def test_staging_allows_development_uris(self, monkeypatch):
        """Staging environment should also accept development URIs for testing."""
        mock_settings = MagicMock()
        mock_settings.environment = "staging"
        monkeypatch.setattr(oauth_module, "settings", mock_settings)

        result = validate_redirect_uri("http://localhost:5173/auth/callback")
        assert result is True

    def test_valid_development_uri_accepted(self, monkeypatch):
        """Valid development URI should be accepted."""
        mock_settings = MagicMock()
        mock_settings.environment = "development"
        monkeypatch.setattr(oauth_module, "settings", mock_settings)

        result = validate_redirect_uri("http://localhost:5173/auth/callback")
        assert result is True

    def test_valid_test_uri_accepted(self, monkeypatch):
        """Valid test URI should be accepted."""
        mock_settings = MagicMock()
        mock_settings.environment = "test"
        monkeypatch.setattr(oauth_module, "settings", mock_settings)

        result = validate_redirect_uri("http://testserver/auth/callback")
        assert result is True

    def test_attacker_uri_rejected(self, monkeypatch):
        """Attacker-controlled URI should be rejected."""
        mock_settings = MagicMock()
        mock_settings.environment = "production"
        monkeypatch.setattr(oauth_module, "settings", mock_settings)

        with pytest.raises(HTTPException) as exc_info:
            validate_redirect_uri("https://attacker.com/steal-tokens")

        assert exc_info.value.status_code == 400
        assert "Invalid redirect_uri" in exc_info.value.detail

    def test_similar_domain_rejected(self, monkeypatch):
        """Similar-looking domain should be rejected (typosquatting prevention)."""
        mock_settings = MagicMock()
        mock_settings.environment = "production"
        monkeypatch.setattr(oauth_module, "settings", mock_settings)

        malicious_uris = [
            "https://app.a13e.com.attacker.com/auth/callback",
            "https://appa13e.com/auth/callback",
            "https://app-a13e.com/auth/callback",
            "https://app.a13e.co/auth/callback",
            "https://app.a13e.com:8080/auth/callback",
            "https://app.a13e.com/auth/callback?next=https://attacker.com",
        ]

        for uri in malicious_uris:
            with pytest.raises(HTTPException) as exc_info:
                validate_redirect_uri(uri)
            assert exc_info.value.status_code == 400

    def test_path_traversal_rejected(self, monkeypatch):
        """Path traversal attempts should be rejected."""
        mock_settings = MagicMock()
        mock_settings.environment = "production"
        monkeypatch.setattr(oauth_module, "settings", mock_settings)

        with pytest.raises(HTTPException):
            validate_redirect_uri(
                "https://app.a13e.com/auth/callback/../../../attacker"
            )

    def test_localhost_rejected_in_production(self, monkeypatch):
        """Localhost URIs should be rejected in production."""
        mock_settings = MagicMock()
        mock_settings.environment = "production"
        monkeypatch.setattr(oauth_module, "settings", mock_settings)

        with pytest.raises(HTTPException):
            validate_redirect_uri("http://localhost:5173/auth/callback")

    def test_http_rejected_for_production_domain(self, monkeypatch):
        """HTTP (non-HTTPS) should be rejected for production domain."""
        mock_settings = MagicMock()
        mock_settings.environment = "production"
        monkeypatch.setattr(oauth_module, "settings", mock_settings)

        with pytest.raises(HTTPException):
            validate_redirect_uri("http://app.a13e.com/auth/callback")

    def test_exact_match_required(self, monkeypatch):
        """URI must exactly match - partial matches rejected."""
        mock_settings = MagicMock()
        mock_settings.environment = "production"
        monkeypatch.setattr(oauth_module, "settings", mock_settings)

        # Extra path segment
        with pytest.raises(HTTPException):
            validate_redirect_uri("https://app.a13e.com/auth/callback/extra")

        # Missing path segment
        with pytest.raises(HTTPException):
            validate_redirect_uri("https://app.a13e.com/auth")

        # Different path
        with pytest.raises(HTTPException):
            validate_redirect_uri("https://app.a13e.com/login/callback")

    def test_environment_alias_prod(self, monkeypatch):
        """'prod' should be treated as 'production'."""
        mock_settings = MagicMock()
        mock_settings.environment = "prod"
        monkeypatch.setattr(oauth_module, "settings", mock_settings)

        result = validate_redirect_uri("https://app.a13e.com/auth/callback")
        assert result is True

    def test_environment_alias_dev(self, monkeypatch):
        """'dev' should be treated as 'development'."""
        mock_settings = MagicMock()
        mock_settings.environment = "dev"
        monkeypatch.setattr(oauth_module, "settings", mock_settings)

        result = validate_redirect_uri("http://localhost:5173/auth/callback")
        assert result is True
