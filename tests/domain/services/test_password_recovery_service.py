import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from app.domain.services.password_recovery_service import PasswordRecoveryService
from app.domain.entities.password_recovery import PasswordRecoveryToken
from app.handlers.errors.password_recovery_exception_handler import (
    PasswordRecoveryTokenNotFoundError,
    PasswordRecoveryTokenExpiredError,
    PasswordRecoveryTokenAlreadyUsedError,
    PasswordRecoveryEmailFailedError
)


@pytest.fixture
def mock_db_port():
    """Create a mock NonRelationalDBPort"""
    mock = AsyncMock()
    mock.insert_entry = MagicMock(return_value="token_id_123")
    mock.find_entry = MagicMock(return_value={
        "token": "test-token-123",
        "user_email": "user@example.com",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
        "is_used": False
    })
    mock.delete_entry = MagicMock(return_value=1)
    mock.delete_many = MagicMock(return_value=5)
    return mock


@pytest.fixture
def password_recovery_service(mock_db_port):
    """Create PasswordRecoveryService instance with mocked dependencies"""
    with patch('app.domain.services.password_recovery_service.settings') as mock_settings:
        mock_settings.PASSWORD_RECOVERY_COLLECTION_NAME = "password_recovery"
        mock_settings.PASSWORD_RECOVERY_TOKEN_EXPIRATION = "24h"
        mock_settings.PASSWORD_RECOVERY_LINK_TEMPLATE = "http://ec2-44-217-132-156.compute-1.amazonaws.com/reset-password?token={token}"
        
        service = PasswordRecoveryService(mock_db_port)
        service.email_service = AsyncMock()
        return service


class TestPasswordRecoveryServiceRequest:
    """Test password recovery request functionality"""

    @pytest.mark.asyncio
    async def test_request_password_recovery_success(self, password_recovery_service):
        """Test successful password recovery request"""
        password_recovery_service.email_service.send_password_recovery_email = AsyncMock(return_value=True)
        
        result = await password_recovery_service.request_password_recovery(
            user_email="user@example.com"
        )
        
        assert result is True
        password_recovery_service.db_port.insert_entry.assert_called_once()
        password_recovery_service.email_service.send_password_recovery_email.assert_called_once()

    @pytest.mark.asyncio
    async def test_request_password_recovery_email_failed(self, password_recovery_service):
        """Test password recovery when email fails to send"""
        password_recovery_service.email_service.send_password_recovery_email = AsyncMock(return_value=False)
        
        with pytest.raises(PasswordRecoveryEmailFailedError):
            await password_recovery_service.request_password_recovery(
                user_email="user@example.com"
            )

    @pytest.mark.asyncio
    async def test_request_password_recovery_token_creation_failed(self, password_recovery_service):
        """Test password recovery when token creation fails"""
        password_recovery_service.db_port.insert_entry = MagicMock(return_value=None)
        
        with pytest.raises(PasswordRecoveryEmailFailedError):
            await password_recovery_service.request_password_recovery(
                user_email="user@example.com"
            )

    @pytest.mark.asyncio
    async def test_request_password_recovery_with_special_email(self, password_recovery_service):
        """Test password recovery with special email format"""
        password_recovery_service.email_service.send_password_recovery_email = AsyncMock(return_value=True)
        
        result = await password_recovery_service.request_password_recovery(
            user_email="user+tag@example.co.uk"
        )
        
        assert result is True

    @pytest.mark.asyncio
    async def test_request_password_recovery_creates_valid_token(self, password_recovery_service):
        """Test that recovery token is created with valid properties"""
        password_recovery_service.email_service.send_password_recovery_email = AsyncMock(return_value=True)
        
        await password_recovery_service.request_password_recovery(
            user_email="user@example.com"
        )
        
        # Get the token data passed to insert_entry
        call_args = password_recovery_service.db_port.insert_entry.call_args
        token_data = call_args[0][1]  # Second argument is the token data
        
        assert token_data["user_email"] == "user@example.com"
        assert "token" in token_data
        assert "expires_at" in token_data
        assert token_data["is_used"] is False

    @pytest.mark.asyncio
    async def test_request_password_recovery_sends_correct_link(self, password_recovery_service):
        """Test that recovery link is sent correctly"""
        password_recovery_service.email_service.send_password_recovery_email = AsyncMock(return_value=True)
        
        await password_recovery_service.request_password_recovery(
            user_email="user@example.com"
        )
        
        # Get the recovery link sent to email service
        call_args = password_recovery_service.email_service.send_password_recovery_email.call_args
        recovery_link = call_args[1]["recovery_link"]  # recovery_link kwarg
        
        assert "reset-password?token=" in recovery_link


class TestPasswordRecoveryServiceValidation:
    """Test password recovery token validation"""

    @pytest.mark.asyncio
    async def test_validate_recovery_token_success(self, password_recovery_service):
        """Test successful token validation"""
        email = await password_recovery_service.validate_recovery_token("test-token-123")
        
        assert email == "user@example.com"
        password_recovery_service.db_port.find_entry.assert_called_once()

    @pytest.mark.asyncio
    async def test_validate_recovery_token_not_found(self, password_recovery_service):
        """Test validation with non-existent token"""
        password_recovery_service.db_port.find_entry = MagicMock(return_value=None)
        
        with pytest.raises(PasswordRecoveryTokenNotFoundError):
            await password_recovery_service.validate_recovery_token("invalid-token")

    @pytest.mark.asyncio
    async def test_validate_recovery_token_already_used(self, password_recovery_service):
        """Test validation with already used token"""
        password_recovery_service.db_port.find_entry = MagicMock(return_value={
            "token": "used-token",
            "user_email": "user@example.com",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
            "is_used": True
        })
        
        with pytest.raises(PasswordRecoveryTokenAlreadyUsedError):
            await password_recovery_service.validate_recovery_token("used-token")

    @pytest.mark.asyncio
    async def test_validate_recovery_token_expired(self, password_recovery_service):
        """Test validation with expired token"""
        password_recovery_service.db_port.find_entry = MagicMock(return_value={
            "token": "expired-token",
            "user_email": "user@example.com",
            "expires_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            "is_used": False
        })
        
        with pytest.raises(PasswordRecoveryTokenExpiredError):
            await password_recovery_service.validate_recovery_token("expired-token")

    @pytest.mark.asyncio
    async def test_validate_recovery_token_database_error(self, password_recovery_service):
        """Test validation when database raises exception"""
        password_recovery_service.db_port.find_entry = MagicMock(side_effect=Exception("DB error"))
        
        with pytest.raises(PasswordRecoveryTokenNotFoundError):
            await password_recovery_service.validate_recovery_token("test-token")


class TestPasswordRecoveryServiceMarkUsed:
    """Test marking tokens as used"""

    @pytest.mark.asyncio
    async def test_mark_token_as_used_success(self, password_recovery_service):
        """Test successful token deletion after use"""
        result = await password_recovery_service.mark_token_as_used("test-token-123")
        
        assert result is True
        password_recovery_service.db_port.delete_entry.assert_called_once_with(
            "password_recovery",
            {"token": "test-token-123"}
        )

    @pytest.mark.asyncio
    async def test_mark_token_as_used_not_found(self, password_recovery_service):
        """Test marking non-existent token as used"""
        password_recovery_service.db_port.delete_entry = MagicMock(return_value=0)
        
        result = await password_recovery_service.mark_token_as_used("non-existent-token")
        
        assert result is False

    @pytest.mark.asyncio
    async def test_mark_token_as_used_database_error(self, password_recovery_service):
        """Test error when deleting token"""
        password_recovery_service.db_port.delete_entry = MagicMock(side_effect=Exception("DB error"))
        
        result = await password_recovery_service.mark_token_as_used("test-token-123")
        
        assert result is False


class TestPasswordRecoveryServiceCleanup:
    """Test cleanup of expired tokens"""

    @pytest.mark.asyncio
    async def test_cleanup_expired_tokens_success(self, password_recovery_service):
        """Test successful cleanup of expired tokens"""
        result = await password_recovery_service.cleanup_expired_tokens()
        
        assert result == 5
        password_recovery_service.db_port.delete_many.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_expired_tokens_no_expired(self, password_recovery_service):
        """Test cleanup when no expired tokens exist"""
        password_recovery_service.db_port.delete_many = MagicMock(return_value=0)
        
        result = await password_recovery_service.cleanup_expired_tokens()
        
        assert result == 0

    @pytest.mark.asyncio
    async def test_cleanup_expired_tokens_database_error(self, password_recovery_service):
        """Test cleanup with database error"""
        password_recovery_service.db_port.delete_many = MagicMock(side_effect=Exception("DB error"))
        
        result = await password_recovery_service.cleanup_expired_tokens()
        
        assert result == 0

    @pytest.mark.asyncio
    async def test_cleanup_deletes_expired_and_used_tokens(self, password_recovery_service):
        """Test that cleanup deletes both expired and used tokens"""
        await password_recovery_service.cleanup_expired_tokens()
        
        call_args = password_recovery_service.db_port.delete_many.call_args
        query = call_args[0][1]  # Second argument is the query
        
        # Verify the query includes both expired and used conditions
        assert "$or" in query
        conditions = query["$or"]
        assert len(conditions) == 2
        assert any("expires_at" in c for c in conditions)
        assert any("is_used" in c for c in conditions)


class TestPasswordRecoveryServiceEdgeCases:
    """Test edge cases and error scenarios"""

    @pytest.mark.asyncio
    async def test_request_recovery_with_generic_exception(self, password_recovery_service):
        """Test request_password_recovery with unexpected exception"""
        password_recovery_service.db_port.insert_entry = MagicMock(side_effect=RuntimeError("Unexpected error"))
        
        with pytest.raises(PasswordRecoveryEmailFailedError):
            await password_recovery_service.request_password_recovery("user@example.com")

    @pytest.mark.asyncio
    async def test_validate_token_with_missing_fields(self, password_recovery_service):
        """Test validation with incomplete token document"""
        password_recovery_service.db_port.find_entry = MagicMock(return_value={
            "token": "incomplete-token"
            # Missing user_email and expires_at
        })
        
        with pytest.raises((PasswordRecoveryTokenNotFoundError, Exception)):
            await password_recovery_service.validate_recovery_token("incomplete-token")
