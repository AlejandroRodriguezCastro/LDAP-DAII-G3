import pytest
from fastapi import Request, status
from unittest.mock import MagicMock
from app.handlers.errors.password_recovery_exception_handler import (
    PasswordRecoveryTokenNotFoundError,
    PasswordRecoveryTokenExpiredError,
    PasswordRecoveryTokenAlreadyUsedError,
    PasswordRecoveryEmailFailedError,
    password_recovery_token_not_found_handler,
    password_recovery_token_expired_handler,
    password_recovery_token_already_used_handler,
    password_recovery_email_failed_handler
)


@pytest.fixture
def mock_request():
    """Create a mock FastAPI Request"""
    return MagicMock(spec=Request)


class TestPasswordRecoveryExceptions:
    """Test password recovery exception classes"""

    def test_token_not_found_error_default_message(self):
        """Test TokenNotFoundError with default message"""
        exc = PasswordRecoveryTokenNotFoundError()
        assert exc.message == "Password recovery token not found or invalid"
        assert str(exc) == "Password recovery token not found or invalid"

    def test_token_not_found_error_custom_message(self):
        """Test TokenNotFoundError with custom message"""
        custom_msg = "Token has been revoked"
        exc = PasswordRecoveryTokenNotFoundError(custom_msg)
        assert exc.message == custom_msg
        assert str(exc) == custom_msg

    def test_token_expired_error_default_message(self):
        """Test TokenExpiredError with default message"""
        exc = PasswordRecoveryTokenExpiredError()
        assert exc.message == "Password recovery token has expired"
        assert str(exc) == "Password recovery token has expired"

    def test_token_expired_error_custom_message(self):
        """Test TokenExpiredError with custom message"""
        custom_msg = "Token expired 2 hours ago"
        exc = PasswordRecoveryTokenExpiredError(custom_msg)
        assert exc.message == custom_msg
        assert str(exc) == custom_msg

    def test_token_already_used_error_default_message(self):
        """Test TokenAlreadyUsedError with default message"""
        exc = PasswordRecoveryTokenAlreadyUsedError()
        assert exc.message == "This password recovery token has already been used"
        assert str(exc) == "This password recovery token has already been used"

    def test_token_already_used_error_custom_message(self):
        """Test TokenAlreadyUsedError with custom message"""
        custom_msg = "Token was used on 2024-01-15"
        exc = PasswordRecoveryTokenAlreadyUsedError(custom_msg)
        assert exc.message == custom_msg

    def test_email_failed_error_default_message(self):
        """Test EmailFailedError with default message"""
        exc = PasswordRecoveryEmailFailedError()
        assert exc.message == "Failed to send password recovery email"
        assert str(exc) == "Failed to send password recovery email"

    def test_email_failed_error_custom_message(self):
        """Test EmailFailedError with custom message"""
        custom_msg = "SMTP connection timeout"
        exc = PasswordRecoveryEmailFailedError(custom_msg)
        assert exc.message == custom_msg
        assert str(exc) == custom_msg

    def test_exception_inheritance(self):
        """Test that all exceptions inherit from Exception"""
        assert issubclass(PasswordRecoveryTokenNotFoundError, Exception)
        assert issubclass(PasswordRecoveryTokenExpiredError, Exception)
        assert issubclass(PasswordRecoveryTokenAlreadyUsedError, Exception)
        assert issubclass(PasswordRecoveryEmailFailedError, Exception)


class TestPasswordRecoveryTokenNotFoundHandler:
    """Test password recovery token not found exception handler"""

    def test_token_not_found_handler_response_structure(self, mock_request):
        """Test handler returns correct response structure"""
        exc = PasswordRecoveryTokenNotFoundError("Invalid token")
        response = password_recovery_token_not_found_handler(mock_request, exc)
        
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.media_type == "application/json"

    def test_token_not_found_handler_content(self, mock_request):
        """Test handler returns correct message content"""
        exc = PasswordRecoveryTokenNotFoundError("Token not found in database")
        response = password_recovery_token_not_found_handler(mock_request, exc)
        
        assert response.body == b'{"message":"Token not found in database"}'

    def test_token_not_found_handler_default_message(self, mock_request):
        """Test handler with default exception message"""
        exc = PasswordRecoveryTokenNotFoundError()
        response = password_recovery_token_not_found_handler(mock_request, exc)
        
        assert status.HTTP_404_NOT_FOUND == response.status_code
        assert "Password recovery token not found or invalid" in response.body.decode()


class TestPasswordRecoveryTokenExpiredHandler:
    """Test password recovery token expired exception handler"""

    def test_token_expired_handler_response_structure(self, mock_request):
        """Test handler returns correct response structure"""
        exc = PasswordRecoveryTokenExpiredError("Token expired")
        response = password_recovery_token_expired_handler(mock_request, exc)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.media_type == "application/json"

    def test_token_expired_handler_content(self, mock_request):
        """Test handler returns correct message content"""
        exc = PasswordRecoveryTokenExpiredError("Token expired 24 hours ago")
        response = password_recovery_token_expired_handler(mock_request, exc)
        
        assert response.body == b'{"message":"Token expired 24 hours ago"}'

    def test_token_expired_handler_default_message(self, mock_request):
        """Test handler with default exception message"""
        exc = PasswordRecoveryTokenExpiredError()
        response = password_recovery_token_expired_handler(mock_request, exc)
        
        assert status.HTTP_401_UNAUTHORIZED == response.status_code
        assert "Password recovery token has expired" in response.body.decode()

    def test_token_expired_handler_uses_401_status(self, mock_request):
        """Test that handler uses 401 Unauthorized status code"""
        exc = PasswordRecoveryTokenExpiredError()
        response = password_recovery_token_expired_handler(mock_request, exc)
        
        # 401 is more appropriate than 403 for expired tokens
        assert response.status_code == 401


class TestPasswordRecoveryTokenAlreadyUsedHandler:
    """Test password recovery token already used exception handler"""

    def test_token_already_used_handler_response_structure(self, mock_request):
        """Test handler returns correct response structure"""
        exc = PasswordRecoveryTokenAlreadyUsedError("Token was used")
        response = password_recovery_token_already_used_handler(mock_request, exc)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.media_type == "application/json"

    def test_token_already_used_handler_content(self, mock_request):
        """Test handler returns correct message content"""
        exc = PasswordRecoveryTokenAlreadyUsedError("Token was used on 2024-01-15")
        response = password_recovery_token_already_used_handler(mock_request, exc)
        
        assert response.body == b'{"message":"Token was used on 2024-01-15"}'

    def test_token_already_used_handler_default_message(self, mock_request):
        """Test handler with default exception message"""
        exc = PasswordRecoveryTokenAlreadyUsedError()
        response = password_recovery_token_already_used_handler(mock_request, exc)
        
        assert status.HTTP_400_BAD_REQUEST == response.status_code
        assert "already been used" in response.body.decode()

    def test_token_already_used_handler_uses_400_status(self, mock_request):
        """Test that handler uses 400 Bad Request status code"""
        exc = PasswordRecoveryTokenAlreadyUsedError()
        response = password_recovery_token_already_used_handler(mock_request, exc)
        
        # 400 is appropriate for client error (reusing token)
        assert response.status_code == 400


class TestPasswordRecoveryEmailFailedHandler:
    """Test password recovery email failed exception handler"""

    def test_email_failed_handler_response_structure(self, mock_request):
        """Test handler returns correct response structure"""
        exc = PasswordRecoveryEmailFailedError("Email service unavailable")
        response = password_recovery_email_failed_handler(mock_request, exc)
        
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert response.media_type == "application/json"

    def test_email_failed_handler_content(self, mock_request):
        """Test handler returns correct message content"""
        exc = PasswordRecoveryEmailFailedError("SMTP connection failed")
        response = password_recovery_email_failed_handler(mock_request, exc)
        
        assert response.body == b'{"message":"SMTP connection failed"}'

    def test_email_failed_handler_default_message(self, mock_request):
        """Test handler with default exception message"""
        exc = PasswordRecoveryEmailFailedError()
        response = password_recovery_email_failed_handler(mock_request, exc)
        
        assert status.HTTP_500_INTERNAL_SERVER_ERROR == response.status_code
        assert "Failed to send password recovery email" in response.body.decode()

    def test_email_failed_handler_uses_500_status(self, mock_request):
        """Test that handler uses 500 Internal Server Error status code"""
        exc = PasswordRecoveryEmailFailedError()
        response = password_recovery_email_failed_handler(mock_request, exc)
        
        # 500 is appropriate for server-side email service failures
        assert response.status_code == 500


class TestExceptionHandlerIntegration:
    """Test exception handlers work with different messages"""

    def test_handlers_with_special_characters(self, mock_request):
        """Test handlers handle special characters in messages"""
        exc = PasswordRecoveryTokenNotFoundError("Token not found: $pecial @chars!")
        response = password_recovery_token_not_found_handler(mock_request, exc)
        
        assert response.status_code == 404
        assert "$pecial @chars!" in response.body.decode()

    def test_handlers_with_long_messages(self, mock_request):
        """Test handlers handle long error messages"""
        long_msg = "A" * 500
        exc = PasswordRecoveryEmailFailedError(long_msg)
        response = password_recovery_email_failed_handler(mock_request, exc)
        
        assert response.status_code == 500
        assert long_msg in response.body.decode()

    def test_handlers_with_unicode_messages(self, mock_request):
        """Test handlers handle unicode characters"""
        exc = PasswordRecoveryTokenExpiredError("Token caducó hace 24 horas 🔐")
        response = password_recovery_token_expired_handler(mock_request, exc)
        
        assert response.status_code == 401
        assert "caducó" in response.body.decode()

    @pytest.mark.parametrize("status_code,expected_status", [
        (404, status.HTTP_404_NOT_FOUND),
        (401, status.HTTP_401_UNAUTHORIZED),
        (400, status.HTTP_400_BAD_REQUEST),
        (500, status.HTTP_500_INTERNAL_SERVER_ERROR),
    ])
    def test_handlers_status_codes(self, status_code, expected_status, mock_request):
        """Test all handlers return correct status codes"""
        exceptions_and_handlers = [
            (PasswordRecoveryTokenNotFoundError(), password_recovery_token_not_found_handler, 404),
            (PasswordRecoveryTokenExpiredError(), password_recovery_token_expired_handler, 401),
            (PasswordRecoveryTokenAlreadyUsedError(), password_recovery_token_already_used_handler, 400),
            (PasswordRecoveryEmailFailedError(), password_recovery_email_failed_handler, 500),
        ]
        
        for exc, handler, expected_code in exceptions_and_handlers:
            response = handler(mock_request, exc)
            assert response.status_code == expected_code
