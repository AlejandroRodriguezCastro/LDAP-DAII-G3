from fastapi import Request, status
from fastapi.responses import JSONResponse


class PasswordRecoveryTokenNotFoundError(Exception):
    """Raised when a password recovery token is not found or invalid"""
    def __init__(self, message: str = "Password recovery token not found or invalid"):
        self.message = message
        super().__init__(self.message)


class PasswordRecoveryTokenExpiredError(Exception):
    """Raised when a password recovery token has expired"""
    def __init__(self, message: str = "Password recovery token has expired"):
        self.message = message
        super().__init__(self.message)


class PasswordRecoveryTokenAlreadyUsedError(Exception):
    """Raised when attempting to use a token that has already been used"""
    def __init__(self, message: str = "This password recovery token has already been used"):
        self.message = message
        super().__init__(self.message)


class PasswordRecoveryEmailFailedError(Exception):
    """Raised when password recovery email fails to send"""
    def __init__(self, message: str = "Failed to send password recovery email"):
        self.message = message
        super().__init__(self.message)


def password_recovery_token_not_found_handler(request: Request, exc: PasswordRecoveryTokenNotFoundError):
    """Handle PasswordRecoveryTokenNotFoundError"""
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"message": exc.message}
    )


def password_recovery_token_expired_handler(request: Request, exc: PasswordRecoveryTokenExpiredError):
    """Handle PasswordRecoveryTokenExpiredError"""
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"message": exc.message}
    )


def password_recovery_token_already_used_handler(request: Request, exc: PasswordRecoveryTokenAlreadyUsedError):
    """Handle PasswordRecoveryTokenAlreadyUsedError"""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"message": exc.message}
    )


def password_recovery_email_failed_handler(request: Request, exc: PasswordRecoveryEmailFailedError):
    """Handle PasswordRecoveryEmailFailedError"""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": exc.message}
    )
