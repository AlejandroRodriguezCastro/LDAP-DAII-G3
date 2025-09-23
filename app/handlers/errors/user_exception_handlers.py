from fastapi import Request, status
from fastapi.responses import JSONResponse

# User-related custom exceptions
class UserNotFoundError(Exception):
    """Raised when a user is not found in the system."""
    def __init__(self, user_id: str = None, message: str = None):
        if message:
            self.message = message
        elif user_id:
            self.message = f"User with ID '{user_id}' not found."
        else:
            self.message = "User not found."
        super().__init__(self.message)

class UserAlreadyExistsError(Exception):
    """Raised when attempting to create a user that already exists."""
    def __init__(self, username: str = None, message: str = None):
        if message:
            self.message = message
        elif username:
            self.message = f"User '{username}' already exists."
        else:
            self.message = "User already exists."
        super().__init__(self.message)

class InvalidUserDataError(Exception):
    """Raised when provided user data is invalid."""
    def __init__(self, details: str = None):
        self.message = f"Invalid user data. {details}" if details else "Invalid user data."
        super().__init__(self.message)

class UnauthorizedUserError(Exception):
    """Raised when a user is not authorized to perform an action."""
    def __init__(self, action: str = None):
        self.message = f"Unauthorized to perform action: {action}" if action else "Unauthorized user."
        super().__init__(self.message)

def user_not_found_handler(request: Request, exc: UserNotFoundError):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": str(exc)},
    )

def user_already_exists_handler(request: Request, exc: UserAlreadyExistsError):
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={"detail": str(exc)},
    )

def invalid_user_data_handler(request: Request, exc: InvalidUserDataError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": str(exc)},
    )

def unauthorized_user_handler(request: Request, exc: UnauthorizedUserError):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": str(exc)},
    )