from fastapi import Request, status
from fastapi.responses import JSONResponse

# Role-related custom exceptions
class RoleNotFoundError(Exception):
    """Raised when a role is not found in the system."""
    def __init__(self, role_id: str = None, message: str = None):
        if message:
            self.message = message
        elif role_id:
            self.message = f"Role with ID '{role_id}' not found."
        else:
            self.message = "Role not found."
        super().__init__(self.message)
        
class RoleAlreadyExistsError(Exception):
    """Raised when attempting to create a role that already exists."""
    def __init__(self, role_name: str = None, message: str = None):
        if message:
            self.message = message
        elif role_name:
            self.message = f"Role '{role_name}' already exists."
        else:
            self.message = "Role already exists."
        super().__init__(self.message)
        
class InvalidRoleDataError(Exception):
    """Raised when provided role data is invalid."""
    def __init__(self, details: str = None):
        self.message = f"Invalid role data. {details}" if details else "Invalid role data."
        super().__init__(self.message)

class FailureRoleCreationError(Exception):
    """Raised when role creation fails due to an internal error."""
    def __init__(self, details: str = None):
        self.message = f"Failed to create role. {details}" if details else "Failed to create role."
        super().__init__(self.message)
        
class FailureRoleDeletionError(Exception):
    """Raised when role deletion fails due to an internal error."""
    def __init__(self, details: str = None):
        self.message = f"Failed to delete role. {details}" if details else "Failed to delete role."
        super().__init__(self.message)
        
class UnauthorizedRoleError(Exception):
    """Raised when a user is not authorized to perform an action on roles."""
    def __init__(self, action: str = None):
        self.message = f"Unauthorized to perform action: {action}" if action else "Unauthorized role action."
        super().__init__(self.message)

def role_not_found_exception_handler(request: Request, exc: RoleNotFoundError):
    # Normalize the message so callers always receive a "Role with ID '<x>' not found." style
    original = getattr(exc, "message", None) or str(exc)
    # If the message already looks like the desired format, keep it as-is
    if isinstance(original, str) and (original.startswith("Role with ID") or original.startswith("Role with id") or original.startswith("Role with name") ): 
        formatted = original
    else:
        # Wrap the original message as the identifier for clarity
        formatted = f"Role with ID '{original}' not found."

    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"message": formatted}
    )
    
def role_already_exists_exception_handler(request: Request, exc: RoleAlreadyExistsError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"message": exc.message}
    )
    
def invalid_role_data_exception_handler(request: Request, exc: InvalidRoleDataError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"message": exc.message}
    )
    
def failure_role_creation_exception_handler(request: Request, exc: FailureRoleCreationError):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": exc.message}
    )
    
def failure_role_deletion_exception_handler(request: Request, exc: FailureRoleDeletionError):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": exc.message}
    )
    
def unauthorized_role_exception_handler(request: Request, exc: UnauthorizedRoleError):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"message": exc.message}
    )
    
        
