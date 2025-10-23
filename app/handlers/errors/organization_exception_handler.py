from fastapi import Request, status
from fastapi.responses import JSONResponse

# Organization-related custom exceptions
class OrganizationNotFoundError(Exception):
    """Raised when an organization unit is not found in the system."""
    def __init__(self, org_name: str = None, message: str = None):
        if message:
            self.message = message
        elif org_name:
            self.message = f"Organization unit '{org_name}' not found."
        else:
            self.message = "Organization unit not found."
        super().__init__(self.message)
        
class OrganizationAlreadyExistsError(Exception):
    """Raised when attempting to create an organization unit that already exists."""
    def __init__(self, org_name: str = None, message: str = None):
        if message:
            self.message = message
        elif org_name:
            self.message = f"Organization unit '{org_name}' already exists."
        else:
            self.message = "Organization unit already exists."
        super().__init__(self.message)
        
class InvalidOrganizationDataError(Exception):
    """Raised when provided organization unit data is invalid."""
    def __init__(self, details: str = None):
        self.message = f"Invalid organization unit data. {details}" if details else "Invalid organization unit data."
        super().__init__(self.message)
        
class UnauthorizedOrganizationError(Exception):
    """Raised when a user is not authorized to perform an action on organization units."""
    def __init__(self, action: str = None):
        self.message = f"Unauthorized to perform action: {action}" if action else "Unauthorized organization unit action."
        super().__init__(self.message)
        
class FailureOrganizationCreationError(Exception):
    """Raised when organization unit creation fails due to an internal error.

    Accepts an optional message and optional details. This keeps compatibility with
    callsites that pass either a single positional details argument or pass a
    message and a details keyword (e.g. FailureOrganizationCreationError("msg", details=...)).
    """
    def __init__(self, message: str = "Failed to create organization unit.", details: str = None):
        self.message = message
        if details:
            self.message += f" Details: {details}"
        super().__init__(self.message)
        
class FailureOrganizationDeletionError(Exception):
    """Raised when organization unit deletion fails due to an internal error.

    Accepts an optional message and optional details. This keeps compatibility with
    callsites that pass either a single positional details argument or pass a
    message and a details keyword (e.g. FailureOrganizationDeletionError("msg", details=...)).
    """
    def __init__(self, message: str = "Failed to delete organization unit.", details: str = None):
        self.message = message
        if details:
            self.message += f" Details: {details}"
        super().__init__(self.message)
        
def organitzation_not_found_exception_handler(request: Request, exc: OrganizationNotFoundError):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"message": exc.message}
    )
    
def organization_already_exists_exception_handler(request: Request, exc: OrganizationAlreadyExistsError):
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={"message": exc.message}
    )
    
def invalid_organization_data_exception_handler(request: Request, exc: InvalidOrganizationDataError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"message": exc.message}
    )
    
def unauthorized_organization_exception_handler(request: Request, exc: UnauthorizedOrganizationError):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"message": exc.message}
    )
    
def failure_organization_creation_exception_handler(request: Request, exc: FailureOrganizationCreationError):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": exc.message}
    )
    
def failure_organization_deletion_exception_handler(request: Request, exc: FailureOrganizationDeletionError):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": exc.message}
    )
    