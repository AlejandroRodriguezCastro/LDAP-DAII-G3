from fastapi import FastAPI
import structlog
from app.handlers.errors.user_exception_handlers import (
    user_not_found_handler,
    user_already_exists_handler,
    invalid_user_data_handler,
    unauthorized_user_handler,
    failure_user_creation_handler,
    failure_user_deletion_handler,
    user_locked_down_handler,
    user_invalid_credentials_handler,
    UserNotFoundError,
    UserAlreadyExistsError,
    InvalidUserDataError,
    UnauthorizedUserError,
    FailureUserCreationError,
    FailureUserDeletionError,
    UserLockedDownError,
    UserInvalidCredentialsError
)

from app.handlers.errors.role_exception_handlers import (
    role_not_found_exception_handler,
    role_already_exists_exception_handler,
    invalid_role_data_exception_handler,
    failure_role_creation_exception_handler,
    failure_role_deletion_exception_handler,
    unauthorized_role_exception_handler,
    RoleNotFoundError,
    RoleAlreadyExistsError,
    InvalidRoleDataError,
    FailureRoleCreationError,
    FailureRoleDeletionError,
    UnauthorizedRoleError
)

logger = structlog.get_logger()

def register_exception_handlers(app: FastAPI):
    logger.info("Registering user exception handlers with FastAPI app.")
    app.add_exception_handler(UserNotFoundError, user_not_found_handler)
    app.add_exception_handler(UserAlreadyExistsError, user_already_exists_handler)
    app.add_exception_handler(InvalidUserDataError, invalid_user_data_handler)
    app.add_exception_handler(UnauthorizedUserError, unauthorized_user_handler)
    app.add_exception_handler(FailureUserCreationError, failure_user_creation_handler)
    app.add_exception_handler(FailureUserDeletionError, failure_user_deletion_handler)
    app.add_exception_handler(UserLockedDownError, user_locked_down_handler)
    app.add_exception_handler(UserInvalidCredentialsError, user_invalid_credentials_handler)
    
    logger.info("Registering role exception handlers with FastAPI app.")
    app.add_exception_handler(RoleNotFoundError, role_not_found_exception_handler)
    app.add_exception_handler(RoleAlreadyExistsError, role_already_exists_exception_handler)
    app.add_exception_handler(InvalidRoleDataError, invalid_role_data_exception_handler)
    app.add_exception_handler(FailureRoleCreationError, failure_role_creation_exception_handler)
    app.add_exception_handler(FailureRoleDeletionError, failure_role_deletion_exception_handler)
    app.add_exception_handler(UnauthorizedRoleError, unauthorized_role_exception_handler)
    