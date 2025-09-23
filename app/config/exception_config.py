from fastapi import FastAPI
import structlog
from app.handlers.errors.user_exception_handlers import (
    user_not_found_handler,
    user_already_exists_handler,
    invalid_user_data_handler,
    unauthorized_user_handler,
    failure_user_creation_handler,
    failure_user_deletion_handler,
    UserNotFoundError,
    UserAlreadyExistsError,
    InvalidUserDataError,
    UnauthorizedUserError,
    FailureUserCreationError,
    FailureUserDeletionError
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