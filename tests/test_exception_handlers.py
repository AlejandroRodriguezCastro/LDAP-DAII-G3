import json
from types import SimpleNamespace

import pytest


def _json_from_response(resp):
    # JSONResponse.body is bytes
    try:
        return json.loads(resp.body.decode())
    except Exception:
        return None


@pytest.mark.parametrize(
    "exc_cls,handler_func,expect_status,expect_key",
    [
        # organization handlers
        ("app.handlers.errors.organization_exception_handler.OrganizationNotFoundError", "app.handlers.errors.organization_exception_handler.organitzation_not_found_exception_handler", 404, "message"),
        ("app.handlers.errors.organization_exception_handler.OrganizationAlreadyExistsError", "app.handlers.errors.organization_exception_handler.organization_already_exists_exception_handler", 409, "message"),
        ("app.handlers.errors.organization_exception_handler.InvalidOrganizationDataError", "app.handlers.errors.organization_exception_handler.invalid_organization_data_exception_handler", 400, "message"),
        ("app.handlers.errors.organization_exception_handler.UnauthorizedOrganizationError", "app.handlers.errors.organization_exception_handler.unauthorized_organization_exception_handler", 401, "message"),
        ("app.handlers.errors.organization_exception_handler.FailureOrganizationCreationError", "app.handlers.errors.organization_exception_handler.failure_organization_creation_exception_handler", 500, "message"),
        ("app.handlers.errors.organization_exception_handler.FailureOrganizationDeletionError", "app.handlers.errors.organization_exception_handler.failure_organization_deletion_exception_handler", 500, "message"),
        # role handlers
        ("app.handlers.errors.role_exception_handlers.RoleNotFoundError", "app.handlers.errors.role_exception_handlers.role_not_found_exception_handler", 404, "message"),
        ("app.handlers.errors.role_exception_handlers.RoleAlreadyExistsError", "app.handlers.errors.role_exception_handlers.role_already_exists_exception_handler", 400, "message"),
        ("app.handlers.errors.role_exception_handlers.InvalidRoleDataError", "app.handlers.errors.role_exception_handlers.invalid_role_data_exception_handler", 422, "message"),
        ("app.handlers.errors.role_exception_handlers.FailureRoleCreationError", "app.handlers.errors.role_exception_handlers.failure_role_creation_exception_handler", 500, "message"),
        ("app.handlers.errors.role_exception_handlers.FailureRoleDeletionError", "app.handlers.errors.role_exception_handlers.failure_role_deletion_exception_handler", 500, "message"),
        ("app.handlers.errors.role_exception_handlers.UnauthorizedRoleError", "app.handlers.errors.role_exception_handlers.unauthorized_role_exception_handler", 401, "message"),
        # user handlers (these return key 'detail' instead of 'message')
        ("app.handlers.errors.user_exception_handlers.UserInvalidCredentialsError", "app.handlers.errors.user_exception_handlers.user_invalid_credentials_handler", 401, "detail"),
        ("app.handlers.errors.user_exception_handlers.UserLockedDownError", "app.handlers.errors.user_exception_handlers.user_locked_down_handler", 423, "detail"),
        ("app.handlers.errors.user_exception_handlers.FailureUserDeletionError", "app.handlers.errors.user_exception_handlers.failure_user_deletion_handler", 500, "detail"),
        ("app.handlers.errors.user_exception_handlers.FailureUserCreationError", "app.handlers.errors.user_exception_handlers.failure_user_creation_handler", 500, "detail"),
        ("app.handlers.errors.user_exception_handlers.UserNotFoundError", "app.handlers.errors.user_exception_handlers.user_not_found_handler", 404, "detail"),
        ("app.handlers.errors.user_exception_handlers.UserAlreadyExistsError", "app.handlers.errors.user_exception_handlers.user_already_exists_handler", 409, "detail"),
        ("app.handlers.errors.user_exception_handlers.InvalidUserDataError", "app.handlers.errors.user_exception_handlers.invalid_user_data_handler", 422, "detail"),
        ("app.handlers.errors.user_exception_handlers.UnauthorizedUserError", "app.handlers.errors.user_exception_handlers.unauthorized_user_handler", 401, "detail"),
    ],
)
def test_exception_handlers_return_expected_status_and_body(exc_cls, handler_func, expect_status, expect_key):
    # Dynamically import exception class and handler function by path
    exc_module_path, exc_name = exc_cls.rsplit(".", 1)
    handler_module_path, handler_name = handler_func.rsplit(".", 1)

    exc_mod = __import__(exc_module_path, fromlist=[exc_name])
    handler_mod = __import__(handler_module_path, fromlist=[handler_name])

    ExcCls = getattr(exc_mod, exc_name)
    handler = getattr(handler_mod, handler_name)

    # Create an instance of the exception with some distinguishing data where possible
    # Many exceptions accept different params; try to pass a helpful value if possible
    try:
        if exc_name.lower().startswith("userlockeddown") or exc_name == "UserLockedDownError":
            exc = ExcCls(user_dn="uid=test", date_until="2099-01-01")
        elif "NotFound" in exc_name and exc_name != "UserInvalidCredentialsError":
            # provide an id/name when available
            exc = ExcCls("identifier")
        elif "AlreadyExists" in exc_name:
            exc = ExcCls("duplicate")
        elif "Invalid" in exc_name or exc_name.startswith("Failure"):
            exc = ExcCls("details go here")
        else:
            # fallback: call without args
            exc = ExcCls()
    except TypeError:
        # last resort: instantiate with no args
        exc = ExcCls()

    fake_request = SimpleNamespace()  # handlers don't inspect request in these modules
    resp = handler(fake_request, exc)

    assert getattr(resp, "status_code", None) == expect_status
    body = _json_from_response(resp)
    assert isinstance(body, dict)
    assert expect_key in body
    # check message/detail matches exception message string or attribute
    # some exceptions expose .message attribute, others rely on str(exc)
    expected_text = getattr(exc, "message", None) or str(exc)
    # For organization/role handlers the content key is 'message' and uses exc.message
    assert expected_text in body[expect_key]
