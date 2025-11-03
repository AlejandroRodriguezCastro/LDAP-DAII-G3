import pytest
import datetime
from unittest.mock import AsyncMock
from app.domain.services.user_service import UserService
from app.domain.entities.user import User
from app.handlers.errors.user_exception_handlers import (
    UserNotFoundError,
    UserAlreadyExistsError,
    InvalidUserDataError,
    FailureUserCreationError,
    FailureUserDeletionError,
    UserLockedDownError,
    UserInvalidCredentialsError,
)


@pytest.mark.asyncio
async def test_get_user_success(mocker, valid_user):
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {"uid": mocker.MagicMock(value="alice")}
    service = UserService(ldap_port)

    result = await service.get_user(valid_user.mail)

    assert result == "alice"
    ldap_port.get_user_by_attribute.assert_called_once_with("mail", valid_user.mail)


@pytest.mark.asyncio
async def test_get_user_not_found(valid_user):
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = None
    service = UserService(ldap_port)

    with pytest.raises(UserNotFoundError):
        await service.get_user(valid_user.mail)

@pytest.mark.asyncio
async def test_create_user_success(patch_role_service, valid_user):
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.side_effect = [None, None, {"ou": "UADE"}]  # email not exists, username not exists, org exists
    ldap_port.create_user.return_value = {"result": 0}
    service = UserService(ldap_port)

    result = await service.create_user(valid_user)

    assert isinstance(result, User)
    assert result.username.startswith(valid_user.first_name[0].lower())
    ldap_port.create_user.assert_called_once_with(valid_user)


@pytest.mark.asyncio
async def test_create_user_already_exists(valid_user):
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.side_effect = [{"uid": "already"}, None, {"ou": "UADE"}]  # email exists
    service = UserService(ldap_port)

    with pytest.raises(UserAlreadyExistsError):
        await service.create_user(valid_user)


@pytest.mark.asyncio
async def test_create_user_invalid_org(valid_user):
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.side_effect = [None, None, None]  # email not exists, username not exists, org missing
    service = UserService(ldap_port)

    with pytest.raises(InvalidUserDataError):
        await service.create_user(valid_user)


@pytest.mark.asyncio
async def test_create_user_failure(patch_role_service, valid_user):
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.side_effect = [None, None, {"ou": "UADE"}]
    ldap_port.create_user.return_value = {"result": 1}  # fails
    service = UserService(ldap_port)

    with pytest.raises(FailureUserCreationError):
        await service.create_user(valid_user)


@pytest.mark.asyncio
async def test_delete_user_success(valid_user):
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {"uid": "alice"}
    ldap_port.delete_user.return_value = True
    service = UserService(ldap_port)

    await service.delete_user(valid_user.mail)

    ldap_port.delete_user.assert_called_once_with(valid_user.mail)


@pytest.mark.asyncio
async def test_delete_user_not_found(valid_user):
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = None
    service = UserService(ldap_port)

    with pytest.raises(UserNotFoundError):
        await service.delete_user(valid_user.mail)


@pytest.mark.asyncio
async def test_delete_user_failure(valid_user):
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {"uid": "alice"}
    ldap_port.delete_user.return_value = False
    service = UserService(ldap_port)

    with pytest.raises(FailureUserDeletionError):
        await service.delete_user(valid_user.mail)


@pytest.mark.asyncio
async def test_authenticate_user_success(valid_user):
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {
        "uid": AsyncMock(value="alice"),
        "ou": AsyncMock(value="UADE"),
    }
    ldap_port.authenticate.return_value = True
    ldap_port.is_account_locked.return_value = False
    service = UserService(ldap_port)

    result = await service.authenticate_user(valid_user.mail, "Secret123")

    assert result is True
    ldap_port.authenticate.assert_called_once()


@pytest.mark.asyncio
async def test_authenticate_user_not_found(valid_user):
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = None
    service = UserService(ldap_port)

    with pytest.raises(UserNotFoundError):
        await service.authenticate_user(valid_user.mail, "Secret123")


@pytest.mark.asyncio
async def test_authenticate_user_missing_uid_ou(valid_user):
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {"uid": AsyncMock(value=None), "ou": AsyncMock(value=None)}
    service = UserService(ldap_port)

    with pytest.raises(InvalidUserDataError):
        await service.authenticate_user(valid_user.mail, "Secret123")


@pytest.mark.asyncio
async def test_authenticate_user_locked_account(valid_user):
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {
        "uid": AsyncMock(value="alice"),
        "ou": AsyncMock(value="UADE"),
    }
    ldap_port.authenticate.return_value = True
    ldap_port.is_account_locked.return_value = datetime.datetime(2024, 1, 1, 10, 0, 0)
    service = UserService(ldap_port)

    with pytest.raises(UserLockedDownError):
        await service.authenticate_user(valid_user.mail, "Secret123")


@pytest.mark.asyncio
async def test_authenticate_user_invalid_credentials(valid_user):
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {
        "uid": AsyncMock(value="alice"),
        "ou": AsyncMock(value="UADE"),
    }
    ldap_port.authenticate.return_value = False
    ldap_port.is_account_locked.return_value = False
    service = UserService(ldap_port)

    with pytest.raises(UserInvalidCredentialsError):
        await service.authenticate_user(valid_user.mail, "badpass")
