import pytest
import datetime
from unittest.mock import AsyncMock, patch
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

    result = await service.get_user(user_mail=valid_user.mail)

    assert result == {"uid": mocker.MagicMock(value="alice")} or result.get("uid").value == "alice"
    ldap_port.get_user_by_attribute.assert_called_once_with("mail", valid_user.mail)


@pytest.mark.asyncio
async def test_get_user_not_found(valid_user):
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = None
    service = UserService(ldap_port)

    with pytest.raises(UserNotFoundError):
        await service.get_user(user_mail=valid_user.mail)

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


# ===== Additional tests for missing coverage =====

@pytest.mark.asyncio
async def test_get_all_users_success(mocker, patch_role_service):
    """Test get_all_users with valid LDAP data"""
    ldap_port = AsyncMock()
    ldap_port.get_all_users.return_value = [
        {
            "uid": ["alice"],
            "mail": ["alice@example.com"],
            "cn": ["Alice Wonderland"],
            "sn": ["Wonderland"],
            "givenName": ["Alice"],
            "telephoneNumber": ["123456789"],
            "ou": ["UADE"],
        }
    ]
    service = UserService(ldap_port)

    result = await service.get_all_users()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0].username == "alice"
    assert result[0].mail == "alice@example.com"


@pytest.mark.asyncio
async def test_get_all_users_not_found(patch_role_service):
    """Test get_all_users when no users exist"""
    ldap_port = AsyncMock()
    ldap_port.get_all_users.return_value = None
    service = UserService(ldap_port)

    with pytest.raises(UserNotFoundError):
        await service.get_all_users()


@pytest.mark.asyncio
async def test_get_user_roles_success(mocker, patch_role_service, valid_user, role_admin):
    """Test get_user_roles successfully retrieves roles"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {"uid": AsyncMock(value="alice")}
    service = UserService(ldap_port)
    
    # Mock the user_role_service's non_relational_db_port to return user roles
    with patch('app.domain.services.user_service.user_role_service') as mock_user_role_service:
        mock_user_role_service.non_relational_db_port.find_entry.return_value = {"roles": ["role_123"]}
        with patch('app.domain.services.user_service.role_service') as mock_role_service:
            mock_role_service.get_roles_by_ids.return_value = [role_admin]
            
            result = await service.get_user_roles(valid_user.mail)
            
            assert isinstance(result, list)
            assert len(result) == 1
            assert result[0].name == "admin"


@pytest.mark.asyncio
async def test_get_user_roles_user_not_found(valid_user):
    """Test get_user_roles when user is not found"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = None
    service = UserService(ldap_port)

    with pytest.raises(UserNotFoundError):
        await service.get_user_roles(valid_user.mail)


@pytest.mark.asyncio
async def test_get_user_by_username(mocker):
    """Test get_user when searching by username"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {"uid": "alice"}
    service = UserService(ldap_port)

    result = await service.get_user(username="alice")

    ldap_port.get_user_by_attribute.assert_called_with("uid", "alice")


@pytest.mark.asyncio
async def test_get_user_by_user_id(mocker):
    """Test get_user when searching by user_id"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {"uid": "alice"}
    service = UserService(ldap_port)

    result = await service.get_user(user_id="alice")

    ldap_port.get_user_by_attribute.assert_called_with("uid", "alice")


@pytest.mark.asyncio
async def test_get_user_no_params():
    """Test get_user with no parameters raises error"""
    ldap_port = AsyncMock()
    service = UserService(ldap_port)

    with pytest.raises(InvalidUserDataError):
        await service.get_user()


@pytest.mark.asyncio
async def test_get_user_returns_list_normalized(mocker):
    """Test get_user normalizes list returns to single entry"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = [{"uid": "alice"}]
    service = UserService(ldap_port)

    result = await service.get_user(user_mail="alice@example.com")

    assert result == {"uid": "alice"}


@pytest.mark.asyncio
async def test_get_users_by_organization_success(mocker, patch_role_service):
    """Test get_users_by_organization successfully retrieves users"""
    ldap_port = AsyncMock()
    ldap_port.get_all_users.return_value = [
        {
            "uid": ["alice"],
            "mail": ["alice@example.com"],
            "cn": ["Alice Wonderland"],
            "sn": ["Wonderland"],
            "givenName": ["Alice"],
            "telephoneNumber": ["123456789"],
            "ou": ["UADE"],
        }
    ]
    service = UserService(ldap_port)

    result = await service.get_users_by_organization("UADE")

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0].organization == "UADE"


@pytest.mark.asyncio
async def test_get_users_by_organization_not_found(patch_role_service):
    """Test get_users_by_organization when no users exist"""
    ldap_port = AsyncMock()
    ldap_port.get_all_users.return_value = [
        {
            "uid": ["alice"],
            "mail": ["alice@example.com"],
            "cn": ["Alice Wonderland"],
            "sn": ["Wonderland"],
            "ou": ["OTHER"],
        }
    ]
    service = UserService(ldap_port)

    with pytest.raises(UserNotFoundError):
        await service.get_users_by_organization("UADE")


@pytest.mark.asyncio
async def test_modify_user_data_success(mocker, patch_role_service, valid_user):
    """Test modify_user_data successfully updates user"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {
        "uid": AsyncMock(value="alice"),
        "mail": "alice@example.com"
    }
    ldap_port.modify_user_data.return_value = True
    service = UserService(ldap_port)

    new_data = {"mail": "newalice@example.com"}
    result = await service.modify_user_data(valid_user.mail, new_data)

    assert result == new_data


@pytest.mark.asyncio
async def test_modify_user_data_user_not_found(valid_user):
    """Test modify_user_data when user not found"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = None
    service = UserService(ldap_port)

    with pytest.raises(UserNotFoundError):
        await service.modify_user_data(valid_user.mail, {})


@pytest.mark.asyncio
async def test_modify_user_data_failure(mocker, patch_role_service, valid_user):
    """Test modify_user_data when modification fails"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {
        "uid": AsyncMock(value="alice"),
        "mail": "alice@example.com"
    }
    ldap_port.modify_user_data.return_value = False
    service = UserService(ldap_port)

    with pytest.raises(FailureUserCreationError):
        await service.modify_user_data(valid_user.mail, {})


@pytest.mark.asyncio
async def test_modify_user_password_success(valid_user):
    """Test modify_user_password successfully updates password"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {
        "uid": AsyncMock(value="alice")
    }
    ldap_port.modify_user_password.return_value = True
    service = UserService(ldap_port)

    result = await service.modify_user_password(valid_user.mail, "newpass123")

    assert result is True


@pytest.mark.asyncio
async def test_modify_user_password_user_not_found(valid_user):
    """Test modify_user_password when user not found"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = None
    service = UserService(ldap_port)

    with pytest.raises(UserNotFoundError):
        await service.modify_user_password(valid_user.mail, "newpass123")


@pytest.mark.asyncio
async def test_modify_user_password_failure(valid_user):
    """Test modify_user_password when modification fails"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {
        "uid": AsyncMock(value="alice")
    }
    ldap_port.modify_user_password.return_value = False
    service = UserService(ldap_port)

    with pytest.raises(FailureUserCreationError):
        await service.modify_user_password(valid_user.mail, "newpass123")


@pytest.mark.asyncio
async def test_delete_user_with_list_response(valid_user):
    """Test delete_user when get_user_by_attribute returns a list"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = [{"uid": "alice"}]
    ldap_port.delete_user.return_value = True
    service = UserService(ldap_port)

    await service.delete_user(valid_user.mail)

    ldap_port.delete_user.assert_called_once()


@pytest.mark.asyncio
async def test_get_last_logins_success(valid_user):
    """Test get_last_logins successfully retrieves login history"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {
        "uid": AsyncMock(value="alice"),
        "ou": AsyncMock(value="UADE")
    }
    ldap_port.get_login_history.return_value = [
        "2024-01-01 10:00:00",
        "2024-01-02 11:00:00",
        "2024-01-03 12:00:00",
    ]
    service = UserService(ldap_port)

    result = await service.get_last_logins(valid_user.mail, limit=2)

    assert len(result) == 2


@pytest.mark.asyncio
async def test_get_last_logins_user_not_found(valid_user):
    """Test get_last_logins when user not found"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = None
    service = UserService(ldap_port)

    with pytest.raises(UserNotFoundError):
        await service.get_last_logins(valid_user.mail)


@pytest.mark.asyncio
async def test_authenticate_user_locked_with_string_date(valid_user):
    """Test authenticate_user locked account with string date"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {
        "uid": AsyncMock(value="alice"),
        "ou": AsyncMock(value="UADE"),
    }
    ldap_port.authenticate.return_value = True
    ldap_port.is_account_locked.return_value = "2024-01-01 10:00:00"
    service = UserService(ldap_port)

    with pytest.raises(UserLockedDownError):
        await service.authenticate_user(valid_user.mail, "Secret123")


@pytest.mark.asyncio
async def test_authenticate_user_with_client_ip(valid_user):
    """Test authenticate_user records login with client IP"""
    ldap_port = AsyncMock()
    ldap_port.get_user_by_attribute.return_value = {
        "uid": AsyncMock(value="alice"),
        "ou": AsyncMock(value="UADE"),
    }
    ldap_port.authenticate.return_value = True
    ldap_port.is_account_locked.return_value = False
    ldap_port.add_login_record = AsyncMock()
    ldap_port.prune_login_records = AsyncMock()
    service = UserService(ldap_port)

    result = await service.authenticate_user(valid_user.mail, "Secret123", "192.168.1.1")

    ldap_port.add_login_record.assert_called_once()
    ldap_port.prune_login_records.assert_called_once()
