import pytest
from fastapi import HTTPException, status, Query
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock, patch
from app.api.v1.users.user import router as user_router
from app.api.v1.organization_unit.organization_unit import router as org_router
from app.api.v1.roles.roles import router as roles_router
from app.domain.entities.user import User
from app.domain.entities.organization_unit import OrganizationUnit
from app.domain.entities.roles import Role


# Test fixtures for API endpoints
@pytest.fixture
def valid_user_data():
    return {
        "username": "alice",
        "mail": "alice@example.com",
        "roles": [],
        "telephone_number": "123456789",
        "first_name": "Alice",
        "last_name": "Wonderland",
        "organization": "UADE",
        "password": "Secret123!##$$$",
    }


@pytest.fixture
def valid_org_data():
    return {"name": "UADE"}


@pytest.fixture
def valid_role_data():
    return {
        "name": "admin",
        "description": "Administrator role",
        "organization": "UADE"
    }


class TestUserEndpoints:
    @pytest.mark.asyncio
    @patch('app.api.v1.users.user._require_roles')
    @patch('app.api.v1.users.user.get_ldap_port_instance')
    @patch('app.api.v1.users.user.UserService')
    async def test_get_user_by_id(self, mock_service_class, mock_ldap, mock_require_roles, valid_user_data):
        """Test GET /user/get-user with user_id"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = AsyncMock(return_value=MagicMock())
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service
        
        # Create mock LDAP user object with LDAP attributes
        ldap_user = MagicMock()
        ldap_user.get = MagicMock(side_effect=lambda key, default="": {
            "uid": "alice",
            "mail": "alice@example.com",
            "cn": "Alice Wonderland",
            "sn": "Wonderland",
            "telephoneNumber": "123456789",
            "ou": "UADE"
        }.get(key, default))
        
        mock_service.get_user = AsyncMock(return_value=ldap_user)
        mock_service.get_user_roles = AsyncMock(return_value=[])
        
        from app.api.v1.users.user import get_user
        request = MagicMock()
        result = await get_user(request, user_id="alice")
        
        assert result.username == "alice"
        # When calling the function directly, verify the service was called with the correct parameters
        call_args = mock_service.get_user.call_args
        assert call_args[1]['user_id'] == "alice"
        # username and user_mail should have default=None
        assert hasattr(call_args[1]['username'], 'default') and call_args[1]['username'].default is None
        assert hasattr(call_args[1]['user_mail'], 'default') and call_args[1]['user_mail'].default is None

    @pytest.mark.asyncio
    @patch('app.api.v1.users.user._require_roles')
    @patch('app.api.v1.users.user.get_ldap_port_instance')
    @patch('app.api.v1.users.user.UserService')
    async def test_get_user_by_username(self, mock_service_class, mock_ldap, mock_require_roles, valid_user_data):
        """Test GET /user/get-user with username"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = AsyncMock(return_value=MagicMock())
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service
        
        # Create mock LDAP user object with LDAP attributes
        ldap_user = MagicMock()
        ldap_user.get = MagicMock(side_effect=lambda key, default="": {
            "uid": "alice",
            "mail": "alice@example.com",
            "cn": "Alice Wonderland",
            "sn": "Wonderland",
            "telephoneNumber": "123456789",
            "ou": "UADE"
        }.get(key, default))
        
        mock_service.get_user = AsyncMock(return_value=ldap_user)
        mock_service.get_user_roles = AsyncMock(return_value=[])
        
        from app.api.v1.users.user import get_user
        request = MagicMock()
        result = await get_user(request, username="alice")
        
        assert result.mail == "alice@example.com"

    @pytest.mark.asyncio
    @patch('app.api.v1.users.user._require_roles')
    @patch('app.api.v1.users.user.get_ldap_port_instance')
    @patch('app.api.v1.users.user.UserService')
    async def test_get_user_no_params(self, mock_service_class, mock_ldap, mock_require_roles):
        """Test GET /user/get-user without parameters raises 400"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = AsyncMock(return_value=MagicMock())
        
        from app.api.v1.users.user import get_user
        request = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            await get_user(request, user_id=None, username=None, user_mail=None)
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    @patch('app.api.v1.users.user._require_roles')
    @patch('app.api.v1.users.user.get_ldap_port_instance')
    @patch('app.api.v1.users.user.UserService')
    async def test_get_user_not_found(self, mock_service_class, mock_ldap, mock_require_roles):
        """Test GET /user/get-user when user not found raises 404"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = AsyncMock(return_value=MagicMock())
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service
        mock_service.get_user = AsyncMock(return_value=None)
        
        from app.api.v1.users.user import get_user
        request = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            await get_user(request, username="missing")
        
        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    @patch('app.api.v1.users.user._require_roles')
    @patch('app.api.v1.users.user.get_ldap_port_instance')
    @patch('app.api.v1.users.user.UserService')
    async def test_create_user(self, mock_service_class, mock_ldap, mock_require_roles, valid_user_data):
        """Test POST /user"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = AsyncMock(return_value=MagicMock())
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service
        
        user = User(**valid_user_data)
        mock_service.create_user = AsyncMock(return_value=user)
        
        from app.api.v1.users.user import create_user
        request = MagicMock()
        result = await create_user(user, request)
        
        assert result.username == "alice"

    @pytest.mark.asyncio
    @patch('app.api.v1.users.user._require_roles')
    @patch('app.api.v1.users.user.get_ldap_port_instance')
    @patch('app.api.v1.users.user.UserService')
    async def test_delete_user(self, mock_service_class, mock_ldap, mock_require_roles):
        """Test DELETE /user/{user_mail}"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = AsyncMock(return_value=MagicMock())
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service
        mock_service.delete_user = AsyncMock()
        
        from app.api.v1.users.user import delete_user
        request = MagicMock()
        await delete_user("alice@example.com", request)
        
        mock_service.delete_user.assert_called_once_with("alice@example.com")

    @pytest.mark.asyncio
    @patch('app.api.v1.users.user._require_roles')
    @patch('app.api.v1.users.user.get_ldap_port_instance')
    @patch('app.api.v1.users.user.UserService')
    async def test_update_user(self, mock_service_class, mock_ldap, mock_require_roles, valid_user_data):
        """Test PUT /user/{user_mail}"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = AsyncMock(return_value=MagicMock())
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service
        
        user = User(**valid_user_data)
        mock_service.modify_user_data = AsyncMock(return_value=user)
        
        from app.api.v1.users.user import update_user
        request = MagicMock()
        result = await update_user("alice@example.com", user, request)
        
        assert result.username == "alice"

    @pytest.mark.asyncio
    @patch('app.api.v1.users.user._require_roles')
    @patch('app.api.v1.users.user.get_ldap_port_instance')
    @patch('app.api.v1.users.user.UserService')
    async def test_get_all_users(self, mock_service_class, mock_ldap, mock_require_roles, valid_user_data):
        """Test GET /user/all"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = AsyncMock(return_value=MagicMock())
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service
        
        users = [User(**valid_user_data)]
        mock_service.get_all_users = AsyncMock(return_value=users)
        
        from app.api.v1.users.user import get_all_users
        request = MagicMock()
        result = await get_all_users(request)
        
        assert len(result) == 1

    @pytest.mark.asyncio
    @patch('app.api.v1.users.user._require_roles')
    @patch('app.api.v1.users.user.get_ldap_port_instance')
    @patch('app.api.v1.users.user.UserService')
    async def test_change_password(self, mock_service_class, mock_ldap, mock_require_roles):
        """Test POST /user/change-password"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = AsyncMock(return_value=MagicMock())
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service
        mock_service.change_password = AsyncMock(return_value=True)
        
        from app.api.v1.users.user import change_password, ChangePasswordRequest
        request = MagicMock()
        payload = ChangePasswordRequest(
            mail="alice@example.com",
            old_password="OldPassword123!",
            new_password="NewPassword123!"
        )
        result = await change_password(request, payload)
        
        assert "Password changed successfully" in result["message"]

    @pytest.mark.asyncio
    @patch('app.api.v1.users.user._require_roles')
    @patch('app.api.v1.users.user.get_ldap_port_instance')
    @patch('app.api.v1.users.user.UserService')
    async def test_change_password_failure(self, mock_service_class, mock_ldap, mock_require_roles):
        """Test POST /user/change-password failure"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = AsyncMock(return_value=MagicMock())
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service
        mock_service.change_password = AsyncMock(return_value=False)
        
        from app.api.v1.users.user import change_password, ChangePasswordRequest
        request = MagicMock()
        payload = ChangePasswordRequest(
            mail="alice@example.com",
            old_password="OldPassword123!",
            new_password="NewPassword123!"
        )
        with pytest.raises(HTTPException) as exc_info:
            await change_password(request, payload)
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST


class TestOrganizationUnitEndpoints:
    @pytest.mark.asyncio
    @patch('app.api.v1.organization_unit.organization_unit._require_roles')
    @patch('app.api.v1.organization_unit.organization_unit.get_ldap_port_instance')
    @patch('app.api.v1.organization_unit.organization_unit.OrganizationUnitService')
    async def test_read_organization_units(self, mock_service_class, mock_ldap, mock_require_roles):
        """Test GET /organization_units/"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = MagicMock()
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service
        mock_service.get_organization_all = AsyncMock(return_value=["UADE"])
        
        from app.api.v1.organization_unit.organization_unit import read_organization_units
        request = MagicMock()
        result = await read_organization_units(request)
        
        assert "organization_units" in result

    @pytest.mark.asyncio
    @patch('app.api.v1.organization_unit.organization_unit._require_roles')
    @patch('app.api.v1.organization_unit.organization_unit.get_ldap_port_instance')
    @patch('app.api.v1.organization_unit.organization_unit.OrganizationUnitService')
    async def test_create_organization_unit(self, mock_service_class, mock_ldap, mock_require_roles):
        """Test POST /organization_units/"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = MagicMock()
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service
        mock_service.create_organization = AsyncMock()
        
        from app.api.v1.organization_unit.organization_unit import create_organization_unit
        org = OrganizationUnit(name="NewOrg")
        request = MagicMock()
        result = await create_organization_unit(org, request)
        
        assert "created" in result["message"].lower()

    @pytest.mark.asyncio
    @patch('app.api.v1.organization_unit.organization_unit._require_roles')
    @patch('app.api.v1.organization_unit.organization_unit.get_ldap_port_instance')
    @patch('app.api.v1.organization_unit.organization_unit.OrganizationUnitService')
    async def test_delete_organization_unit(self, mock_service_class, mock_ldap, mock_require_roles):
        """Test DELETE /organization_units/{org_unit_name}"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = MagicMock()
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service
        mock_service.delete_organization = AsyncMock()
        
        from app.api.v1.organization_unit.organization_unit import delete_organization_unit
        request = MagicMock()
        result = await delete_organization_unit("OldOrg", request)
        
        assert "deleted" in result["message"].lower()


class TestRolesEndpoints:
    @pytest.mark.asyncio
    @patch('app.api.v1.roles.roles._require_roles')
    @patch('app.api.v1.roles.roles.role_service')
    async def test_create_role(self, mock_role_service, mock_require_roles, valid_role_data):
        """Test POST /roles/"""
        mock_require_roles.return_value = None
        mock_role_service.create_role.return_value = "role_123"
        
        from app.api.v1.roles.roles import create_role
        role = Role(**valid_role_data)
        request = MagicMock()
        result = await create_role(role, request)
        
        assert "inserted_id" in result

    @pytest.mark.asyncio
    @patch('app.api.v1.roles.roles._require_roles')
    @patch('app.api.v1.roles.roles.role_service')
    async def test_get_roles(self, mock_role_service, mock_require_roles, valid_role_data):
        """Test GET /roles/"""
        mock_require_roles.return_value = None
        role = Role(**valid_role_data)
        mock_role_service.get_roles.return_value = [role]
        
        from app.api.v1.roles.roles import get_roles
        request = MagicMock()
        result = await get_roles(request)
        
        assert "roles" in result

    @pytest.mark.asyncio
    @patch('app.api.v1.roles.roles._require_roles')
    @patch('app.api.v1.roles.roles.role_service')
    async def test_delete_role(self, mock_role_service, mock_require_roles):
        """Test DELETE /roles/{role_id}"""
        mock_require_roles.return_value = None
        mock_role_service.delete_role.return_value = 1
        
        from app.api.v1.roles.roles import delete_role
        request = MagicMock()
        result = await delete_role("role_123", request)
        
        assert "deleted_count" in result

    @pytest.mark.asyncio
    @patch('app.api.v1.roles.roles._require_roles')
    @patch('app.api.v1.roles.roles.role_service')
    async def test_get_roles_by_organization(self, mock_role_service, mock_require_roles, valid_role_data):
        """Test GET /roles/organization/{organization_name}"""
        mock_require_roles.return_value = None
        role = Role(**valid_role_data)
        mock_role_service.get_roles_by_organization.return_value = [role]
        
        from app.api.v1.roles.roles import get_roles_by_organization
        request = MagicMock()
        result = await get_roles_by_organization("UADE", request)
        
        assert "roles" in result


# ===== Additional endpoint tests for missing coverage =====

class TestUserEndpointsAdditional:
    @pytest.mark.asyncio
    @patch('app.api.v1.users.user._require_roles')
    @patch('app.api.v1.users.user.get_ldap_port_instance')
    @patch('app.api.v1.users.user.UserService')
    async def test_get_users_by_organization(self, mock_service_class, mock_ldap, mock_require_roles, valid_user_data):
        """Test GET /user/by-organization/{org_unit_name}"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = AsyncMock(return_value=MagicMock())
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service
        
        users = [User(**valid_user_data)]
        mock_service.get_users_by_organization = AsyncMock(return_value=users)
        
        from app.api.v1.users.user import get_users_by_organization
        request = MagicMock()
        result = await get_users_by_organization("UADE", request)
        
        assert len(result) == 1
        assert result[0].organization == "UADE"

    @pytest.mark.asyncio
    @patch('app.api.v1.users.user._require_roles')
    @patch('app.api.v1.users.user.get_ldap_port_instance')
    @patch('app.api.v1.users.user.UserService')
    async def test_get_user_with_mail(self, mock_service_class, mock_ldap, mock_require_roles, valid_user_data):
        """Test GET /user/get-user with user_mail"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = AsyncMock(return_value=MagicMock())
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service
        
        # Create mock LDAP user object with LDAP attributes
        ldap_user = MagicMock()
        ldap_user.get = MagicMock(side_effect=lambda key, default="": {
            "uid": "alice",
            "mail": "alice@example.com",
            "cn": "Alice Wonderland",
            "sn": "Wonderland",
            "telephoneNumber": "123456789",
            "ou": "UADE"
        }.get(key, default))
        
        mock_service.get_user = AsyncMock(return_value=ldap_user)
        mock_service.get_user_roles = AsyncMock(return_value=[])
        
        from app.api.v1.users.user import get_user
        request = MagicMock()
        result = await get_user(request, user_mail="alice@example.com")
        
        assert result.mail == "alice@example.com"

    @pytest.mark.asyncio
    @patch('app.api.v1.users.user._require_roles')
    @patch('app.api.v1.users.user.get_ldap_port_instance')
    @patch('app.api.v1.users.user.UserService')
    async def test_get_user_with_roles(self, mock_service_class, mock_ldap, mock_require_roles, valid_user_data):
        """Test GET /user/get-user with roles normalization"""
        mock_require_roles.return_value = None
        mock_ldap.return_value = AsyncMock(return_value=MagicMock())
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service
        
        # Create mock LDAP user object with LDAP attributes
        ldap_user = MagicMock()
        ldap_user.get = MagicMock(side_effect=lambda key, default="": {
            "uid": "alice",
            "mail": "alice@example.com",
            "cn": "Alice Wonderland",
            "sn": "Wonderland",
            "telephoneNumber": "123456789",
            "ou": "UADE"
        }.get(key, default))
        
        # Mock role objects returned from service
        mock_role = Role(name="admin", description="Admin", organization="UADE")
        mock_service.get_user = AsyncMock(return_value=ldap_user)
        mock_service.get_user_roles = AsyncMock(return_value=[mock_role])
        
        from app.api.v1.users.user import get_user
        request = MagicMock()
        result = await get_user(request, user_mail="alice@example.com")
        
        assert len(result.roles) == 1
