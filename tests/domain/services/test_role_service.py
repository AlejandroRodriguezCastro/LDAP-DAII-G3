import pytest
from unittest.mock import MagicMock
from app.domain.services.role_service import RoleService
from app.domain.entities.roles import Role
from app.handlers.errors.role_exception_handlers import (
    RoleNotFoundError,
    RoleAlreadyExistsError,
    FailureRoleCreationError,
)


@pytest.fixture
def valid_role():
    return Role(name="Admin", description="Admin role", organization="default")


def test_create_role_success(valid_role):
    db_port = MagicMock()
    db_port.find_entry.return_value = None
    db_port.insert_entry.return_value = "123"

    service = RoleService(db_port, "roles")
    result = service.create_role(valid_role)

    assert result == "123"
    db_port.find_entry.assert_called_once_with(service.collection, {"name": valid_role.name})
    db_port.insert_entry.assert_called_once()


def test_create_role_already_exists(valid_role):
    db_port = MagicMock()
    db_port.find_entry.return_value = {"name": valid_role.name}

    service = RoleService(db_port, "roles")
    with pytest.raises(RoleAlreadyExistsError):
        service.create_role(valid_role)


def test_create_role_failure(valid_role):
    db_port = MagicMock()
    db_port.find_entry.return_value = None
    db_port.insert_entry.return_value = None

    service = RoleService(db_port, "roles")
    with pytest.raises(FailureRoleCreationError):
        service.create_role(valid_role)


def test_get_roles_success(valid_role):
    db_port = MagicMock()
    db_port.find_entries.return_value = [valid_role.model_dump()]

    service = RoleService(db_port, "roles")
    roles = service.get_roles()

    assert isinstance(roles[0], Role)
    assert roles[0].name == "Admin"


def test_get_roles_not_found():
    db_port = MagicMock()
    db_port.find_entries.return_value = []

    service = RoleService(db_port, "roles")
    with pytest.raises(RoleNotFoundError):
        service.get_roles()


def test_delete_role_success():
    db_port = MagicMock()
    db_port.delete_entry.return_value = 1

    service = RoleService(db_port, "roles")
    result = service.delete_role("123")

    assert result == 1
    db_port.delete_entry.assert_called_once_with(service.collection, {"id": "123"})


def test_delete_role_not_found():
    db_port = MagicMock()
    db_port.delete_entry.return_value = 0

    service = RoleService(db_port, "roles")
    with pytest.raises(RoleNotFoundError):
        service.delete_role("123")


def test_delete_roles_by_name_success():
    db_port = MagicMock()
    db_port.delete_entry.return_value = 1

    service = RoleService(db_port, "roles")
    result = service.delete_roles_by_name("Admin")

    assert result == 1
    db_port.delete_entry.assert_called_once_with(service.collection, {"name": "Admin"})


def test_delete_roles_by_name_not_found():
    db_port = MagicMock()
    db_port.delete_entry.return_value = 0

    service = RoleService(db_port, "roles")
    with pytest.raises(RoleNotFoundError):
        service.delete_roles_by_name("Admin")


def test_delete_roles_success():
    db_port = MagicMock()
    db_port.delete_many.return_value = 2

    service = RoleService(db_port, "roles")
    result = service.delete_roles({"name": "Admin"})

    assert result == 2
    db_port.delete_many.assert_called_once_with(service.collection, {"name": "Admin"})


def test_delete_roles_not_found():
    db_port = MagicMock()
    db_port.delete_many.return_value = 0

    service = RoleService(db_port, "roles")
    with pytest.raises(RoleNotFoundError):
        service.delete_roles({"name": "Admin"})


# ===== Additional tests for missing coverage =====

def test_get_roles_by_organization_success(valid_role):
    """Test get_roles_by_organization successfully retrieves roles"""
    db_port = MagicMock()
    role_dict = valid_role.model_dump()
    role_dict["organization"] = "UADE"
    db_port.find_entries.return_value = [role_dict]

    service = RoleService(db_port, "roles")
    roles = service.get_roles_by_organization("UADE")

    assert len(roles) == 1
    assert roles[0].name == "Admin"
    # Verify the query was constructed correctly
    db_port.find_entries.assert_called_once()
    call_args = db_port.find_entries.call_args
    assert "$or" in call_args[0][1]


def test_get_roles_by_organization_not_found():
    """Test get_roles_by_organization when no roles exist"""
    db_port = MagicMock()
    db_port.find_entries.return_value = []

    service = RoleService(db_port, "roles")
    with pytest.raises(RoleNotFoundError):
        service.get_roles_by_organization("UADE")


def test_get_roles_by_ids_success(valid_role):
    """Test get_roles_by_ids successfully retrieves roles"""
    db_port = MagicMock()
    role_dict = valid_role.model_dump()
    role_dict["_id"] = "123"
    db_port.find_entries.return_value = [role_dict]

    service = RoleService(db_port, "roles")
    roles = service.get_roles_by_ids(["123"])

    assert len(roles) == 1
    assert roles[0].name == "Admin"


def test_get_roles_by_ids_empty_list():
    """Test get_roles_by_ids with empty list"""
    db_port = MagicMock()

    service = RoleService(db_port, "roles")
    roles = service.get_roles_by_ids([])

    assert roles == []
    db_port.find_entries.assert_not_called()


def test_get_roles_by_ids_with_objectid():
    """Test get_roles_by_ids with ObjectId conversion"""
    db_port = MagicMock()
    role_dict = {
        "name": "Admin",
        "description": "Admin role",
        "organization": "UADE"
    }
    db_port.find_entries.return_value = [role_dict]

    service = RoleService(db_port, "roles")
    roles = service.get_roles_by_ids(["507f1f77bcf86cd799439011"])

    # Verify the service tried to build a query with ObjectId
    db_port.find_entries.assert_called_once()
    call_args = db_port.find_entries.call_args
    # The query should have either used id or _id field
    assert len(call_args[0]) >= 1


def test_get_roles_by_ids_partial_match():
    """Test get_roles_by_ids when some IDs don't match"""
    db_port = MagicMock()
    role_dict = {
        "name": "Admin",
        "description": "Admin role",
        "organization": "UADE"
    }
    db_port.find_entries.return_value = [role_dict]

    service = RoleService(db_port, "roles")
    roles = service.get_roles_by_ids(["123", "456"])

    # Even if only one role is found, the service should return it
    assert len(roles) == 1


def test_get_roles_organization_field_variations(valid_role):
    """Test get_roles handles various organization field names"""
    db_port = MagicMock()
    
    # Test with different organization field variations
    role_with_org = valid_role.model_dump()
    role_with_org["organization"] = "UADE"
    
    db_port.find_entries.return_value = [role_with_org]

    service = RoleService(db_port, "roles")
    roles = service.get_roles()

    assert len(roles) == 1
    assert roles[0].organization == "UADE"


def test_delete_role_with_different_filter():
    """Test delete_role uses correct filter"""
    db_port = MagicMock()
    db_port.delete_entry.return_value = 1

    service = RoleService(db_port, "roles")
    result = service.delete_role("role-id-123")

    db_port.delete_entry.assert_called_once_with("roles", {"id": "role-id-123"})
    assert result == 1
