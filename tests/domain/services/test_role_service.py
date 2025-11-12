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
    # The method should query by _id (ObjectId) or id field
    call_args = db_port.delete_entry.call_args
    assert call_args[0][0] == service.collection
    assert call_args[0][1] == {"$or": [{"id": "123"}]} or "123" in str(call_args[0][1])


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
