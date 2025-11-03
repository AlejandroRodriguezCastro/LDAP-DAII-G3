import pytest
from unittest.mock import MagicMock
from app.domain.services.user_role_service import UserRoleService
from app.domain.entities.user_role import UserRole
from app.domain.entities.roles import Role
from app.handlers.errors.role_exception_handlers import (
    RoleNotFoundError,
    RoleAlreadyExistsError,
    InvalidRoleDataError,
    FailureRoleCreationError,
)


@pytest.fixture
def valid_user_role():
    return UserRole(username="alice", roles=["role1"])


@pytest.fixture
def valid_role():
    return Role(name="Admin", description="Admin role", organization="UADE")


@pytest.fixture
def role_string_id():
    return "role_id_123"


def test_create_user_role_success(valid_user_role):
    db_port = MagicMock()
    db_port.find_entry.return_value = None
    db_port.insert_entry.return_value = "user_role_123"

    service = UserRoleService(db_port, "user_roles")
    result = service.create_user_role(valid_user_role)

    assert result == "user_role_123"
    db_port.find_entry.assert_called_once()
    db_port.insert_entry.assert_called_once()


def test_create_user_role_already_exists(valid_user_role):
    db_port = MagicMock()
    db_port.find_entry.return_value = {"username": "alice"}

    service = UserRoleService(db_port, "user_roles")
    with pytest.raises(RoleAlreadyExistsError):
        service.create_user_role(valid_user_role)


def test_create_user_role_failure(valid_user_role):
    db_port = MagicMock()
    db_port.find_entry.return_value = None
    db_port.insert_entry.return_value = None

    service = UserRoleService(db_port, "user_roles")
    with pytest.raises(FailureRoleCreationError):
        service.create_user_role(valid_user_role)


def test_add_role_to_user_with_role_model(valid_role):
    """Test adding a Role model instance to a new user"""
    db_port = MagicMock()
    
    # First call: find_entry for role in roles collection
    role_doc = {"_id": "role_id_123", "name": "Admin"}
    db_port.find_entry.side_effect = [role_doc, None]  # role found, user not found
    db_port.insert_entry.return_value = "new_user_id"

    service = UserRoleService(db_port, "user_roles")
    result = service.add_role_to_user("alice", valid_role)

    assert result == 1
    db_port.insert_entry.assert_called_once()


def test_add_role_to_user_with_string_id(role_string_id):
    """Test adding a role by string ID to a new user"""
    db_port = MagicMock()
    
    # First find_entry: look up role by ID
    role_doc = {"_id": role_string_id, "name": "Admin"}
    db_port.find_entry.side_effect = [role_doc, None]  # role found, user not found
    db_port.insert_entry.return_value = "new_user_id"

    service = UserRoleService(db_port, "user_roles")
    result = service.add_role_to_user("bob", role_string_id)

    assert result == 1


def test_add_role_to_user_by_name_string(valid_role):
    """Test adding a role by name string to a new user"""
    db_port = MagicMock()
    
    # First find_entry: look up role by ID fails, then by name succeeds
    role_doc = {"_id": "role_id_123", "name": "Admin"}
    db_port.find_entry.side_effect = [None, role_doc, None]  # ID lookup fails, name lookup succeeds, user not found
    db_port.insert_entry.return_value = "new_user_id"

    service = UserRoleService(db_port, "user_roles")
    result = service.add_role_to_user("charlie", "Admin")

    assert result == 1


def test_add_role_to_user_no_username():
    """Test that empty username raises InvalidRoleDataError"""
    db_port = MagicMock()
    service = UserRoleService(db_port, "user_roles")
    
    with pytest.raises(InvalidRoleDataError):
        service.add_role_to_user("", "role_id")


def test_add_role_to_user_role_not_found_by_id():
    """Test that non-existent role ID raises RoleNotFoundError"""
    db_port = MagicMock()
    db_port.find_entry.return_value = None  # Role not found
    
    service = UserRoleService(db_port, "user_roles")
    
    with pytest.raises(RoleNotFoundError):
        service.add_role_to_user("alice", "nonexistent_role_id")


def test_add_role_to_user_invalid_role_type():
    """Test that invalid role type raises InvalidRoleDataError"""
    db_port = MagicMock()
    service = UserRoleService(db_port, "user_roles")
    
    with pytest.raises(InvalidRoleDataError):
        service.add_role_to_user("alice", 123)  # Invalid type


def test_add_role_to_user_role_model_no_name():
    """Test that Role model without name raises InvalidRoleDataError"""
    db_port = MagicMock()
    service = UserRoleService(db_port, "user_roles")
    
    # Create a role without name
    role_mock = MagicMock()
    role_mock.model_dump.return_value = {"description": "No name"}
    
    with pytest.raises(InvalidRoleDataError):
        service.add_role_to_user("alice", role_mock)


def test_add_role_to_user_to_existing_user(valid_role):
    """Test adding a role to an existing user"""
    db_port = MagicMock()
    
    # Find role, then find existing user with roles
    role_doc = {"_id": "role_id_123", "name": "Admin"}
    user_doc = {"username": "alice", "roles": ["other_role_id"]}
    db_port.find_entry.side_effect = [role_doc, user_doc]
    db_port.update_entry.return_value = 1

    service = UserRoleService(db_port, "user_roles")
    result = service.add_role_to_user("alice", valid_role)

    assert result == 1
    db_port.update_entry.assert_called_once()


def test_add_role_to_user_duplicate_role():
    """Test adding a role that user already has (should skip)"""
    db_port = MagicMock()
    
    role_doc = {"_id": "role_id_123", "name": "Admin"}
    user_doc = {"username": "alice", "roles": ["role_id_123"]}
    db_port.find_entry.side_effect = [role_doc, user_doc]

    service = UserRoleService(db_port, "user_roles")
    result = service.add_role_to_user("alice", "Admin")

    assert result == 0  # No roles added
    db_port.update_entry.assert_not_called()


def test_add_role_to_user_update_failure():
    """Test failure when updating user with new role"""
    db_port = MagicMock()
    
    role_doc = {"_id": "role_id_123", "name": "Admin"}
    user_doc = {"username": "alice", "roles": ["other_role_id"]}
    db_port.find_entry.side_effect = [role_doc, user_doc]
    db_port.update_entry.return_value = 0  # Update failed

    service = UserRoleService(db_port, "user_roles")
    
    with pytest.raises(FailureRoleCreationError):
        service.add_role_to_user("alice", "Admin")


def test_add_role_to_user_new_user_creation_failure(valid_role):
    """Test failure when creating new user with role"""
    db_port = MagicMock()
    
    role_doc = {"_id": "role_id_123", "name": "Admin"}
    db_port.find_entry.side_effect = [role_doc, None]  # Role found, user not found
    db_port.insert_entry.return_value = None  # Insert failed

    service = UserRoleService(db_port, "user_roles")
    
    with pytest.raises(FailureRoleCreationError):
        service.add_role_to_user("alice", valid_role)


def test_add_role_to_user_no_role_id_in_doc():
    """Test error when role document doesn't have _id"""
    db_port = MagicMock()
    
    role_doc = {"name": "Admin"}  # No _id
    db_port.find_entry.side_effect = [role_doc, None]

    service = UserRoleService(db_port, "user_roles")
    
    with pytest.raises(InvalidRoleDataError):
        service.add_role_to_user("alice", "Admin")


def test_add_roles_to_user_single_role(valid_role):
    """Test adding a single role via add_roles_to_user"""
    db_port = MagicMock()
    
    role_doc = {"_id": "role_id_123", "name": "Admin"}
    db_port.find_entry.side_effect = [role_doc, None]
    db_port.insert_entry.return_value = "new_user_id"

    service = UserRoleService(db_port, "user_roles")
    result = service.add_roles_to_user("alice", valid_role)

    assert result == 1


def test_add_roles_to_user_single_string():
    """Test adding a single role by string via add_roles_to_user"""
    db_port = MagicMock()
    
    role_doc = {"_id": "role_id_123", "name": "Admin"}
    db_port.find_entry.side_effect = [role_doc, None]
    db_port.insert_entry.return_value = "new_user_id"

    service = UserRoleService(db_port, "user_roles")
    result = service.add_roles_to_user("alice", "Admin")

    assert result == 1


def test_add_roles_to_user_multiple_roles():
    """Test adding multiple roles via add_roles_to_user"""
    db_port = MagicMock()
    
    role1_doc = {"_id": "role_id_1", "name": "Admin"}
    role2_doc = {"_id": "role_id_2", "name": "User"}
    user_doc = {"username": "alice", "roles": []}
    
    db_port.find_entry.side_effect = [
        role1_doc, user_doc,  # First role addition
        role2_doc, user_doc   # Second role addition
    ]
    db_port.insert_entry.return_value = "new_user_id"
    db_port.update_entry.return_value = 1

    service = UserRoleService(db_port, "user_roles")
    result = service.add_roles_to_user("alice", ["Admin", "User"])

    assert result == 2


def test_add_roles_to_user_invalid_input():
    """Test that invalid roles_input raises InvalidRoleDataError"""
    db_port = MagicMock()
    service = UserRoleService(db_port, "user_roles")
    
    with pytest.raises(InvalidRoleDataError):
        service.add_roles_to_user("alice", 123)


def test_add_roles_to_user_empty_list():
    """Test adding empty list of roles"""
    db_port = MagicMock()
    service = UserRoleService(db_port, "user_roles")
    result = service.add_roles_to_user("alice", [])
    
    assert result == 0


def test_add_roles_to_user_mixed_duplicates():
    """Test adding multiple roles with some duplicates"""
    db_port = MagicMock()
    
    role1_doc = {"_id": "role_id_1", "name": "Admin"}
    role2_doc = {"_id": "role_id_2", "name": "User"}
    user_doc = {"username": "alice", "roles": ["role_id_1"]}  # Already has Admin
    
    db_port.find_entry.side_effect = [
        role1_doc, user_doc,  # First: Admin already exists (skip)
        role2_doc, user_doc   # Second: User doesn't exist (add)
    ]
    db_port.update_entry.return_value = 1

    service = UserRoleService(db_port, "user_roles")
    result = service.add_roles_to_user("alice", ["Admin", "User"])

    assert result == 1  # Only 1 role added (User)
