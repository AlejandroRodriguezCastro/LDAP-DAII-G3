import pytest
from app.domain.entities.user import User
from app.domain.entities.roles import Role

@pytest.fixture
def valid_role():
    return Role(name="admin", description="Administrator role", organization="UADE")

@pytest.fixture
def valid_user_data(valid_role):
    return {
        "username": "alice",
        "mail": "alice@example.com",
        "roles": [valid_role],
        "telephone_number": "123456789",
        "first_name": "Alice",
        "last_name": "Wonderland",
        "organization": "UADE",
        "password": "Secret123!##$$$",
    }

def test_user_initialization(valid_user_data):
    user = User(**valid_user_data)
    assert user.username == "alice"
    assert user.mail == "alice@example.com"
    assert user.is_active is True
    assert isinstance(user.roles[0], Role)

def test_user_str_contains_username_and_email(valid_user_data):
    user = User(**valid_user_data)
    s = str(user)
    assert "alice" in s
    assert "alice@example.com" in s

def test_user_equality_same_values(valid_user_data):
    u1 = User(**valid_user_data)
    u2 = User(**valid_user_data)
    # test equality based on values, not object identity
    assert u1.address == u2.address
    assert u1.mail == u2.mail
    assert u1.telephone_number == u2.telephone_number
    assert u1.first_name == u2.first_name
    assert u1.last_name == u2.last_name
    assert u1.organization == u2.organization
    assert u1.password == u2.password

def test_user_equality_different(valid_user_data):
    u1 = User(**valid_user_data)
    data2 = valid_user_data.copy()
    data2["username"] = "bob"
    data2["mail"] = "bob@example.com"
    data2["password"] = "AnotherSecret123!##$$$"
    u2 = User(**data2)
    assert u1 != u2

def test_user_missing_required_fields(valid_role):
    # Missing mail, first_name, last_name, org, etc.
    with pytest.raises(Exception):
        User(username="bob", roles=[valid_role], password="pwd123", telephone_number="111")
