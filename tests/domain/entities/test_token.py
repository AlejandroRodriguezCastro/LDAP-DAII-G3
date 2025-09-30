import pytest
import time
from app.domain.entities.token import Token

@pytest.fixture
def valid_token_data():
    now = int(time.time())
    return {
        "sub": "user123",
        "aud": "test-audience",
        "iss": "test-issuer",
        "exp": now + 3600,  # 1 hour from now
        "nbf": now,
        "iat": now,
        "jti": "token-123",
        "roles": ["admin", "user"],
        "email": "user@example.com",
    }

def test_token_initialization_valid(valid_token_data):
    token = Token(**valid_token_data)
    assert token.sub == "user123"
    assert "admin" in token.roles
    assert token.typ == "access"  # default

def test_token_missing_required_fields(valid_token_data):
    data = valid_token_data.copy()
    data.pop("sub")
    with pytest.raises(Exception):
        Token(**data)

def test_token_with_empty_roles(valid_token_data):
    data = valid_token_data.copy()
    data["roles"] = []
    token = Token(**data)
    assert token.roles == []

def test_token_expired_false(valid_token_data):
    token = Token(**valid_token_data)
    assert token.exp > int(time.time())

def test_token_expired_true(valid_token_data):
    data = valid_token_data.copy()
    data["exp"] = int(time.time()) - 10  # already expired
    token = Token(**data)
    assert token.exp < int(time.time())

def test_token_str_and_jwt(valid_token_data):
    token = Token(**valid_token_data)
    jwt_str = token.to_jwt(secret="mysecret", algorithm="HS256")
    assert isinstance(jwt_str, str)
    assert "." in jwt_str  # JWT has 3 parts separated by "."
