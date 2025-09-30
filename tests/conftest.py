import pytest
import time
from app.domain.entities.user import User
from app.domain.entities.roles import Role
from app.domain.entities.token import Token


# -------------------------------
# Role Fixtures
# -------------------------------
@pytest.fixture
def role_admin():
    return Role(name="admin", description="Administrator role")


@pytest.fixture
def role_user():
    return Role(name="user", description="Standard user role")


# -------------------------------
# User Fixtures
# -------------------------------
@pytest.fixture
def valid_user(role_admin):
    return User(
        username="alice",
        mail="alice@example.com",
        roles=[role_admin],
        telephone_number="123456789",
        first_name="Alice",
        last_name="Wonderland",
        organization="UADE",
        password="Secret123!##$$$",
    )


@pytest.fixture
def another_user(role_user):
    return User(
        username="bob",
        mail="bob@example.com",
        roles=[role_user],
        telephone_number="987654321",
        first_name="Bob",
        last_name="Builder",
        organization="UADE",
        password="FixIt123!2##%",
    )


# -------------------------------
# Token Fixtures
# -------------------------------
@pytest.fixture
def valid_token():
    now = int(time.time())
    return Token(
        sub="alice",
        aud="test-audience",
        iss="test-issuer",
        exp=now + 3600,
        nbf=now,
        iat=now,
        jti="token-123",
        roles=["admin"],
        email="alice@example.com",
    )


@pytest.fixture
def expired_token():
    now = int(time.time())
    return Token(
        sub="alice",
        aud="test-audience",
        iss="test-issuer",
        exp=now - 10,  # already expired
        nbf=now - 100,
        iat=now - 100,
        jti="token-expired",
        roles=["admin"],
        email="alice@example.com",
    )
