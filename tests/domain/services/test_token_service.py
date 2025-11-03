import pytest
import jwt
import datetime
from unittest.mock import AsyncMock
from app.domain.services.token_service import TokenService
from app.domain.entities.token import Token
from app.domain.entities.client_credentials import ClientCredentials
from app.domain.entities.roles import Role
from app.config.settings import settings


@pytest.mark.asyncio
async def test_generate_token_success():
    user_service = AsyncMock()
    user_service.get_user.return_value = "uid123"
    user_service.get_user_roles.return_value = [
        Role(name="admin", description="Admin role", organization="org1")
    ]

    service = TokenService(user_service)
    creds = ClientCredentials(username="alice@example.com", password="af94320j!#!")

    token = await service.generate_token(creds)

    assert isinstance(token, Token)
    assert token.sub == "uid123"
    assert token.email == "alice@example.com"
    assert "admin" in token.roles
    user_service.get_user.assert_called_once_with("alice@example.com")


def test_refresh_token_success():
    user_service = AsyncMock()
    service = TokenService(user_service)

    original = Token(
        sub="uid123",
        aud="ldap.com",
        iss="auth_server",
        email="alice@example.com",
        exp=int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 60,
        nbf=int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
        iat=int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
        jti="oldid",
        roles=["user"],
        typ="access",
        scope=["read", "write"],
    )

    refreshed = service.refresh_token(original)

    assert isinstance(refreshed, Token)
    assert refreshed.sub == original.sub
    assert refreshed.jti != original.jti
    assert refreshed.exp > original.exp


def test_validate_token_success_with_object():
    user_service = AsyncMock()
    service = TokenService(user_service)

    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    token = Token(
        sub="uid123",
        aud="ldap.com",
        iss="auth_server",
        email="alice@example.com",
        exp=int(now) + 100,
        nbf=int(now) - 10,
        iat=int(now) - 10,
        jti="id",
        roles=["user"],
        typ="access",
        scope=["read", "write"]
    )

    assert service.validate_token(token=token) is True


def test_validate_token_expired():
    user_service = AsyncMock()
    service = TokenService(user_service)

    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    token = Token(
        sub="uid123",
        aud="ldap.com",
        iss="auth_server",
        email="alice@example.com",
        exp=int(now) - 10,  # already expired
        nbf=int(now) - 20,
        iat=int(now) - 20,
        jti="id",
        roles=["user"],        
        typ="access",
        scope=["read", "write"]
    )

    assert service.validate_token(token=token) is False


def test_validate_token_not_yet_valid():
    user_service = AsyncMock()
    service = TokenService(user_service)

    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    token = Token(
        sub="uid123",
        aud="ldap.com",
        iss="auth_server",
        email="alice@example.com",
        exp=int(now) + 100,
        nbf=int(now) + 50,  # not valid yet
        iat=int(now) - 10,
        jti="id",
        roles=["user"],
        typ="access",
        scope=["read", "write"]
    )

    assert service.validate_token(token=token) is False


def test_validate_token_future_iat():
    user_service = AsyncMock()
    service = TokenService(user_service)

    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    token = Token(
        sub="uid123",
        aud="ldap.com",
        iss="auth_server",
        email="alice@example.com",
        exp=int(now) + 100,
        nbf=int(now) - 10,
        iat=int(now) + 50,  # issued in future
        jti="id",
        roles=["user"],
        typ="access",
        scope=["read", "write"]
    )

    assert service.validate_token(token=token) is False


def test_validate_token_with_jwt(monkeypatch):
    user_service = AsyncMock()
    service = TokenService(user_service)

    payload = {
        "sub": "uid123",
        "aud": "ldap.com",
        "iss": "auth_server",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
        "nbf": datetime.datetime.now(datetime.timezone.utc),
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "jti": "jwtid",
    }

    token_str = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    result = service.validate_token(jwt_token=token_str)

    assert result is True


def test_validate_token_with_invalid_jwt():
    user_service = AsyncMock()
    service = TokenService(user_service)

    bad_token = "invalid.jwt.token"
    result = service.validate_token(jwt_token=bad_token)

    assert result is False


def test_validate_token_no_input():
    user_service = AsyncMock()
    service = TokenService(user_service)

    assert service.validate_token() is False
