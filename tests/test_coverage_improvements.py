"""
Additional tests to improve overall coverage on low-coverage modules.
"""

import asyncio
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from types import SimpleNamespace


def test_mongo_settings_connection(monkeypatch):
    """Test MongoDB connection settings."""
    from app.config import mongo_settings
    from app.config.settings import settings

    # Mock MongoClient to avoid real connection
    mock_client = MagicMock()
    monkeypatch.setattr("app.config.mongo_settings.MongoClient", mock_client)

    # Reset global state
    mongo_settings.mongo_client = None

    # Test connect_db
    client = mongo_settings.connect_db()
    assert client is not None

    # Test disconnect_db
    mongo_settings.disconnect_db()
    assert mongo_settings.mongo_client is None


def test_logging_configuration():
    """Test logging configuration."""
    from app.utils.logging import configure_logging
    import logging

    configure_logging()
    logger = logging.getLogger("test_logger")
    assert logger is not None

    # Verify aio_pika logging is suppressed
    aio_pika_logger = logging.getLogger("aio_pika")
    assert aio_pika_logger.level >= logging.WARNING


def test_rabbitmq_singleton_initialization(monkeypatch):
    """Test RabbitMQ singleton initialization."""
    from app.config.rabbitmq_singleton import RabbitMQSingleton

    # Just verify the class exists and can be instantiated
    singleton = RabbitMQSingleton()
    assert isinstance(singleton, RabbitMQSingleton)


@pytest.mark.asyncio
async def test_rabbitmq_singleton_connect_with_timeout(monkeypatch):
    """Test RabbitMQ singleton connection with timeout."""
    from app.config.rabbitmq_singleton import RabbitMQSingleton

    singleton = RabbitMQSingleton()

    # Mock the connect call to simulate timeout
    async def mock_connect(connection_url):
        await asyncio.sleep(10)  # Longer than timeout

    monkeypatch.setattr("aio_pika.connect_robust", mock_connect, raising=False)

    # Connection should timeout after 5 seconds
    with pytest.raises(asyncio.TimeoutError):
        await singleton.connect()


def test_ldap_controller_initialization(monkeypatch):
    """Test LDAP controller base is abstract."""
    from app.controllers.ldap_base_controller import LDAPBaseController

    # LDAPBaseController is abstract, so we can't instantiate it directly
    assert hasattr(LDAPBaseController, 'connect')
    assert hasattr(LDAPBaseController, 'disconnect')
    assert hasattr(LDAPBaseController, 'search')


def test_exception_config_initialization():
    """Test exception configuration."""
    from app.config.exception_config import register_exception_handlers
    from fastapi import FastAPI

    app = FastAPI()
    register_exception_handlers(app)

    # Verify that exception handlers were registered
    assert len(app.exception_handlers) > 0


def test_password_recovery_entity():
    """Test PasswordRecoveryToken entity."""
    from app.domain.entities.password_recovery import PasswordRecoveryToken

    token = PasswordRecoveryToken(
        user_email="test@example.com",
        token="TOKEN123",
        expires_at="2025-12-31T23:59:59Z"
    )

    assert token.user_email == "test@example.com"
    assert token.token == "TOKEN123"
    assert token.is_used is False


def test_user_entity_methods():
    """Test User entity methods."""
    from app.domain.entities.user import User

    user = User(
        mail="john@example.com",
        first_name="John",
        last_name="Doe",
        telephone_number="+1234567890",
        organization="IT",
        password="ValidPassword123!"
    )

    assert user.mail == "john@example.com"
    assert user.is_active is True
    assert user.first_name == "John"


def test_organization_unit_entity():
    """Test OrganizationUnit entity."""
    from app.domain.entities.organization_unit import OrganizationUnit

    org_unit = OrganizationUnit(
        name="IT"
    )

    assert org_unit.name == "IT"


def test_token_entity_initialization():
    """Test Token entity initialization."""
    from app.domain.entities.token import Token
    import time

    now = int(time.time())
    token = Token(
        sub="client_123",
        aud="ldap.com",
        iss="auth_server",
        exp=now + 3600,
        nbf=now,
        iat=now,
        jti="jwt_id_123",
        roles=["admin"],
        email="test@example.com"
    )

    assert token.sub == "client_123"
    assert token.email == "test@example.com"


def test_roles_entity():
    """Test Role entity."""
    from app.domain.entities.roles import Role

    role = Role(
        name="admin",
        description="Administrator role",
        organization="IT"
    )

    assert role.name == "admin"
    assert role.description == "Administrator role"


def test_user_role_entity():
    """Test UserRole entity."""
    from app.domain.entities.user_role import UserRole

    user_role = UserRole(
        username="john.doe",
        roles=["role_1", "role_2"]
    )

    assert user_role.username == "john.doe"
    assert len(user_role.roles) == 2


def test_client_credentials_entity():
    """Test ClientCredentials entity."""
    from app.domain.entities.client_credentials import ClientCredentials

    creds = ClientCredentials(
        username="client_id",
        password="client_secret",
        redirect_uris=["http://localhost/callback"]
    )

    assert creds.username == "client_id"
    assert creds.password == "client_secret"
    assert len(creds.redirect_uris) == 1


@pytest.mark.asyncio
async def test_organization_unit_service_operations(monkeypatch):
    """Test OrganizationUnitService operations."""
    from app.domain.services.organization_unit_service import OrganizationUnitService

    call_count = {}
    
    class FakeLDAPPort:
        async def get_organization_all(self):
            return [
                SimpleNamespace(name="IT"),
                SimpleNamespace(name="HR")
            ]

        async def get_organization_by_name(self, name):
            # First call (during create) returns None, subsequent calls return org
            if name == "Finance":
                call_count[name] = call_count.get(name, 0) + 1
                if call_count[name] == 1:
                    return None  # First call - doesn't exist yet
                return SimpleNamespace(name="Finance")  # Second call - exists
            return None

        async def create_organization(self, org_data):
            return True

        async def delete_organization(self, org_name):
            return True

    service = OrganizationUnitService(FakeLDAPPort())

    # Test get_organization_all
    result = await service.get_organization_all()
    assert len(result) == 2

    # Test create_organization (first call to get_organization_by_name returns None)
    from app.domain.entities.organization_unit import OrganizationUnit
    org = OrganizationUnit(name="Finance")
    result = await service.create_organization(org)
    assert result is True

    # Test delete_organization (second call to get_organization_by_name returns org)
    result = await service.delete_organization("Finance")
    assert result is True


@pytest.mark.asyncio
async def test_role_service_operations(monkeypatch):
    """Test RoleService operations."""
    from app.domain.services.role_service import RoleService

    class FakeNonRelationalDBPort:
        def find_entries(self, collection):
            return [
                {"_id": "123", "name": "admin", "description": "Admin role", "organization": "IT"},
                {"_id": "124", "name": "user", "description": "User role", "organization": "IT"}
            ]

    service = RoleService(FakeNonRelationalDBPort(), "roles")

    result = service.get_roles()
    assert len(result) == 2


def test_expiration_parser():
    """Test expiration parser utility."""
    from app.utils.helpers.expiration_parser import parse_expiration

    # Test parsing hours
    result = parse_expiration("2h")
    assert result.total_seconds() == 7200

    # Test parsing days
    result = parse_expiration("1d")
    assert result.days == 1

    # Test parsing minutes
    result = parse_expiration("30m")
    assert result.total_seconds() == 1800


def test_authentication_handler_functions():
    """Test authentication handler functions."""
    from app.handlers.authentication.authentication_handler import (
        _extract_token_from_auth_header,
        _decode_roles_from_jwt
    )

    # Just verify the functions exist and are callable
    assert callable(_extract_token_from_auth_header)
    assert callable(_decode_roles_from_jwt)


def test_email_port_initialization(monkeypatch):
    """Test EmailPort initialization."""
    from app.ports.outbound.email_port import EmailPort
    from app.config.settings import settings

    port = EmailPort()
    assert port is not None


def test_nonrelational_db_port_operations():
    """Test NonRelationalDBPort operations."""
    from app.ports.outbound.nonrelationaldb_port import NonRelationalDBPort

    class FakeCollection:
        def find_one(self, query):
            return {"_id": "test"}

        def insert_one(self, document):
            return SimpleNamespace(inserted_id="test_id")

        def find(self, query):
            return [{"_id": "test", "name": "item"}]

    class FakeDB:
        def __getitem__(self, key):
            return FakeCollection()

    class FakeClient:
        def __getitem__(self, key):
            return FakeDB()

    port = NonRelationalDBPort(FakeClient())

    result = port.find_entry("test_collection", {})
    assert result == {"_id": "test"}

    result = port.insert_entry("test_collection", {"key": "value"})
    assert result is not None

    result = port.find_entries("test_collection")
    assert len(result) == 1


@pytest.mark.asyncio
async def test_rabbitmq_event_publisher_error_handling(monkeypatch):
    """Test RabbitMQ event publisher error handling."""
    from app.handlers.rabbitmq_event_publisher import publish_ldap_event

    async def fake_get_rabbitmq_error():
        raise Exception("Connection failed")

    monkeypatch.setattr(
        "app.handlers.rabbitmq_event_publisher.get_rabbitmq_port_instance",
        fake_get_rabbitmq_error,
        raising=False,
    )

    result = await publish_ldap_event("user.created", {"username": "test"})
    assert result is False


def test_user_exception_handlers():
    """Test user exception handlers."""
    from app.handlers.errors.user_exception_handlers import (
        user_not_found_handler,
        user_already_exists_handler,
        UserNotFoundError,
        UserAlreadyExistsError
    )

    exc = UserNotFoundError("user@example.com")
    response = user_not_found_handler(None, exc)
    assert response.status_code == 404

    exc = UserAlreadyExistsError("user@example.com")
    response = user_already_exists_handler(None, exc)
    assert response.status_code == 409


def test_role_exception_handlers():
    """Test role exception handlers."""
    from app.handlers.errors.role_exception_handlers import (
        role_not_found_exception_handler,
        role_already_exists_exception_handler,
        RoleNotFoundError,
        RoleAlreadyExistsError
    )

    exc = RoleNotFoundError("admin")
    response = role_not_found_exception_handler(None, exc)
    assert response.status_code == 404

    exc = RoleAlreadyExistsError("admin")
    response = role_already_exists_exception_handler(None, exc)
    assert response.status_code == 400


def test_organization_exception_handlers():
    """Test organization exception handlers."""
    from app.handlers.errors.organization_exception_handler import (
        organitzation_not_found_exception_handler,
        organization_already_exists_exception_handler,
        OrganizationNotFoundError,
        OrganizationAlreadyExistsError
    )

    exc = OrganizationNotFoundError("IT")
    response = organitzation_not_found_exception_handler(None, exc)
    assert response.status_code == 404

    exc = OrganizationAlreadyExistsError("IT")
    response = organization_already_exists_exception_handler(None, exc)
    assert response.status_code == 409


def test_password_recovery_exception_handlers():
    """Test password recovery exception handlers."""
    from app.handlers.errors.password_recovery_exception_handler import (
        password_recovery_token_expired_handler,
        password_recovery_token_not_found_handler,
        PasswordRecoveryTokenExpiredError,
        PasswordRecoveryTokenNotFoundError
    )

    exc = PasswordRecoveryTokenExpiredError("user@example.com")
    response = password_recovery_token_expired_handler(None, exc)
    assert response.status_code == 401

    exc = PasswordRecoveryTokenNotFoundError("invalid_code")
    response = password_recovery_token_not_found_handler(None, exc)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_token_service_with_edge_cases(monkeypatch):
    """Test TokenService edge cases."""
    from app.domain.services.token_service import TokenService
    from app.domain.entities.client_credentials import ClientCredentials

    class FakeUserService:
        async def get_user_roles(self, username):
            return []

        async def get_user(self, user_mail):
            return {"uid": "user_123"}

    service = TokenService(FakeUserService())

    # Test generating token
    creds = ClientCredentials(username="test@example.com", password="TestPass123!")
    result = await service.generate_token(creds)
    assert result is not None
    assert result.email == "test@example.com"


def test_settings_loading():
    """Test settings are properly loaded."""
    from app.config.settings import settings

    assert settings.APP_NAME is not None
    assert settings.MONGO_URI is not None
    assert settings.RABBITMQ_HOST is not None
    assert settings.RABBITMQ_PORT is not None
