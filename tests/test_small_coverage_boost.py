import sys
import types
import asyncio
from types import SimpleNamespace

import pytest


async def _call_async(coro):
    return await coro


def test_ldap_singleton_creates_and_returns_same_instance(monkeypatch):
    # Prepare fake modules that the singleton imports lazily
    openldap_mod = types.ModuleType("app.controllers.OpenLDAP.openldap_controller")

    class OpenLDAPController:
        def __repr__(self):
            return "<OpenLDAPController fake>"

    openldap_mod.OpenLDAPController = OpenLDAPController
    sys.modules["app.controllers.OpenLDAP.openldap_controller"] = openldap_mod

    ldap_port_mod = types.ModuleType("app.ports.outbound.ldap_port")

    class LDAPPort:
        def __init__(self, controller):
            self.controller = controller

        def __repr__(self):
            return f"<LDAPPort controller={self.controller}>"

    ldap_port_mod.LDAPPort = LDAPPort
    sys.modules["app.ports.outbound.ldap_port"] = ldap_port_mod

    # Import the function under test and ensure the singleton is created
    from app.config import ldap_singleton

    # Ensure starting state
    ldap_singleton.ldap_port_instance = None

    inst = asyncio.run(ldap_singleton.get_ldap_port_instance())
    assert isinstance(inst, LDAPPort)

    # Second call must return the same instance
    inst2 = asyncio.run(ldap_singleton.get_ldap_port_instance())
    assert inst is inst2


def test_auth_routes_with_patched_services(monkeypatch):
    # Patch get_ldap_port_instance to avoid heavy imports
    async def fake_get_ldap():
        return object()

    monkeypatch.setattr(
        "app.api.v1.authentication.auth.get_ldap_port_instance",
        fake_get_ldap,
        raising=False,
    )

    # Create lightweight fake UserService/TokenService to exercise route logic
    class FakeUserService:
        def __init__(self, ldap):
            self.ldap = ldap

        async def authenticate_user(self, username, password, client_ip=None):
            return True

        async def get_last_logins(self, mail, limit=5):
            return ["2020-01-01T00:00:00Z"] * limit

    class FakeTokenService:
        def __init__(self, user_service):
            self.user_service = user_service

        async def generate_token(self, credential):
            class FakeToken:
                def to_jwt(self):
                    return "fake.jwt.token"

            return FakeToken()

        def validate_token(self, jwt_token=None, token=None):
            return True

    # Patch classes in the module under test
    monkeypatch.setattr(
        "app.api.v1.authentication.auth.UserService", FakeUserService, raising=False
    )
    monkeypatch.setattr(
        "app.api.v1.authentication.auth.TokenService", FakeTokenService, raising=False
    )

    # Import the module and call the handler functions directly
    from app.api.v1.authentication import auth as auth_module
    from app.domain.entities.client_credentials import ClientCredentials
    from app.domain.entities.token import TokenValidationRequest

    # Build fake request object with client.host attribute
    fake_request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"))

    cred = ClientCredentials(username="user@example.com", password="pass")

    token_result = asyncio.run(auth_module.token(cred, fake_request))
    assert token_result == "fake.jwt.token"

    # Validate token
    validate_req = TokenValidationRequest(jwt_token="fake.jwt.token")
    validate_resp = asyncio.run(auth_module.validate_token(validate_req))
    assert validate_resp == {"detail": "Token is valid"}

    # get_login_history should return login_history shaped response
    history_resp = asyncio.run(auth_module.get_login_history("user@example.com", limit=2))
    assert isinstance(history_resp, dict)
    assert "login_history" in history_resp


def test_rabbitmq_event_publisher_functions(monkeypatch):
    """Test RabbitMQ event publisher functions."""
    from app.handlers.rabbitmq_event_publisher import (
        publish_ldap_event,
        publish_authentication_event,
        publish_user_operation_event,
        publish_organization_operation_event,
        publish_role_operation_event,
        publish_error_event
    )

    # Mock get_rabbitmq_port_instance to avoid actual RabbitMQ calls
    class FakeRabbitMQPort:
        async def publish_message(self, message_body):
            return True

        async def publish_log_message(self, log_level, message, source, **kwargs):
            return True

        async def publish_audit_log(self, action, user, resource, status, **kwargs):
            return True

    async def fake_get_rabbitmq():
        return FakeRabbitMQPort()

    monkeypatch.setattr(
        "app.handlers.rabbitmq_event_publisher.get_rabbitmq_port_instance",
        fake_get_rabbitmq,
        raising=False,
    )

    # Test publish_ldap_event
    result = asyncio.run(publish_ldap_event("user.created", {"username": "test"}))
    assert result is True

    # Test publish_authentication_event success
    result = asyncio.run(
        publish_authentication_event("SUCCESS", username="test", user_id="123")
    )
    assert result is True

    # Test publish_authentication_event failure
    result = asyncio.run(
        publish_authentication_event(
            "FAILURE", username="test", error_reason="Invalid password"
        )
    )
    assert result is True

    # Test publish_user_operation_event
    result = asyncio.run(
        publish_user_operation_event("CREATE", "testuser", "SUCCESS", "admin")
    )
    assert result is True

    # Test publish_organization_operation_event
    result = asyncio.run(
        publish_organization_operation_event("CREATE", "TestOrg", "SUCCESS", "admin")
    )
    assert result is True

    # Test publish_role_operation_event
    result = asyncio.run(
        publish_role_operation_event("CREATE", "TestRole", "SUCCESS", "admin")
    )
    assert result is True

    # Test publish_error_event
    result = asyncio.run(
        publish_error_event("ValidationError", "Invalid input", context={"field": "email"})
    )
    assert result is True


def test_rabbitmq_port_message_publishing(monkeypatch):
    """Test RabbitMQPort message publishing methods."""
    from app.ports.outbound.rabbitmq_port import RabbitMQPort

    class FakeExchange:
        async def publish(self, message, routing_key):
            return True

    class FakeSingleton:
        async def connect(self):
            pass

        async def get_exchange(self):
            return FakeExchange()

    port = RabbitMQPort(FakeSingleton())

    # Test publish_message
    result = asyncio.run(port.publish_message({"key": "value"}))
    assert result is True

    # Test publish_log_message
    result = asyncio.run(
        port.publish_log_message("INFO", "Test message", "TEST_SOURCE")
    )
    assert result is True

    # Test publish_audit_log
    result = asyncio.run(
        port.publish_audit_log("CREATE_USER", "admin", "user:test", "SUCCESS")
    )
    assert result is True
