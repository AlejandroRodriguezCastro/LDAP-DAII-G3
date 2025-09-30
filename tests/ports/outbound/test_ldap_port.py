import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock
from app.ports.outbound.ldap_port import LDAPPort
from app.controllers.ldap_base_controller import LDAPBaseController


class FakeEntry:
    """Helper class to simulate LDAP entries."""
    def __init__(self, **attrs):
        for k, v in attrs.items():
            setattr(self, k, MagicMock(value=v))


class FakeLDAPController(LDAPBaseController):
    """Fake implementation of LDAPBaseController for testing."""
    def __init__(self):
        self.connected = False
        self.entries = []
        self.auth_result = True
        self.add_result = {"result": 0}
        self.delete_called_with = None

    def connect(self):
        self.connected = True

    def disconnect(self):
        self.connected = False

    def search(self, search_base=None, search_filter=None, scope=None, attributes=None):
        return self.entries

    def add_entry(self, dn, attributes, password=None):
        return self.add_result

    def modify_entry(self, dn, changes):
        pass

    def delete_entry(self, dn):
        self.delete_called_with = dn
        return True

    def get_entry(self, dn):
        return self.entries

    def check_connection(self):
        return self.connected

    def authenticate(self, user_dn, password):
        return self.auth_result


@pytest_asyncio.fixture
async def ldap_port():
    controller = FakeLDAPController()
    port = LDAPPort(controller)
    return port, controller


@pytest.mark.asyncio
async def test_init_with_valid_controller():
    controller = FakeLDAPController()
    port = LDAPPort(controller)
    assert isinstance(port, LDAPPort)


def test_init_with_invalid_controller():
    with pytest.raises(ValueError):
        LDAPPort(object())


@pytest.mark.asyncio
async def test_create_user_to_delete_calls_add_entry(ldap_port):
    port, controller = ldap_port
    controller.add_result = {"result": 0}
    result = await port.create_user_to_delete("jdoe")
    assert controller.connected is False


@pytest.mark.asyncio
async def test_create_user_calls_add_entry(ldap_port):
    from app.domain.entities.user import User
    port, controller = ldap_port
    user = User(
        username="jdoe",
        mail="jdoe@example.com",
        telephone_number="123",
        first_name="John",
        last_name="Doe",
        organization="OrgF2",
        password="pwd"
    )
    response = await port.create_user(user)
    assert response == controller.add_result


@pytest.mark.asyncio
async def test_get_user_by_attribute_tuple_result(ldap_port):
    port, controller = ldap_port
    controller.entries = ([{"uid": "jdoe"}],)
    result = await port.get_user_by_attribute("uid", "jdoe")
    assert result == [{"uid": "jdoe"}]


@pytest.mark.asyncio
async def test_get_user_by_attribute_list_result(ldap_port):
    port, controller = ldap_port
    controller.entries = [[{"uid": "jdoe"}]]
    result = await port.get_user_by_attribute("uid", "jdoe")
    assert result == {"uid": "jdoe"}


@pytest.mark.asyncio
async def test_get_user_by_attribute_empty_list(ldap_port):
    port, controller = ldap_port
    controller.entries = [[]]
    result = await port.get_user_by_attribute("uid", "notfound")
    assert result is None


@pytest.mark.asyncio
async def test_delete_user_found(ldap_port):
    port, controller = ldap_port
    entry = MagicMock()
    entry.entry_dn = "uid=jdoe,dc=ldap,dc=com"
    controller.entries = [[entry]]
    result = await port.delete_user("jdoe@example.com")
    assert controller.delete_called_with == entry.entry_dn
    assert result is True


@pytest.mark.asyncio
async def test_delete_user_not_found(ldap_port):
    port, controller = ldap_port
    controller.entries = []
    result = await port.delete_user("notfound@example.com")
    assert result is True
    assert controller.delete_called_with is None


@pytest.mark.asyncio
async def test_is_first_login_zero_count(ldap_port):
    port, controller = ldap_port
    entry = FakeEntry(loginCount="0")
    controller.entries = [[entry]]
    result = await port.is_first_login("uid=jdoe")
    assert result is True


@pytest.mark.asyncio
async def test_is_first_login_nonzero_count(ldap_port):
    port, controller = ldap_port
    entry = FakeEntry(loginCount="5")
    controller.entries = [[entry]]
    result = await port.is_first_login("uid=jdoe")
    assert result is False


@pytest.mark.asyncio
async def test_is_first_login_no_attribute(ldap_port):
    port, controller = ldap_port
    controller.entries = [[]]
    result = await port.is_first_login("uid=jdoe")
    assert result is True


@pytest.mark.asyncio
async def test_authenticate_success(ldap_port):
    port, controller = ldap_port
    controller.auth_result = True
    result = await port.authenticate("uid=jdoe", "pwd")
    assert result is True


@pytest.mark.asyncio
async def test_authenticate_failure(ldap_port):
    port, controller = ldap_port
    controller.auth_result = False
    result = await port.authenticate("uid=jdoe", "wrong")
    assert result is False


@pytest.mark.asyncio
async def test_is_account_locked_with_value(ldap_port):
    port, controller = ldap_port
    entry = FakeEntry(pwdAccountLockedTime="2025-01-01")
    controller.entries = [[entry]]
    result = await port.is_account_locked("uid=jdoe")
    assert result == "2025-01-01"


@pytest.mark.asyncio
async def test_is_account_locked_none(ldap_port):
    port, controller = ldap_port
    controller.entries = [[]]
    result = await port.is_account_locked("uid=jdoe")
    assert result is None


@pytest.mark.asyncio
async def test_dummy_method_returns_string(ldap_port):
    port, _ = ldap_port
    result = await port.dummy_method()
    assert result == "This is a dummy method in LDAPPort"
