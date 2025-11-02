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
async def test_create_user_calls_add_entry(ldap_port):
    from app.domain.entities.user import User
    port, controller = ldap_port
    user = User(
        username="jdoe",
        mail="jdoe@example.com",
        telephone_number="+12345678901",
        first_name="John",
        last_name="Doe",
        organization="OrgF2",
        password="ValidPassw0rd!"
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
async def test_get_organization_all_filters_and_dedups(ldap_port):
    port, controller = ldap_port
    # Create FakeEntry-like objects that have entry_attributes_as_dict
    class E:
        def __init__(self, dn, attrs):
            self.entry_dn = dn
            self.entry_attributes_as_dict = attrs

    entries = [
        E("ou=People,dc=ldap,dc=com", {"ou": ["People"]}),
        E("ou=Sales,dc=ldap,dc=com", {"ou": ["Sales"]}),
        E("ou=Sales,dc=ldap,dc=com", {"ou": ["Sales"]}),
        E("ou=policies,dc=ldap,dc=com", {"ou": ["policies"]}),
        E("ou=Engineering,dc=ldap,dc=com", {"ou": ["Engineering"]}),
    ]
    controller.entries = (entries, {})
    out = await port.get_organization_all()
    names = [e["ou"][0] for e in out]
    assert "People" not in names
    assert "policies" not in names
    assert names == ["Sales", "Engineering"]


@pytest.mark.asyncio
async def test_get_all_users_and_login_record_prune_history(ldap_port):
    port, controller = ldap_port

    class E:
        def __init__(self, dn, raw):
            self.entry_dn = dn
            self.entry_attributes_as_dict = raw
            # allow attribute access for loginIP/loginTimestamp
            if "loginIP" in raw:
                self.loginIP = MagicMock(value=raw["loginIP"])
            if "loginTimestamp" in raw:
                self.loginTimestamp = MagicMock(value=raw["loginTimestamp"])

    e1 = E("uid=a,dc=ldap,dc=com", {"uid": ["a"], "mail": ["a@x"]})
    e2 = E("uid=b,dc=ldap,dc=com", {"uid": ["b"], "mail": ["b@x"]})
    controller.entries = ( [e1, e2], {} )
    users = await port.get_all_users()
    assert isinstance(users, list)
    assert users[0]["uid"] == ["a"]

    # add_login_record
    res = await port.add_login_record("uid=a,dc=ldap,dc=com", "1.2.3.4")
    assert res == controller.add_result

    # prune_login_records: create 6 records, keep_last=3 -> delete 3
    recs = [E(f"loginTimestamp=2025010{i}00000Z,uid=a,dc=ldap,dc=com", {"loginTimestamp": f"2025010{i}00000Z"}) for i in range(6)]
    controller.entries = (recs, {})
    controller.deleted = None
    # ensure delete_entry records
    controller.deleted = []
    await port.prune_login_records("uid=a,dc=ldap,dc=com", keep_last=3)
    assert len(controller.deleted) == 3

    # get_login_history
    recs2 = [E("loginTimestamp=20250103000000Z,uid=a,dc=ldap,dc=com", {"loginIP": "1.1.1.1"}),
             E("loginTimestamp=20250102000000Z,uid=a,dc=ldap,dc=com", {"loginIP": "2.2.2.2"})]
    controller.entries = (recs2, {})
    history = await port.get_login_history("uid=a,dc=ldap,dc=com")
    assert history[0]["loginTimestamp"] > history[1]["loginTimestamp"]
    assert history[0]["loginIP"] == "1.1.1.1"


@pytest.mark.asyncio
async def test_modify_reset_create_and_delete_organization(ldap_port):
    port, controller = ldap_port
    from app.domain.entities.user import User

    user = User(
        username="jdoe",
        mail="jdoe@example.com",
        telephone_number="+12345678901",
        first_name="John",
        last_name="Doe",
        organization="Sales",
        password="ValidPassw0rd!"
    )
    # modify_user_data
    user_dn = {"uid": MagicMock(value="jdoe"), "ou": MagicMock(value="Sales")}
    res = await port.modify_user_data(user_dn, user)
    assert res is True

    # reset_user_password
    res2 = await port.reset_user_password("uid=jdoe,dc=ldap,dc=com", "N3wP@ssw0rd")
    assert res2 is True

    # create_organization
    class Org:
        def __init__(self, name):
            self.name = name
    org = Org("NewOrg")
    res3 = await port.create_organization(org)
    assert res3 == controller.add_result

    # get_organization_by_name
    e = MagicMock()
    controller.entries = [e]
    out = await port.get_organization_by_name("NewOrg")
    assert out is e

    # delete_organization
    e_child = MagicMock()
    e_child.entry_dn = "cn=user,ou=NewOrg,dc=ldap,dc=com"
    e_base = MagicMock()
    e_base.entry_dn = "ou=NewOrg,dc=ldap,dc=com"
    controller.entries = ( [e_child, e_base], {} )
    controller.deleted = []
    res4 = await port.delete_organization("NewOrg")
    assert res4 is True
    assert controller.deleted[0] == e_child.entry_dn
    assert controller.deleted[-1] == e_base.entry_dn
