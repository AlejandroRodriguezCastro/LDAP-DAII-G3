import asyncio
from types import SimpleNamespace

import pytest

from app.domain.services.user_service import UserService
from app.domain.services.organization_unit_service import OrganizationUnitService
from app.domain.entities.user import User
from app.domain.entities.organization_unit import OrganizationUnit
from app.domain.entities.roles import Role
from app.handlers.errors.user_exception_handlers import (
    UserNotFoundError,
    UserAlreadyExistsError,
    InvalidUserDataError,
    FailureUserCreationError,
    FailureUserDeletionError,
    UserLockedDownError,
    UserInvalidCredentialsError,
)
from app.handlers.errors.organization_exception_handler import (
    OrganizationNotFoundError,
    OrganizationAlreadyExistsError,
    FailureOrganizationCreationError,
)


class FakeLDAPPort:
    def __init__(self):
        # Internal store to vary behaviors
        self.users = {}
        self.organizations = set()
        self.login_history = {}

    # Organization methods
    async def get_organization_all(self):
        return list(self.organizations)

    async def get_organization_by_name(self, name):
        return name in self.organizations

    async def create_organization(self, org_data: OrganizationUnit):
        self.organizations.add(org_data.name)
        return {'result': 0}

    async def update(self, org_id, org_data: OrganizationUnit):
        # pretend success
        return True

    async def delete_organization(self, org_name: str):
        if org_name in self.organizations:
            self.organizations.remove(org_name)
            return True
        return False

    # User methods
    async def get_all_users(self):
        if not self.users:
            return []
        # return a representation similar to LDAP entries used by the service
        out = []
        for u in self.users.values():
            out.append({
                'uid': [u.username],
                'mail': [u.mail],
                'telephoneNumber': [u.telephone_number],
                'givenName': [u.first_name],
                'sn': [u.last_name],
                'ou': [u.organization],
            })
        return out

    async def get_user_by_attribute(self, attr, value):
        # support simple lookups by mail and uid and ou
        if attr == 'mail':
            u = next((x for x in self.users.values() if x.mail == value), None)
            if not u:
                return None
            return {'uid': SimpleNamespace(value=u.username), 'ou': SimpleNamespace(value=u.organization)}
        if attr == 'uid':
            u = self.users.get(value)
            if not u:
                return None
            return {'uid': SimpleNamespace(value=u.username), 'ou': SimpleNamespace(value=u.organization)}
        if attr == 'ou':
            return value in self.organizations
        return None

    async def create_user(self, user: User):
        # simulate LDAP result structure
        self.users[user.username] = user
        return {'result': 0}

    async def delete_user(self, user_mail: str):
        u = next((k for k, v in self.users.items() if v.mail == user_mail), None)
        if not u:
            return False
        del self.users[u]
        return True

    async def authenticate(self, user_dn: str, password: str):
        # Accept any password that contains 'good'
        return 'good' in password

    async def add_login_record(self, user_dn: str, client_ip: str):
        self.login_history.setdefault(user_dn, []).append({'ip': client_ip})

    async def prune_login_records(self, user_dn: str, keep_last: int):
        if user_dn in self.login_history:
            self.login_history[user_dn] = self.login_history[user_dn][-keep_last:]

    async def is_account_locked(self, user_dn: str):
        # Return False by default (not locked)
        return False

    async def get_login_history(self, dn: str):
        return self.login_history.get(dn, [])

    async def modify_user_data(self, user_dn, new_data):
        return True

    async def modify_user_password(self, user_dn, new_password):
        return True

    async def reset_user_password(self, user_dn, new_password):
        return True


def run(coro):
    # Use asyncio.run which is compatible with Python 3.7+ and
    # avoids RuntimeError on Python 3.12 when there's no current event loop.
    return asyncio.run(coro)


def make_user(first='Alice', last='Smith', mail='alice@example.com', org='UADE'):
    return User(
        username=f"{first[0].lower()}{last.lower()}",
        mail=mail,
        roles=[],
        telephone_number='+12345678901',
        first_name=first,
        last_name=last,
        organization=org,
        password='Password123!'
    )


def test_organization_service_get_all_and_not_found():
    ldap = FakeLDAPPort()
    svc = OrganizationUnitService(ldap)

    # no organizations -> should raise
    with pytest.raises(OrganizationNotFoundError):
        run(svc.get_organization_all())

    # add organization and succeed
    ldap.organizations.add('UADE')
    out = run(svc.get_organization_all())
    assert 'UADE' in out


def test_organization_create_and_delete():
    ldap = FakeLDAPPort()
    svc = OrganizationUnitService(ldap)

    # create when not exists
    org = OrganizationUnit(name='NewOrg')
    out = run(svc.create_organization(org))
    assert out == {'result': 0}

    # create again -> already exists
    with pytest.raises(OrganizationAlreadyExistsError):
        run(svc.create_organization(org))

    # delete present -> success
    res = run(svc.delete_organization('NewOrg'))
    assert res is True

    # delete not present -> raises
    with pytest.raises(OrganizationNotFoundError):
        run(svc.delete_organization('Nope'))


def test_user_service_get_all_and_not_found():
    ldap = FakeLDAPPort()
    svc = UserService(ldap)

    with pytest.raises(UserNotFoundError):
        run(svc.get_all_users())

    # add a user and fetch
    u = make_user()
    ldap.users[u.username] = u
    users = run(svc.get_all_users())
    assert users and users[0].username == u.username


def test_user_service_get_user_and_create_delete(patch_role_service):
    ldap = FakeLDAPPort()
    svc = UserService(ldap)

    with pytest.raises(UserNotFoundError):
        run(svc.get_user(user_mail='missing@example.com'))

    # create user flow
    ldap.organizations.add('UADE')
    new = make_user(first='Charlie', last='Delta', mail='charlie@example.com', org='UADE')
    # ensure no email exists
    res = run(svc.create_user(new))
    assert isinstance(res, User)

    # trying to create same email should raise
    dup = make_user(first='Charlie', last='Delta', mail='charlie@example.com', org='UADE')
    with pytest.raises(UserAlreadyExistsError):
        run(svc.create_user(dup))

    # delete existing
    ok = run(svc.delete_user('charlie@example.com'))
    assert ok is None

    # delete missing -> raises
    with pytest.raises(UserNotFoundError):
        run(svc.delete_user('none@example.com'))


def test_user_service_authentication_and_locked():
    ldap = FakeLDAPPort()
    svc = UserService(ldap)

    # setup user
    ldap.organizations.add('UADE')
    u = make_user(first='Donna', last='Echo', mail='donna@example.com', org='UADE')
    ldap.users[u.username] = u

    # missing mail -> raise
    with pytest.raises(UserNotFoundError):
        run(svc.authenticate_user('missing@example.com', 'bad'))

    # invalid credentials
    with pytest.raises(UserInvalidCredentialsError):
        run(svc.authenticate_user('donna@example.com', 'bad'))

    # good credentials -> returns True
    ok = run(svc.authenticate_user('donna@example.com', 'this_is_good_password'))
    assert ok is True


def test_modify_user_data_and_password():
    ldap = FakeLDAPPort()
    svc = UserService(ldap)

    ldap.organizations.add('UADE')
    u = make_user(first='Frank', last='G', mail='frank@example.com', org='UADE')
    ldap.users[u.username] = u

    # modify data success
    new = SimpleNamespace(username=u.username)
    res = run(svc.modify_user_data('frank@example.com', new))
    assert res is new

    # modify password success
    ok = run(svc.change_password('frank@example.com', 'this_is_good_password', 'newpass123'))
    assert ok is True
