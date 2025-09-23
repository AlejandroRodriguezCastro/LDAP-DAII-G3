from ldap3 import Server, Connection, ALL, HASHED_SALTED_SHA, MODIFY_ADD
from ldap3.utils.hashed import hashed
import structlog
from app.controllers.ldap_base_controller import LDAPBaseController
from app.config.settings import settings

logger = structlog.get_logger()

class OpenLDAPController(LDAPBaseController):
    def check_connection(self):
        logger.debug("Checking LDAP connection...")
        self.connect()
        is_connected = self.conn.bound
        self.disconnect()
        logger.debug("LDAP connection status: %s", is_connected)
        return is_connected

    def connect(self):
        # Implement connection logic
        logger.debug("Connecting to LDAP server...")
        self.server = Server(settings.LDAP_URL)
        self.conn = Connection(self.server, user=settings.LDAP_BIND_DN, password=settings.LDAP_BIND_PASSWORD)
        self.conn.bind()
        logger.debug("LDAP connection established.")

    def disconnect(self):
        # Implement disconnection logic
        self.conn.unbind()
        logger.debug("LDAP connection closed.")

    def search(self, search_base='', search_filter='', scope='BASE', attributes=['*']):
        logger.debug("Searching LDAP controller:", search_base=search_base, search_filter=search_filter, scope=scope)
        self.conn.search(search_base=search_base, search_filter=search_filter, search_scope=scope, attributes=attributes)
        return self.conn.entries, self.conn.result

    def add_entry(self, dn: str, attributes: dict, password: str = None):
        # Implement add entry logic
        logger.debug("Adding LDAP entry:", dn=dn, attributes=attributes)
        if password:
            logger.debug("Hashing password for LDAP entry")
            attributes['userPassword'] = hashed(HASHED_SALTED_SHA, password)
        self.conn.add(dn, attributes=attributes)
        return self.conn.result

    def modify_entry(self, dn: str, attributes: dict, operation=MODIFY_ADD):
        # Implement modify entry logic
        changes = {
            attr: [(operation, [val] if not isinstance(val, list) else val)]
            for attr, val in attributes.items()
        }
        self.conn.modify(dn, changes=changes)

    def delete_entry(self, dn: str):
        # Implement delete entry logic
        self.conn.delete(dn)

    def get_entry(self, dn: str):
        # Implement get entry logic
        self.conn.search(dn, '(objectClass=*)')
        return self.conn.entries
    
    def check_connection(self):
        return self.conn.bound