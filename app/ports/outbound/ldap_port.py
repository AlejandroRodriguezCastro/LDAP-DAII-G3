from random import randint, random
import structlog
from app.controllers.ldap_base_controller import LDAPBaseController
from app.domain.entities.user import User

logger = structlog.get_logger()

class LDAPPort:
    def __init__(self, ldap_controller: LDAPBaseController):
        self.ldap_controller = ldap_controller
        logger.info("Initializing LDAPPort with controller:", controller=ldap_controller)
        if not isinstance(ldap_controller, LDAPBaseController):
            raise ValueError("ldap_controller must be an instance of  LDAPBaseController")
    
    async def create_user(self, user: str):
        logger.info("LDAPPort: Creating user")
        self.ldap_controller.connect()
        
        # dn = f"uid=jdoe,ou=People,ou=ldap,dc=com"
        dn = "uid=jdoe3,ou=OrgF2,dc=ldap,dc=com"

        organizations = ["OrgA2", "OrgB2", "OrgC2", "OrgD2", "OrgE2", "OrgF2"]
        # for org in organizations:
        #     logger.info("Creating organizational units if not exist:", organization=org)
        #     dn_org = f"ou={org},dc=ldap,dc=com"
        #     self.ldap_controller.add_entry(dn_org, {"objectClass": ["organizationalUnit"]})
        #     dn_people = f"ou=People,ou={org},dc=ldap,dc=com"
        #     self.ldap_controller.add_entry(dn_people, {"objectClass": ["organizationalUnit"]})
        #     self.ldap_controller.add_entry(dn_org, {"objectClass": ["top", "posixGroup"], "cn": f"{org}-group", "gidNumber": str(randint(5000, 6000))})

        # dn_group = f"cn=OrgF-group,ou=OrgF,dc=ldap,dc=com"
        # response = self.ldap_controller.search(dn_group, search_filter="(objectClass=posixGroup)", attributes=["gidNumber"])
        # logger.info("Group search response:", response=response)
        # if response and len(response) > 0:
        #     gid = response[0].gidNumber.value
        #     logger.info("Group already exists:", group=dn_group, gid=gid)
        # else:
        #     gid = None

        response = await self.ldap_controller.add_entry(
            dn,
            {
                "objectClass": ["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount"],
                "cn": "John Doe 3",
                "sn": "Doe 3",
                "uid": "jdoe3",
                "mail": "jdoe@example.com",
                "userPassword": "password123",
                "telephoneNumber": "123-456-7890",
                "postalAddress": "123 Main St, Anytown, USA",
                "uidNumber": "10001",
                "gidNumber": "1253425",
                "ou": "OrgF2",
                "homeDirectory": "/home/jdoe",
                "loginShell": "/bin/bash"
            }

        )
        # self.ldap_controller.add_entry((
        #     f"cn={user.username},ou=users,dc=example,dc=com",
        #     {"objectClass": ["top", "person"], "sn": user.last_name, "cn": user.username}
        # ))
        
        
        self.ldap_controller.disconnect()    
    
    async def get_user(self, username: str):
        logger.info("LDAPPort: Getting user")
        logger.info("Fetching user from LDAP:", username=username)
        self.ldap_controller.connect()
        base_dn = "ou=users,dc=example,dc=com"  # Change as needed
        search_filter = f"(uid={username})"
        result = self.ldap_controller.search(base_dn, search_filter, scope="SUBTREE")
        self.ldap_controller.disconnect()
        # If result is a tuple, get the first element
        if isinstance(result, tuple):
            result = result[0]
        # If result is a list, get the first dict
        if isinstance(result, list):
            if result:
                entry = result[0]
            else:
                entry = None
        else:
            entry = result
        return entry
    
    async def create_user2(self, user: User):
        logger.info("LDAPPort: Creating user")
        self.ldap_controller.connect()        
        
        dn = f"uid=jdoe3,ou=OrgF2,dc=ldap,dc=com"
        
        response = await self.ldap_controller.add_entry(
            dn,
            {
                "objectClass": ["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount"],
                "cn": "John Doe 3",
                "sn": "Doe 3",
                "uid": "jdoe3",
                "mail": "jdoe@example.com",
                "userPassword": "password123",
                "telephoneNumber": "123-456-7890",
                "postalAddress": "123 Main St, Anytown, USA",
                "uidNumber": "10001",
                "gidNumber": "1253425",
                "ou": "OrgF2",
                "homeDirectory": "/home/jdoe",
                "loginShell": "/bin/bash"
            }

        )
        
    async def check_if_mail_exists(self, mail: str):
        logger.info("LDAPPort: Checking if mail exists")
        self.ldap_controller.connect()
        base_dn = "ou=People,dc=ldap,dc=com"  # Change as needed
        search_filter = f"(mail={mail})"
        result = self.ldap_controller.search(base_dn, search_filter, scope="SUBTREE")
        self.ldap_controller.disconnect()
        # If result is a tuple, get the first element
        if isinstance(result, tuple):
            result = result[0]
        # If result is a list, get the first dict
        if isinstance(result, list):
            if result:
                entry = result[0]
            else:
                entry = None
        else:
            entry = result
        return entry is not None
    
    async def dummy_method(self):
        print("This is a dummy method in LDAPPort")
        return "This is a dummy method in LDAPPort"

