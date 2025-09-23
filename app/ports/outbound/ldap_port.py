from random import randint, random
import structlog
from app.controllers.ldap_base_controller import LDAPBaseController
from app.domain.entities.user import User
from random import randint

logger = structlog.get_logger()

class LDAPPort:
    def __init__(self, ldap_controller: LDAPBaseController):
        self.ldap_controller = ldap_controller
        logger.info("Initializing LDAPPort with controller:", controller=ldap_controller)
        if not isinstance(ldap_controller, LDAPBaseController):
            raise ValueError("ldap_controller must be an instance of  LDAPBaseController")
    
    async def create_user_to_delete(self, user: str):
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
        
    async def create_user(self, user: User):
        logger.info("LDAPPort: Creating user")
        self.ldap_controller.connect()        

        dn = f"uid={user.username},ou={user.organization},dc=ldap,dc=com"

        response = self.ldap_controller.add_entry(
            dn,
            {
            "objectClass": ["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount"],
            "cn": f"{user.first_name} {user.last_name}",
            "sn": user.last_name,
            "uid": user.username,
            "mail": user.mail,
            "telephoneNumber": user.telephone_number,
            "postalAddress": "123 Main St, Anytown, USA",
            "uidNumber": str(randint(10000, 20000)),
            "gidNumber": str(randint(20000, 30000)),
            "ou": f"{user.organization}",
            "homeDirectory": f"/home/{user.username}",
            "loginShell": "/bin/bash"
            },
            user.password
        )
        self.ldap_controller.disconnect()
        return response
   
    async def get_user_by_attribute(self, attr: str, value: str):
        logger.info("LDAPPort: Getting user by attribute", attr=attr)
        self.ldap_controller.connect()
        base_dn = "dc=ldap,dc=com" 
        search_filter = f"({attr}={value})"
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
    
    async def delete_user(self, user_mail: str):
        logger.info("LDAPPort: Deleting user by mail", mail=user_mail)
        self.ldap_controller.connect()
        base_dn = "dc=ldap,dc=com" 
        search_filter = f"(mail={user_mail})"
        result = self.ldap_controller.search(base_dn, search_filter, scope="SUBTREE")
        if isinstance(result, tuple):
            result = result[0]
        if isinstance(result, list) and result:
            dn = result[0].entry_dn
            self.ldap_controller.delete_entry(dn)
            logger.info("User deleted:", dn=dn)
        else:
            logger.info("User not found for deletion:", mail=user_mail)
        self.ldap_controller.disconnect()
        return True
        
    async def get_orgs(self):
        pass
    
    async def dummy_method(self):
        print("This is a dummy method in LDAPPort")
        return "This is a dummy method in LDAPPort"

