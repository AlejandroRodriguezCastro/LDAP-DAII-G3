from random import randint
import datetime
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
        
        logger.debug("Search result get user by attribute:", result=result)
        logger.debug("Type of result:", type=type(result))
        if isinstance(result, tuple):
            result = result[0]
        # If result is a list, get the first dict
        logger.debug("Processed result after tuple check:", result=result)
        logger.debug("Type of processed result:", type=type(result))
        if isinstance(result, list):
            if result:
                entry = result[0]
            else:
                entry = None
        else:
            entry = result
        return entry
    
    
    async def update_user(self, user: User):
        logger.info("LDAPPort: Updating user", username=user.username)
        self.ldap_controller.connect()
        dn = f"uid={user.username},ou={user.organization},dc=ldap,dc=com"
        changes = {
            "cn": user.first_name + " " + user.last_name,
            "sn": user.last_name,
            "mail": user.mail,
            "telephoneNumber": user.telephone_number,
            # Add other attributes as needed
        }
        self.ldap_controller.modify_entry(dn, changes)
        self.ldap_controller.disconnect()
        return True
    
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

    async def is_first_login(self, user_dn: str) -> bool:
        logger.info("LDAPPort: Checking if first login for user", user_dn=user_dn)
        self.ldap_controller.connect()
        result = self.ldap_controller.search(
            search_base=user_dn,
            search_filter="(objectClass=*)",
            scope="BASE",
            attributes=["loginCount"]
        )
        self.ldap_controller.disconnect()
        entries = result[0] if isinstance(result, tuple) else result
        if entries and hasattr(entries[0], "loginCount"):
            login_count = entries[0].loginCount.value
            logger.info("Login count found:", user_dn=user_dn, login_count=login_count)
            return int(login_count) == 0
        logger.info("No loginCount attribute found, assuming first login:", user_dn=user_dn)
        return True  # If attribute not found, assume first login

    async def authenticate(self, user_dn: str, password: str) -> bool:
        logger.info("LDAPPort: Authenticating user", user_dn=user_dn)
        self.ldap_controller.connect()
        is_authenticated = self.ldap_controller.authenticate(user_dn, password)
        self.ldap_controller.disconnect()
        return is_authenticated

    async def is_account_locked(self, user_dn: str) -> bool:
        """
        Returns the value of pwdAccountLockedTime if the account is locked, otherwise None.
        """
        self.ldap_controller.connect()
        result = self.ldap_controller.search(
            search_base=user_dn,
            search_filter="(objectClass=*)",
            scope="BASE",
            attributes=["pwdAccountLockedTime"]
        )
        self.ldap_controller.disconnect()
        entries = result[0] if isinstance(result, tuple) else result
        if entries and hasattr(entries[0], "pwdAccountLockedTime"):
            # Return the value as a string (may be a list or single value)
            lock_time = entries[0].pwdAccountLockedTime.value
            return lock_time
        return None
    
    async def dummy_method(self):
        print("This is a dummy method in LDAPPort")
        return "This is a dummy method in LDAPPort"

    async def modify_user_data(self, user_dn, user: User):
        logger.info("LDAPPort: Modifying user data", username=user_dn['uid'].value)
        logger.debug("User data to modify:", user=user)
        self.ldap_controller.connect()
        dn = f"uid={user_dn['uid'].value},ou={user_dn['ou'].value},dc=ldap,dc=com"
        logger.debug("Modifying user DN:", dn=dn)
        changes = {
            "cn": user.first_name + " " + user.last_name,
            "sn": user.last_name,
            "mail": user.mail,
            "telephoneNumber": user.telephone_number,
            # Add other attributes as needed
        }
        logger.debug("Changes to apply:", changes=changes)
        self.ldap_controller.modify_entry(dn, changes, operation=self.ldap_controller.MODIFY_REPLACE)
        self.ldap_controller.disconnect()
        return True
    
    async def reset_user_password(self, user_dn: str, new_password: str):
        logger.info("LDAPPort: Resetting user password", user_dn=user_dn)
        self.ldap_controller.connect()
        changes = {
            "userPassword": new_password
        }
        self.ldap_controller.modify_entry(user_dn, changes, operation=self.ldap_controller.MODIFY_REPLACE)
        self.ldap_controller.disconnect()
        return True
    
    async def get_all_users(self):
        logger.info("LDAPPort: Getting all users")
        self.ldap_controller.connect()
        base_dn = "dc=ldap,dc=com" 
        search_filter = "(objectClass=inetOrgPerson)"
        result = self.ldap_controller.search(base_dn, search_filter, scope="SUBTREE", attributes=["*"])
        self.ldap_controller.disconnect()
        
        logger.debug("Search result get all users:", result=result)
        logger.debug("Type of result:", type(type(result)))
        if isinstance(result, tuple):
            result = result[0]
        # If result is a list, return it directly
        logger.debug("Processed result after tuple check:", result=result)
        logger.debug("Type of processed result:", type(type(result)))
        if isinstance(result, list):
            return [entry.entry_attributes_as_dict for entry in result]
        else:
            return []

    async def add_login_record(self, user_dn: str, ip: str):
        logger.info("LDAPPort: Adding login record", user_dn=user_dn, ip=ip)
        now = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%SZ")
        self.ldap_controller.connect()
        record_dn = f"loginTimestamp={now},{user_dn}"

        attributes = {
            "objectClass": ["top", "loginRecord"],
            "loginIP": ip,
            "loginTimestamp": now
        }

        result = self.ldap_controller.add_entry(record_dn, attributes)
        self.ldap_controller.disconnect()
        return result
    
    async def prune_login_records(self, user_dn: str, keep_last: int = 5):
        self.ldap_controller.connect()
        search_filter = "(objectClass=loginRecord)"
        result, _ = self.ldap_controller.search(
            search_base=user_dn,
            search_filter=search_filter,
            scope="ONELEVEL",
            attributes=["loginTimestamp"]
        )
        records = sorted(result, key=lambda e: e.loginTimestamp.value, reverse=True)

        for old in records[keep_last:]:
            self.ldap_controller.delete_entry(old.entry_dn)

        self.ldap_controller.disconnect()
        
    async def get_login_history(self, user_dn: str) -> list[dict]:
        logger.info("LDAPPort: Fetching login history", user_dn=user_dn)
        self.ldap_controller.connect()
        result, _ = self.ldap_controller.search(
            search_base=user_dn,
            search_filter="(objectClass=loginRecord)",
            scope="ONELEVEL",
            attributes=["loginIP"]
        )
        logger.debug("Login history search result:", result=result)
        self.ldap_controller.disconnect()

        if not result:
            return []

        history = []
        for rec in result:
            # Extract timestamp from DN
            dn_parts = rec.entry_dn.split(",")[0]  # e.g. "loginTimestamp=20250930031034Z"
            ts = dn_parts.split("=")[1]

            history.append({
                "loginTimestamp": ts,
                "loginIP": rec.loginIP.value if "loginIP" in rec else None
            })

        # Sort newest first
        history.sort(key=lambda x: x["loginTimestamp"], reverse=True)

        logger.debug("Formatted login history:", history=history)
        return history
