import structlog
from app.config.settings import settings
from app.domain.entities.user import User
from app.ports.outbound.ldap_port import LDAPPort
import datetime
from app.handlers.errors.user_exception_handlers import (
    UserNotFoundError,
    UserAlreadyExistsError,
    InvalidUserDataError,
    FailureUserCreationError,
    FailureUserDeletionError,
    UserLockedDownError,
    UserInvalidCredentialsError
)


logger = structlog.get_logger()

class UserService:
    def __init__(self, ldap_port: LDAPPort):
        self.ldap_port = ldap_port

    async def get_all_users(self) -> list[User]:
        logger.info("Fetching all users from LDAP")
        users_data = await self.ldap_port.get_all_users()
        if not users_data:
            logger.info("No users found in LDAP")
            raise UserNotFoundError("No users found.")
        users = [User(
            username=user.get('uid', [None])[0],
            mail=user.get('mail', [None])[0],
            telephone_number=user.get('telephoneNumber', [None])[0],
            first_name=user.get('givenName', [None])[0],
            last_name=user.get('sn', [None])[0],
            organization=user.get('ou', [None])[0],
            password=None  # Passwords are not fetched for security reasons
        ) for user in users_data]
        return users
    
    async def get_user(self, user_mail: str) -> str:
        logger.info("Fetching user from LDAP by mail:", user_mail=user_mail)
        user_data = await self.ldap_port.get_user_by_attribute("mail", user_mail)
        if not user_data:
            logger.info("User not found for mail:", mail=user_mail)
            raise UserNotFoundError(user_mail)
        logger.info("User data found for mail:", mail=user_mail, user_data=user_data)
        return user_data['uid'].value if 'uid' in user_data else None
        
    
    async def dummy_service_method(self):
        logger.info("Calling dummy service method")
        return await self.ldap_port.dummy_method()

    async def create_user_to_delete(self, user_data: User) -> User:
        logger.info("Creating user in LDAP:", username=user_data)
        await self.ldap_port.create_user_to_delete("jdoe")
    
    async def create_user(self, user: User) -> User:
        logger.info("Creating user in LDAP:", username=user.mail)
        
        check_email = await self.ldap_port.get_user_by_attribute("mail", f"{user.mail}")
        logger.info("Mail existence check result:", exists=check_email, mail=user.mail)
        
        base_username = f"{user.first_name[0]}{user.last_name.split()[-1]}".lower()
        check_username = await self.ldap_port.get_user_by_attribute("uid", f"{base_username}")
        logger.info("Username existence check result:", exists=check_username, base_username=base_username)
            
        username = f"{base_username}"
        counter = 1
        while check_username:
            username = f"{base_username}{counter}"
            check_username = await self.ldap_port.get_user_by_attribute("uid", username)
            counter += 1
            logger.info("Username existence check result:", exists=check_username)
            
        user.username = username
        logger.info("Final username to be used:", username=user.username)
            
        check_organization = await self.ldap_port.get_user_by_attribute("ou", f"{user.organization}")
        logger.info("Organization existence check result:", exists=check_organization, organization=user.organization)
        
        if check_email:
            logger.info("Email already exists. User not created.")
            raise UserAlreadyExistsError(user)
    
        if not check_organization:
            logger.info("Organization does not exist. User not created.")
            raise InvalidUserDataError("Organization does not exist.")

        response = await self.ldap_port.create_user(user)
        
        logger.info("User creation response from LDAP:", response=response)
        if response.get('result', 1) != 0:
            logger.error("Failed to create user in LDAP:", response=response)
            raise FailureUserCreationError("Failed to create user in LDAP.", details=str(response))
        return user

    async def delete_user(self, user_mail: str):
        logger.info("Deleting user from LDAP:", user_mail=user_mail)
        check_email = await self.ldap_port.get_user_by_attribute("mail", f"{user_mail}")
        logger.info("Mail existence check result:", exists=check_email, mail=user_mail)
        
        if not check_email:
            logger.info("Email does not exist. User not found for deletion.")
            raise UserNotFoundError(user_mail)
        deleted = await self.ldap_port.delete_user(user_mail)
        
        if not deleted:
            logger.error("Failed to delete user in LDAP:", mail=user_mail)
            raise FailureUserDeletionError("Failed to delete user in LDAP.")

    async def authenticate_user(self, user_dn: str, password: str, client_ip: str = None) -> bool:
        logger.info("Searching user by mail for authentication", mail=user_dn)
        user_data = await self.ldap_port.get_user_by_attribute("mail", user_dn)
        if not user_data:
            logger.info("User not found for mail", mail=user_dn)
            raise UserNotFoundError(user_dn)
        logger.info("User data found for mail", mail=user_dn, user_data=user_data)
        
        uid = user_data['uid'].value if user_data['uid'].value else None
        ou = user_data['ou'].value if user_data['ou'].value else None

        if not uid or not ou:
            logger.info("User found but missing uid or ou", user=user_data)
            raise InvalidUserDataError("User record missing uid or ou.")
        
        user_dn = f"uid={uid},ou={ou},dc=ldap,dc=com"
        logger.info("Constructed user_dn for authentication", user_dn=user_dn)

        is_authenticated = await self.ldap_port.authenticate(user_dn, password)
        logger.info("Authentication result:", user_dn=user_dn, is_authenticated=is_authenticated)
        
        if is_authenticated:
            client_ip = client_ip or "unknown"
            await self.ldap_port.add_login_record(user_dn, client_ip)
            await self.ldap_port.prune_login_records(user_dn, keep_last=settings.LOGIN_HISTORY_LIMIT)

        # is_first_login = await self.ldap_port.is_first_login(user_dn)
        # logger.info("Is first login check:", user_dn=user_dn, is_first_login=is_first_login)
        
        is_locked = await self.ldap_port.is_account_locked(user_dn)
        logger.info("Is locked down?", user_dn=user_dn, is_locked=is_locked)
        if is_locked:
            if hasattr(is_locked, "strftime"):
                readable_date = (is_locked + datetime.timedelta(seconds=300)).strftime("%Y-%m-%d %H:%M:%S")
            else:
                try:
                    # Try to parse is_locked as a datetime string
                    dt = datetime.datetime.strptime(str(is_locked), "%Y-%m-%d %H:%M:%S")
                    readable_date = (dt + datetime.timedelta(seconds=300)).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    readable_date = str(is_locked)
            raise UserLockedDownError(user_dn=user_dn, date_until=readable_date)

        if not is_authenticated:
            logger.info("Authentication failed for user", user_dn=user_dn)
            raise UserInvalidCredentialsError("Invalid credentials provided.")
        
        return is_authenticated
    
    async def modify_user_data(self, user_mail: str, new_data: dict):
        logger.info("Modifying user data in LDAP:", mail=user_mail, new_data=new_data)
        user_dn = await self.ldap_port.get_user_by_attribute("mail", f"{user_mail}")
        logger.info("Mail existence check result:", exists=user_dn, mail=user_mail)
        
        if not user_dn:
            logger.info("Email does not exist. User not found for modification.")
            raise UserNotFoundError(user_mail)

        user_exists = user_dn['uid'].value if 'uid' in user_dn else None
        logger.info("User DN fetched for modification:", user_dn=user_exists)
        if not user_exists:
            logger.info("User DN not found in record. Cannot modify user.")
            raise InvalidUserDataError("User DN not found in record.")
        
        modified = await self.ldap_port.modify_user_data(user_dn, new_data)
        if not modified:
            logger.error("Failed to modify user data in LDAP:", mail=user_mail)
            raise FailureUserCreationError("Failed to modify user data in LDAP.")

        # Ensure we return a User instance that matches the API response_model.
        # The incoming `new_data` is expected to be a User model from the route,
        # but make sure the username matches the one in LDAP (uid).

        if hasattr(new_data, 'username') and user_exists:
            new_data.username = user_exists

        return new_data
    
    async def modify_user_password(self, user_mail: str, new_password: str):
        logger.info("Modifying user password in LDAP:", mail=user_mail)
        user_dn = await self.ldap_port.get_user_by_attribute("mail", f"{user_mail}")
        logger.info("Mail existence check result:", exists=user_dn, mail=user_mail)
        
        if not user_dn:
            logger.info("Email does not exist. User not found for password modification.")
            raise UserNotFoundError(user_mail)

        user_exists = user_dn['uid'].value if 'uid' in user_dn else None
        logger.info("User DN fetched for password modification:", user_dn=user_exists)
        if not user_exists:
            logger.info("User DN not found in record. Cannot modify password.")
            raise InvalidUserDataError("User DN not found in record.")
        
        modified = await self.ldap_port.modify_user_password(user_dn, new_password)
        if not modified:
            logger.error("Failed to modify user password in LDAP:", mail=user_mail)
            raise FailureUserCreationError("Failed to modify user password in LDAP.")

        return True
    
    async def get_last_logins(self, user_mail: str, limit: int = 5):
        logger.info("Fetching last login history for user:", mail=user_mail, limit=limit)
        user_dn = await self.ldap_port.get_user_by_attribute("mail", user_mail)
        if not user_dn:
            raise UserNotFoundError(user_mail)

        dn = f"uid={user_dn['uid'].value},ou={user_dn['ou'].value},dc=ldap,dc=com"
        logger.info("Constructed DN for fetching login history:", dn=dn)
        history = await self.ldap_port.get_login_history(dn)
        return history[-limit:]  # last N entries
