import structlog
from app.domain.entities.user import User
from app.ports.outbound.ldap_port import LDAPPort
from app.handlers.errors.user_exception_handlers import (
    UserNotFoundError,
    UserAlreadyExistsError,
    InvalidUserDataError,
    FailUserCreationError
)


logger = structlog.get_logger()

class UserService:
    def __init__(self, ldap_port: LDAPPort):
        self.ldap_port = ldap_port

    # async def get_user(self, username: str) -> User:
    #     logger.info("Fetching user from LDAP:", username=username)
    #     entry = await self.ldap_port.get_user(username)
    #     if entry is None:
    #         return None  # Let the API layer handle the 404
    #     return User(**entry)

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
            raise FailUserCreationError("Failed to create user in LDAP.", details=str(response))
        return response
