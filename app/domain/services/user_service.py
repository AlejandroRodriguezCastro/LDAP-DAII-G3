import structlog
from app.domain.entities.user import User
from app.ports.outbound.ldap_port import LDAPPort
from app.handlers.errors.user_exception_handlers import (
    UserNotFoundError,
    UserAlreadyExistsError,
    InvalidUserDataError,
)


logger = structlog.get_logger()

class UserService:
    def __init__(self, ldap_port: LDAPPort):
        self.ldap_port = ldap_port

    async def get_user(self, username: str) -> User:
        logger.info("Fetching user from LDAP:", username=username)
        entry = await self.ldap_port.get_user(username)
        if entry is None:
            return None  # Let the API layer handle the 404
        return User(**entry)

    async def dummy_service_method(self):
        logger.info("Calling dummy service method")
        return await self.ldap_port.dummy_method()
    
    async def create_user(self, user_data: User) -> User:
        logger.info("Creating user in LDAP:", username=user_data)
        await self.ldap_port.create_user("jdoe")
    
    async def create_user2(self, user: str):
        logger.info("Creating user in LDAP:", username=user)
        check_email = await self.ldap_port.check_if_mail_exists("jdoe@example.com")
        logger.info("Mail existence check result:", exists=check_email)
        
        if not check_email:
            await self.ldap_port.create_user2(user)
        else:
            logger.info("Email already exists. User not created.")
            raise UserAlreadyExistsError(user)
