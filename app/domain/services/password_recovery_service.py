import structlog
from datetime import datetime, timezone, timedelta
from app.domain.entities.password_recovery import PasswordRecoveryToken, PasswordRecoveryRequest
from app.ports.outbound.nonrelationaldb_port import NonRelationalDBPort
from app.ports.outbound.email_port import EmailPort
from app.config.settings import settings
from app.handlers.errors.password_recovery_exception_handler import (
    PasswordRecoveryTokenNotFoundError,
    PasswordRecoveryTokenExpiredError,
    PasswordRecoveryTokenAlreadyUsedError,
    PasswordRecoveryEmailFailedError
)
from app.utils.helpers.expiration_parser import parse_expiration

logger = structlog.get_logger(__name__)


class PasswordRecoveryService:
    """Service for managing password recovery flows"""

    def __init__(self, non_relational_db_port: NonRelationalDBPort):
        self.db_port = non_relational_db_port
        self.collection_name = settings.PASSWORD_RECOVERY_COLLECTION_NAME
        self.email_service = EmailPort()
        self.token_expiration = parse_expiration(settings.PASSWORD_RECOVERY_TOKEN_EXPIRATION)

    async def request_password_recovery(self, user_email: str, user_exists: bool = True) -> bool:
        """Create a password recovery token and send email
        
        Args:
            user_email: Email address of the user requesting recovery
            user_exists: Whether the user exists (for security, we don't reveal if user doesn't exist)
            
        Returns:
            bool: True if recovery email was sent successfully
            
        Raises:
            PasswordRecoveryEmailFailedError: If email sending fails
        """
        logger.info("Processing password recovery request", user_email=user_email)

        try:
            # Create recovery token
            now = datetime.now(timezone.utc)
            expires_at = now + self.token_expiration
            
            recovery_token = PasswordRecoveryToken(
                user_email=user_email,
                expires_at=expires_at.isoformat()
            )

            # Save token to database
            token_dict = recovery_token.model_dump()
            token_id = self.db_port.insert_entry(self.collection_name, token_dict)
            
            if not token_id:
                logger.error("Failed to create password recovery token", user_email=user_email)
                raise PasswordRecoveryEmailFailedError("Could not generate recovery token")

            logger.info("Password recovery token created", user_email=user_email, token_id=token_id)

            # Build recovery link
            recovery_link = settings.PASSWORD_RECOVERY_LINK_TEMPLATE.format(token=recovery_token.token)

            # Send email
            email_sent = await self.email_service.send_password_recovery_email(
                recipient_email=user_email,
                recovery_token=recovery_token.token,
                recovery_link=recovery_link
            )

            if not email_sent:
                logger.warning("Failed to send password recovery email", user_email=user_email)
                raise PasswordRecoveryEmailFailedError("Failed to send recovery email. Please try again later.")

            logger.info("Password recovery email sent successfully", user_email=user_email)
            return True

        except PasswordRecoveryEmailFailedError:
            raise
        except Exception as e:
            logger.error("Error in password recovery request", user_email=user_email, error=str(e))
            raise PasswordRecoveryEmailFailedError("An error occurred while processing your recovery request")

    async def validate_recovery_token(self, token: str) -> str:
        """Validate a recovery token and return the associated email
        
        Args:
            token: The recovery token to validate
            
        Returns:
            str: The email address associated with the token
            
        Raises:
            PasswordRecoveryTokenNotFoundError: If token doesn't exist
            PasswordRecoveryTokenExpiredError: If token has expired
            PasswordRecoveryTokenAlreadyUsedError: If token has been used
        """
        logger.info("Validating password recovery token")

        try:
            # Find token in database
            token_doc = self.db_port.find_entry(
                self.collection_name,
                {"token": token}
            )

            if not token_doc:
                logger.warning("Password recovery token not found", token_prefix=token[:8])
                raise PasswordRecoveryTokenNotFoundError("Invalid recovery token")

            # Check if token has been used
            if token_doc.get("is_used", False):
                logger.warning("Password recovery token already used", token_prefix=token[:8])
                raise PasswordRecoveryTokenAlreadyUsedError()

            # Check if token has expired
            expires_at = datetime.fromisoformat(token_doc.get("expires_at"))
            if datetime.now(timezone.utc) > expires_at:
                logger.warning("Password recovery token expired", token_prefix=token[:8])
                raise PasswordRecoveryTokenExpiredError()

            logger.info("Password recovery token validated successfully")
            return token_doc.get("user_email")

        except (PasswordRecoveryTokenNotFoundError, PasswordRecoveryTokenExpiredError, PasswordRecoveryTokenAlreadyUsedError):
            raise
        except Exception as e:
            logger.error("Error validating recovery token", error=str(e))
            raise PasswordRecoveryTokenNotFoundError("Invalid recovery token")

    async def mark_token_as_used(self, token: str) -> bool:
        """Mark a recovery token as used and delete it
        
        Args:
            token: The token to mark as used and delete
            
        Returns:
            bool: True if successful
        """
        try:
            # Delete the token immediately after use (security best practice)
            result = self.db_port.delete_entry(
                self.collection_name,
                {"token": token}
            )
            logger.info("Password recovery token deleted after use", token_prefix=token[:8])
            return result > 0
        except Exception as e:
            logger.error("Error deleting token after use", error=str(e))
            return False

    async def cleanup_expired_tokens(self) -> int:
        """Remove expired recovery tokens from database
        
        Returns:
            int: Number of tokens deleted
        """
        try:
            now = datetime.now(timezone.utc).isoformat()
            # Delete tokens where expires_at < now or is_used = true
            result = self.db_port.delete_many(
                self.collection_name,
                {"$or": [
                    {"expires_at": {"$lt": now}},
                    {"is_used": True}
                ]}
            )
            logger.info("Cleaned up expired/used recovery tokens", deleted_count=result)
            return result
        except Exception as e:
            logger.error("Error cleaning up expired tokens", error=str(e))
            return 0
