
import structlog
import uuid
import jwt
from app.domain.entities.token import Token, TokenValidationRequest
from app.domain.entities.client_credentials import ClientCredentials
from app.domain.services.user_service import UserService
from app.config.settings import settings
from datetime import datetime, timezone, timedelta

now = datetime.now(timezone.utc)

logger = structlog.get_logger()

class TokenService:
    def __init__(self, user_service: UserService):
        self.user_service = user_service

    async def generate_token(self, client_credentials: ClientCredentials) -> Token:
        logger.info("Generating token for client:", client_id=client_credentials.username)
        now = datetime.now(timezone.utc)
        # Add more claims: email, scope, typ
        roles_objects = await self.user_service.get_user_roles(client_credentials.username)
        # Extract role names from Role objects
        roles_names = [role.name for role in roles_objects] if roles_objects else []
        token = Token(
            sub= await self.user_service.get_user(client_credentials.username),
            aud="ldap.com",
            iss="auth_server",
            exp=int((now + settings.token_expiration_timedelta).timestamp()),
            nbf=int(now.timestamp()),
            iat=int(now.timestamp()),
            jti=str(uuid.uuid4()),
            roles=roles_names,
            email=client_credentials.username,
            scope=getattr(client_credentials, "scopes", []),
            typ="access"
        )
        logger.info("Token generated:", token=token)
        return token
    
    def refresh_token(self, token: Token) -> Token:
        logger.info("Refreshing token:", token=token)
        # Dummy refresh logic, replace with real refresh logic
        refreshed_token = Token(
            sub=token.sub,
            aud=token.aud,
            iss=token.iss,
            email=token.email,
            exp=int((now + timedelta(minutes=30)).timestamp()),
            nbf=int(now.timestamp()),
            iat=int(now.timestamp()),
            jti="refreshed_unique_token_id",
            roles=token.roles,
            typ=token.typ,
            scope=token.scope
        )
        logger.info("Token refreshed:", refreshed_token=refreshed_token)
        return refreshed_token
    
    def validate_token(self, token: Token = None, jwt_token: str = None) -> bool:
        """
        Validates a token. You can pass either a Token object (will check claims only),
        or a JWT string (will verify signature and claims).
        """
        logger.info("Validating token:", token=token, jwt_token=jwt_token)
        current_time = datetime.now(timezone.utc).timestamp()
        try:
            if jwt_token:
                # Validate JWT signature and claims
                payload = TokenValidationRequest(jwt_token=jwt_token).decode_jwt()
                logger.info("JWT signature and claims valid", payload=payload)
                return True
            elif token:
                # Validate claims only (no signature)
                if token.exp < current_time:
                    logger.warning("Token has expired:", exp=token.exp, current_time=current_time)
                    return False
                if hasattr(token, 'nbf') and token.nbf > current_time:
                    logger.warning("Token not yet valid:", nbf=token.nbf, current_time=current_time)
                    return False
                if hasattr(token, 'iat') and token.iat > current_time:
                    logger.warning("Token issued in the future:", iat=token.iat, current_time=current_time)
                    return False
                logger.info("Token validation result:", is_valid=True)
                return True
            else:
                logger.error("No token or jwt_token provided for validation")
                return False
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            return False
        except jwt.InvalidTokenError as e:
            logger.warning(f"JWT token is invalid: {e}")
            return False
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            return False
        except jwt.InvalidTokenError as e:
            logger.warning(f"JWT token is invalid: {e}")
            return False