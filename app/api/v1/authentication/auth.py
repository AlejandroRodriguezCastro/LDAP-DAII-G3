from fastapi import APIRouter, HTTPException, status, Query, Request
from pydantic import BaseModel
import structlog
from app.config.settings import settings
from app.domain.entities.token import Token, TokenValidationRequest
from app.domain.entities.client_credentials import ClientCredentials
from app.domain.services.user_service import UserService
from app.config.ldap_singleton import get_ldap_port_instance
from app.domain.services.token_service import TokenService

logger = structlog.get_logger()

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)
    
@router.post("/token",  response_model=str, status_code=status.HTTP_200_OK)
async def token(credential: ClientCredentials, request: Request):
    logger.info("Received request to generate token for client:", client_id=credential.username)
    logger.debug("Client credentials received:", client_credentials=credential)
    ldap_port_instance = await get_ldap_port_instance()
    user_service = UserService(ldap_port_instance)
    logger.info("Authenticating user:", username=credential.username, client_ip=request.client.host)
    await user_service.authenticate_user(credential.username, credential.password, client_ip=request.client.host)
    token_service = TokenService(user_service)
    token = await token_service.generate_token(credential)
    return token.to_jwt()
    
@router.get("/test")
async def test_endpoint():    
    logger.info("Received request to authenticate user:", user_dn="user_dn")
    ldap_port_instance = await get_ldap_port_instance()
    user_service = UserService(ldap_port_instance)
    await user_service.authenticate_user("user_dn", "password")
    
@router.post("/validate", status_code=status.HTTP_200_OK)
async def validate_token(request: TokenValidationRequest):
    logger.info("Received request to validate token:", jwt_token=request.jwt_token)
    ldap_port_instance = await get_ldap_port_instance()
    user_service = UserService(ldap_port_instance)
    token_service = TokenService(user_service)
    is_valid = token_service.validate_token(jwt_token=request.jwt_token)
    if not is_valid:
        logger.warning("Token validation failed")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    logger.info("Token validation succeeded")
    return {"detail": "Token is valid"}

@router.get("/login-history", status_code=status.HTTP_200_OK)
async def get_login_history(user_mail: str, limit: int = Query(settings.LOGIN_HISTORY_LIMIT, ge=1, le=100)):
    logger.info("Received request to get login history:", user_mail=user_mail)
    ldap_port_instance = await get_ldap_port_instance()
    user_service = UserService(ldap_port_instance)
    history = await user_service.get_last_logins(user_mail, limit=limit)
    return {"login_history": history}