from fastapi import Request, HTTPException, status
from app.domain.entities.token import TokenValidationRequest
import structlog

logger = structlog.get_logger(__name__)

def _extract_token_from_auth_header(request: Request) -> str:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    logger.debug("Extracting token from Authorization header")
    if not auth:
        logger.warning("Missing Authorization header")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        logger.debug("Token extracted successfully")
        return parts[1]
    if len(parts) == 1:
        return parts[0]
    logger.warning("Invalid Authorization header")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Authorization header")


def _decode_roles_from_jwt(token_str: str) -> list:
    try:
        tv = TokenValidationRequest(jwt_token=token_str)
        payload = tv.decode_jwt()
        roles = payload.get("roles", [])
        return roles or []
    except Exception:
        logger.warning("Failed to decode JWT")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


async def _require_roles(request: Request, allowed_roles: list):
    token_str = _extract_token_from_auth_header(request)
    roles = _decode_roles_from_jwt(token_str)
    if not any(r in roles for r in allowed_roles):
        logger.warning("Forbidden: insufficient roles")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: insufficient roles")