from fastapi import APIRouter, HTTPException, status, Query
import structlog
from app.domain.services.user_service import UserService
from app.domain.entities.user import User
from app.config.ldap_singleton import get_ldap_port_instance

logger = structlog.get_logger()

router = APIRouter(
    prefix="/user",
    tags=["user"]
)


@router.get("/asd")
async def get_user(user_id: str = Query(None), username: str = Query(None)):
    ldap_port_instance = await get_ldap_port_instance()
    logger.info("Using LDAPPort singleton instance:", instance=ldap_port_instance)
    user_entity = UserService(ldap_port_instance)
    if user_id:
        logger.info("User to fetch by ID:", user=user_id)
        user = user_entity.get_user(user_id)
        logger.info("User fetched by ID:", user=user_id)
    elif username:
        logger.info("User to fetch by username:", username=username)
        user = await user_entity.get_user(username)
        logger.debug("Result from get_user_by_username:", user=user)
        logger.info("User fetched by username:", username=username)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either user_id or username query parameter is required"
        )
    if user:
        return user
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="User not found"
    )

@router.get("/dummy")
async def dummy_endpoint():
    ldap_port_instance = await get_ldap_port_instance()
    logger.info("Using LDAPPort singleton instance:", instance=ldap_port_instance)
    user_service = UserService(ldap_port_instance)
    result = await user_service.create_user("a")
    return {"message": "This is a dummy endpoint", "result": result}

@router.post("/", response_model=User, status_code=status.HTTP_201_CREATED)
async def create_user(user: User):
    logger.info("Received request to create user:", user=user)
    ldap_port_instance = await get_ldap_port_instance()
    user_service = UserService(ldap_port_instance)
    created_user = await user_service.create_user(user)
    return created_user