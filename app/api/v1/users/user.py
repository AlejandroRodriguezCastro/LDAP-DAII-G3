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


@router.get("/get-user", response_model=User)
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

@router.post("/", response_model=User, status_code=status.HTTP_201_CREATED)
async def create_user(user: User):
    logger.info("Received request to create user:", user=user)
    ldap_port_instance = await get_ldap_port_instance()
    user_service = UserService(ldap_port_instance)
    created_user = await user_service.create_user(user)
    return created_user

@router.delete("/{user_mail}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_mail: str):
    logger.info("Received request to delete user:", user_mail=user_mail)
    ldap_port_instance = await get_ldap_port_instance()
    user_service = UserService(ldap_port_instance)
    await user_service.delete_user(user_mail)

@router.put("/{user_mail}", response_model=User)
async def update_user(user_mail: str, user: User):
    logger.info("Received request to update user:", user_mail=user_mail, user=user)
    ldap_port_instance = await get_ldap_port_instance()
    user_service = UserService(ldap_port_instance)
    updated_user = await user_service.modify_user_data(user_mail, user)
    return updated_user

@router.get("/all", response_model=list[User])
async def get_all_users():
    logger.info("Received request to fetch all users")
    ldap_port_instance = await get_ldap_port_instance()
    user_service = UserService(ldap_port_instance)
    users = await user_service.get_all_users()
    return users

@router.post("/change-password", status_code=status.HTTP_200_OK)
async def change_password(user_mail: str = Query(...), new_password: str = Query(...)):
    logger.info("Received request to change password", user_mail=user_mail)
    ldap_port_instance = await get_ldap_port_instance()
    user_service = UserService(ldap_port_instance)
    success = await user_service.change_password(user_mail, new_password)
    if success:
        return {"message": "Password changed successfully"}
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Failed to change password"
    )