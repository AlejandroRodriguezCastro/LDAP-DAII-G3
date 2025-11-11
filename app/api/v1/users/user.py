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
async def get_user(user_id: str | None = Query(default=None), username: str | None = Query(default=None), user_mail: str | None = Query(default=None)):
    if user_id is None and username is None and user_mail is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either user_id, username or user_mail query parameter is required"
        )
    ldap_port_instance = await get_ldap_port_instance()
    logger.info("Using LDAPPort singleton instance:", instance=ldap_port_instance)
    user_service = UserService(ldap_port_instance)
    user = await user_service.get_user(user_id=user_id, username=username, user_mail=user_mail)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Build User object from LDAP data
    def get_value(field):
        """Helper to extract value from LDAP field (handles LDAP Attribute objects, dicts, and strings)"""
        if field is None:
            return None
        if isinstance(field, str):
            return field
        # Handle LDAP Attribute objects - they may have a value property or be convertible to string
        if hasattr(field, 'value'):
            return field.value
        # Handle cases where the object itself is the value when converted to string
        field_str = str(field)
        # Extract value from "uid: arodriguez" format
        if ': ' in field_str:
            return field_str.split(': ', 1)[1]
        return field_str
    
    def safe_get(obj, key, default=None):
        """Safely get attribute from LDAP Entry or dict-like object"""
        try:
            value = obj.get(key, default) if hasattr(obj, 'get') else getattr(obj, key, default)
            return value if value else default
        except Exception:
            return default
    
    cn_value = get_value(safe_get(user, "cn", "")) or ""
    sn_value = get_value(safe_get(user, "sn", "")) or ""
    # Derive first name by removing last name from CN; fallback to first token of CN
    if cn_value and sn_value and sn_value in cn_value:
        if cn_value.endswith(sn_value):
            first_name = cn_value[: len(cn_value) - len(sn_value)].strip().rstrip(",")
        else:
            first_name = cn_value.replace(sn_value, "").strip()
    else:
        first_name = cn_value.split()[0] if cn_value else ""

    # Determine organisation value early so we can populate Role objects if needed
    organization_val = get_value(safe_get(user, "ou", "")) or ""

    roles = await user_service.get_user_roles(user_mail=user_mail)
    # Normalize roles into Role-compatible dicts/instances so Pydantic can validate
    normalized_roles = []
    if roles:
        for role in roles:
            # If already a Role model instance, keep as-is
            if hasattr(role, "model_dump"):
                normalized_roles.append(role)
            # If it's a dict from DB/service, ensure required 'organization' field exists
            elif isinstance(role, dict):
                if not role.get("organization"):
                    role["organization"] = organization_val
                normalized_roles.append(role)
            # If it's just a role name (string), create a minimal Role dict
            elif isinstance(role, str):
                normalized_roles.append({"name": role, "organization": organization_val})
            else:
                # Fallback: coerce to string name
                normalized_roles.append({"name": str(role), "organization": organization_val})
    roles = normalized_roles

    return User(
        username=get_value(safe_get(user, "uid", "")),
        mail=get_value(safe_get(user, "mail", "")),
        telephone_number=get_value(safe_get(user, "telephoneNumber", "")),
        first_name=first_name,
        last_name=get_value(safe_get(user, "sn", "")),
        organization=get_value(safe_get(user, "ou", "")),
        roles=roles,
        password="asd324ewrf!@#QWEqwe"  # Placeholder
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

@router.get("/by-organization/{org_unit_name}", response_model=list[User])
async def get_users_by_organization(org_unit_name: str):
    logger.info("Received request to fetch users by organization:", org_unit_name=org_unit_name)
    ldap_port_instance = await get_ldap_port_instance()
    user_service = UserService(ldap_port_instance)
    users = await user_service.get_users_by_organization(org_unit_name)
    return users

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