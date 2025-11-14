# FastAPI endpoint for role creation
from fastapi import APIRouter, Request
import structlog
from app.config.settings import settings
from app.domain.entities.roles import Role
from app.domain.services.role_service import RoleService
from app.ports.outbound.nonrelationaldb_port import NonRelationalDBPort
from app.config.mongo_settings import connect_db
from app.handlers.authentication.authentication_handler import _require_roles

logger = structlog.get_logger()

router = APIRouter(
    prefix="/roles",
    tags=["roles"]
)

role_service = RoleService(NonRelationalDBPort(non_relational_db=connect_db(), db_name=settings.MONGO_DB_NAME), collection_name=settings.ROLES_COLLECTION_NAME)

@router.post("/", response_model=dict)
async def create_role(role: Role, request: Request):
    logger.info("Received request to create role:", role=role)
    await _require_roles(request, [settings.ADMIN_ROLES[1], settings.SUPER_ADMIN_ROLES[1]])
    inserted_id = role_service.create_role(role)
    return {"inserted_id": inserted_id}

@router.get("/", response_model=dict)
async def get_roles(request: Request):
    logger.info("Received request to fetch all roles")
    await _require_roles(request, [settings.ADMIN_ROLES[0], settings.SUPER_ADMIN_ROLES[0]])
    roles = role_service.get_roles()
    return {"roles": roles}

@router.delete("/{role_id}", response_model=dict)
async def delete_role(role_id: str, request: Request):
    await _require_roles(request, [settings.ADMIN_ROLES[1], settings.SUPER_ADMIN_ROLES[1]])
    logger.info("Received request to delete role", role_id=role_id)
    deleted_count = role_service.delete_role(role_id)
    return {"deleted_count": deleted_count}

@router.get("/organization/{organization_name}", response_model=dict)
async def get_roles_by_organization(organization_name: str, request: Request):
    logger.info("Received request to fetch roles by organization", organization_name=organization_name)
    await _require_roles(request, [settings.ADMIN_ROLES[0], settings.SUPER_ADMIN_ROLES[0]])
    roles = role_service.get_roles_by_organization(organization_name)
    return {"roles": roles}

@router.delete("/", response_model=dict)
async def delete_roles_by_name(role_name: str, request: Request):
    await _require_roles(request, [settings.ADMIN_ROLES[1], settings.SUPER_ADMIN_ROLES[1]])
    logger.info("Received request to delete roles by name", role_name=role_name)
    deleted_count = role_service.delete_roles_by_name(role_name)
    return {"deleted_count": deleted_count}
    
@router.delete("/filter", response_model=dict)
async def delete_roles(filter: dict, request: Request):
    await _require_roles(request, [settings.ADMIN_ROLES[1], settings.SUPER_ADMIN_ROLES[1]])
    logger.info("Received request to delete roles by filter", filter=filter)
    deleted_count = role_service.delete_roles(filter)
    return {"deleted_count": deleted_count}
