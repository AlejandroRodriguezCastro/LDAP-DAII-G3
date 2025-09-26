# FastAPI endpoint for role creation
from fastapi import APIRouter, HTTPException
import structlog
from app.domain.entities.roles import Role
from app.domain.services.role_service import RoleService
from app.ports.outbound.nonrelationaldb_port import NonRelationalDBPort
from app.config.mongo_settings import connect_db

logger = structlog.get_logger()

router = APIRouter(
    prefix="/roles",
    tags=["roles"]
)

role_service = RoleService(NonRelationalDBPort(non_relational_db=connect_db(), db_name="ldap-roles"))

@router.post("/", response_model=dict)
async def create_role(role: Role):
    logger.info("Received request to create role:", role=role)
    inserted_id = role_service.create_role(role)
    return {"inserted_id": inserted_id}

@router.get("/", response_model=dict)
async def get_roles():
    logger.info("Received request to fetch all roles")
    roles = role_service.get_roles()
    return {"roles": roles}

@router.delete("/{role_id}", response_model=dict)
async def delete_role(role_id: str):
    logger.info("Received request to delete role", role_id=role_id)
    deleted_count = role_service.delete_role(role_id)
    return {"deleted_count": deleted_count}


@router.delete("/", response_model=dict)
async def delete_roles_by_name(role_name: str):
	logger.info("Received request to delete roles by name", role_name=role_name)
	deleted_count = role_service.delete_roles_by_name(role_name)
	return {"deleted_count": deleted_count}
    
@router.delete("/filter", response_model=dict)
async def delete_roles(filter: dict):
	logger.info("Received request to delete roles by filter", filter=filter)
	deleted_count = role_service.delete_roles(filter)
	return {"deleted_count": deleted_count}
    