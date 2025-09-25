# FastAPI endpoint for role creation
from fastapi import APIRouter, HTTPException
import structlog
from app.domain.entities.roles import Role
from app.domain.services.role_service import RoleService
from app.ports.outbound.mongo_port import MongoPort
from app.config.mongo_settings import connect_db

logger = structlog.get_logger()

router = APIRouter(
    prefix="/roles",
    tags=["roles"]
)

role_service = RoleService(MongoPort(mongo_client=connect_db(), db_name="ldap-roles", collection_name="roles")) ## Change in main and mongo_settings

@router.post("/", response_model=dict)
async def create_role(role: Role):
	try:
		logger.info("Received request to create role:", role=role)
		inserted_id = role_service.create_role(role)
		return {"inserted_id": inserted_id}
	except Exception as e:
		logger.error("Error creating role", exc_info=e)
		raise HTTPException(status_code=500, detail=str(e))

@router.get("/", response_model=dict)
async def get_roles():
	try:
		logger.info("Received request to fetch all roles")
		roles = role_service.get_roles()
		return {"roles": roles}
	except Exception as e:
		logger.error("Error fetching roles", exc_info=e)
		raise HTTPException(status_code=500, detail=str(e))