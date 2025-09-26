from app.domain.entities.roles import Role
from app.ports.outbound.nonrelationaldb_port import NonRelationalDBPort
import structlog
from app.config.settings import settings
from app.handlers.errors.role_exception_handlers import (
    RoleNotFoundError,
    RoleAlreadyExistsError,
    InvalidRoleDataError,
    FailureRoleCreationError,
    FailureRoleDeletionError,
    UnauthorizedRoleError
)

logger = structlog.get_logger(__name__)
class RoleService:
    def __init__(self, non_relational_db_port: NonRelationalDBPort):
        self.non_relational_db_port = non_relational_db_port
        self.collection = settings.ROLES_COLLECTION_NAME
        logger.info("Initialized RoleService")

    def create_role(self, role: Role) -> str:
        role_dict = role.model_dump()
        # Check if role already exists by name (or unique field)
        existing = self.non_relational_db_port.find_entry(self.collection, {"name": role_dict.get("name")})
        if existing:
            logger.warning("Role already exists", role=role_dict)
            raise RoleAlreadyExistsError(f"Role with name '{role_dict.get('name')}' already exists.")
        inserted_id = self.non_relational_db_port.insert_entry(self.collection, role_dict)
        if not inserted_id:
            raise FailureRoleCreationError("Failed to create role.")
        return inserted_id
    
    def get_roles(self) -> list[Role]:
        roles_cursor = self.non_relational_db_port.find_entries(self.collection)
        roles = [Role(**role) for role in roles_cursor]
        if not roles:
            raise RoleNotFoundError("No roles found.")
        return roles

    def delete_role(self, role_id: str) -> int:
        logger.info("Received request to delete role", role_id=role_id)
        deleted_count = self.non_relational_db_port.delete_entry(self.collection, {"id": role_id})
        if deleted_count == 0:
            raise RoleNotFoundError(f"Role with id '{role_id}' not found.")
        return deleted_count
    
    def delete_roles_by_name(self, role_name: str) -> int:
        logger.info("Received request to delete roles by name", role_name=role_name)
        deleted_count = self.non_relational_db_port.delete_entry(self.collection, {"name": role_name})
        if deleted_count == 0:
            raise RoleNotFoundError(f"Role with name '{role_name}' not found.")
        return deleted_count
    
    def delete_roles(self, filter: dict) -> int:
        logger.info("Received request to delete roles by filter", filter=filter)
        deleted_count = self.non_relational_db_port.delete_many(self.collection, filter)
        if deleted_count == 0:
            raise RoleNotFoundError(f"No roles found for filter: {filter}")
        return deleted_count
        
