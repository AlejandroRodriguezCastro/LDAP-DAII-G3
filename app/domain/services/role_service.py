from app.domain.entities.roles import Role
from app.ports.outbound.nonrelationaldb_port import NonRelationalDBPort
# bson is optional in some test environments; import when available to support _id lookups
try:
    from bson import ObjectId
except Exception:  # pragma: no cover - best-effort import for environments without pymongo/bson
    ObjectId = None
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
    def __init__(self, non_relational_db_port: NonRelationalDBPort, collection_name: str ):
        self.non_relational_db_port = non_relational_db_port
        self.collection = collection_name
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
        roles: list[Role] = []
        for role in roles_cursor:
            # Normalize DB document to Role fields
            role_data = {
                "id": str(role.get("_id")) if role.get("_id") is not None else role.get("id"),
                "name": role.get("name"),
                "description": role.get("description", ""),
                "created_at": role.get("created_at", "2024-01-01T00:00:00Z"),
                "updated_at": role.get("updated_at", "2024-01-01T00:00:00Z"),
                # DB used 'organization_unit' in some places — accept that as fallback
                "organization": role.get("organization") or role.get("organization_unit") or role.get("organizationUnit")
            }
            roles.append(Role(**role_data))

        if not roles:
            raise RoleNotFoundError()

        return roles

    def get_roles_by_organization(self, organization: str) -> list[Role]:
        logger.debug("Fetching roles for organization", organization=organization, collection=self.collection)
        query = {"$or": [
            {"organization": organization},
            {"organization_unit": organization},
            {"organizationUnit": organization}
        ]}
        logger.debug("Using organization query", organization=organization, query=query)
        roles_cursor = self.non_relational_db_port.find_entries(self.collection, query)
        logger.debug("Fetched roles for organization", organization=organization, roles_cursor=roles_cursor)
        roles: list[Role] = []
        for role in roles_cursor:
            role_data = {
                "id": str(role.get("_id")) if role.get("_id") is not None else role.get("id"),
                "name": role.get("name"),
                "description": role.get("description", ""),
                "created_at": role.get("created_at", "2024-01-01T00:00:00Z"),
                "updated_at": role.get("updated_at", "2024-01-01T00:00:00Z"),
                "organization": role.get("organization") or role.get("organization_unit") or role.get("organizationUnit")
            }
            roles.append(Role(**role_data))

        if not roles:
            raise RoleNotFoundError(f"No roles found for organization '{organization}'.")

        return roles
    
    def get_roles_by_ids(self, role_ids: list[str]) -> list[Role]:
        """Fetch multiple roles by their IDs.
        
        Args:
            role_ids: List of role IDs to fetch
            
        Returns:
            List of Role objects matching the provided IDs (returns empty list if none found)
        """
        if not role_ids:
            return []
        
        logger.debug("Fetching roles by IDs", role_ids=role_ids, collection=self.collection)
        
        # Build query to match both id field and _id field (handles different storage formats)
        # First try matching by id field, then by _id (MongoDB ObjectId as string)
        id_query = {"id": {"$in": role_ids}}
        objectid_query_list = []
        
        if ObjectId:
            for rid in role_ids:
                try:
                    objectid_query_list.append(ObjectId(rid))
                except Exception:
                    pass
        
        if objectid_query_list:
            query = {"$or": [id_query, {"_id": {"$in": objectid_query_list}}]}
        else:
            query = id_query
        
        roles_cursor = self.non_relational_db_port.find_entries(self.collection, query)
        logger.debug("Fetched roles by IDs", role_ids=role_ids, roles_cursor=roles_cursor)
        
        roles: list[Role] = []
        for role in roles_cursor:
            role_data = {
                "name": role.get("name"),
                "description": role.get("description", ""),
                "created_at": role.get("created_at", "2024-01-01T00:00:00Z"),
                "updated_at": role.get("updated_at", "2024-01-01T00:00:00Z"),
                "organization": role.get("organization") or role.get("organization_unit") or role.get("organizationUnit")
            }
            roles.append(Role(**role_data))
        
        # Log any missing IDs
        found_ids = {r.name for r in roles}
        missing_ids = set(role_ids) - found_ids
        if missing_ids:
            logger.warning("Some role IDs not found in collection", missing_ids=list(missing_ids), role_ids=role_ids)
        
        logger.debug("Resolved roles from IDs", role_ids=role_ids, resolved_count=len(roles))
        
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
        
