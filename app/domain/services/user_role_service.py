from app.domain.entities.user_role import UserRole
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

class UserRoleService:
    def __init__(self, non_relational_db_port: NonRelationalDBPort, collection_name: str ):
        self.non_relational_db_port = non_relational_db_port
        self.collection = collection_name
        logger.info("Initialized RoleService")

    def create_user_role(self, user_role: UserRole) -> str:
        user_role_dict = user_role.model_dump()
        # Check if user role already exists by username (or unique field)
        existing = self.non_relational_db_port.find_entry(self.collection, {"username": user_role_dict.get("username")})
        if existing:
            logger.warning("User role already exists", user_role=user_role_dict)
            raise RoleAlreadyExistsError(f"Role with username '{user_role_dict.get('username')}' already exists.")
        inserted_id = self.non_relational_db_port.insert_entry(self.collection, user_role_dict)
        if not inserted_id:
            raise FailureRoleCreationError("Failed to create role.")
        return inserted_id
    
    def add_role_to_user(self, username: str, role) -> int:
        """Add a single role (model or identifier) to a user's roles.

        The `role` parameter can be:
        - a Role model instance (with .model_dump()), or
        - a string representing the role's id or name.

        This method will validate the role exists in the roles collection and
        avoid adding duplicates. If the user does not exist, a new user entry
        will be created with the given role.
        """
        if not username:
            raise InvalidRoleDataError("Username is required")

        # resolve role_doc depending on input type (do this before user lookup so we can create user if needed)
        role_doc = None
        if hasattr(role, "model_dump"):
            # If a Role model is passed, we need to look it up by name to get its _id from the DB
            role_model_dict = role.model_dump()
            role_name = role_model_dict.get("name")
            if not role_name:
                raise InvalidRoleDataError("Role model must have a name")
            role_doc = self.non_relational_db_port.find_entry(settings.ROLES_COLLECTION_NAME, {"name": role_name})
            if not role_doc:
                raise RoleNotFoundError(f"Role '{role_name}' not found in roles collection.")
        elif isinstance(role, str):
            # try to find by _id first, then by name in the roles collection
            role_doc = self.non_relational_db_port.find_entry(settings.ROLES_COLLECTION_NAME, {"_id": role})
            if not role_doc:
                role_doc = self.non_relational_db_port.find_entry(settings.ROLES_COLLECTION_NAME, {"name": role})
            if not role_doc:
                raise RoleNotFoundError(f"Role '{role}' not found in roles collection.")
        else:
            raise InvalidRoleDataError("Unsupported role type")

        # fetch user role entry
        user_role_entry = self.non_relational_db_port.find_entry(self.collection, {"username": username})
        if not user_role_entry:
            # create new user entry with this role (store reference _id only)
            role_id = None
            if isinstance(role_doc, dict):
                role_id = role_doc.get("_id")
            elif hasattr(role_doc, "model_dump"):
                role_id = role_doc.model_dump().get("_id")

            if not role_id:
                raise InvalidRoleDataError("Could not resolve role id to store for new user")

            new_user = {"username": username, "roles": [role_id]}
            inserted_id = self.non_relational_db_port.insert_entry(self.collection, new_user)
            if not inserted_id:
                raise FailureRoleCreationError(f"Failed to create user '{username}' with role.")
            logger.info("Created new user with role reference", username=username, role_id=role_id)
            # return 1 to indicate one role was added
            return 1

        # existing user: operate on its stored representation
        user_role_dict = user_role_entry
        roles = user_role_dict.get("roles", []) or []

        # normalize existing roles as set of ids
        existing_ids = {r for r in roles if isinstance(r, str)}

        role_id = None
        if isinstance(role_doc, dict):
            role_id = role_doc.get("_id")
        elif hasattr(role_doc, "model_dump"):
            role_id = role_doc.model_dump().get("_id")

        if not role_id:
            raise InvalidRoleDataError("Could not resolve role id to store")

        if role_id in existing_ids:
            logger.info("Role already assigned to user; skipping", username=username, role_id=role_id)
            return 0

        # append role id reference
        roles.append(role_id)

        updated_count = self.non_relational_db_port.update_entry(
            self.collection,
            {"username": username},
            {"roles": roles}
        )
        if updated_count == 0:
            raise FailureRoleCreationError(f"Failed to add role to user '{username}'.")

        return updated_count

    def add_roles_to_user(self, username: str, roles_input: Role | str | list[Role | str]) -> int:
        """Add one or more roles to a user's roles.

        `roles_input` may be:
        - a single `Role` model instance
        - a single role id/name string
        - a list of `Role` instances and/or strings

        Returns the number of roles actually added (duplicates are skipped).
        """
        # Normalize to list
        if isinstance(roles_input, (Role, str)):
            items = [roles_input]
        elif isinstance(roles_input, list):
            items = roles_input
        else:
            raise InvalidRoleDataError("roles_input must be a Role, str, or list of those")

        total_added = 0
        for item in items:
            # delegate to single-role method which handles validation and duplicates
            logger.debug("Adding role to user", username=username, role=item)
            added = self.add_role_to_user(username, item)
            logger.debug("Role addition result", username=username, role=item, added=added)
            # add_role_to_user returns updated_count from DB or 0 when skipped
            if added:
                total_added += 1

        return total_added

    def delete_user_roles_by_username(self, username: str) -> int:
        """Delete all roles associated with a given username."""
        if not username:
            raise InvalidRoleDataError("Username is required for deletion")

        deleted_count = self.non_relational_db_port.delete_many(
            self.collection,
            {"username": username}
        )
        if deleted_count == 0:
            logger.warning("No user roles found to delete for username", username=username)
        else:
            logger.info("Deleted user roles for username", username=username, deleted_count=deleted_count)

        return deleted_count