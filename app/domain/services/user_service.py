import structlog
from app.config.settings import settings
from app.domain.entities.user import User
from app.ports.outbound.ldap_port import LDAPPort
import datetime
from app.handlers.errors.user_exception_handlers import (
    UserNotFoundError,
    UserAlreadyExistsError,
    InvalidUserDataError,
    FailureUserCreationError,
    FailureUserDeletionError,
    UserLockedDownError,
    UserInvalidCredentialsError
)
from app.domain.services.role_service import RoleService
from app.domain.services.user_role_service import UserRoleService
from app.ports.outbound.nonrelationaldb_port import NonRelationalDBPort
from app.config.mongo_settings import connect_db


logger = structlog.get_logger()

role_service = RoleService(NonRelationalDBPort(non_relational_db=connect_db(), db_name="ldap-roles"), collection_name=settings.ROLES_COLLECTION_NAME)
user_role_service = UserRoleService(NonRelationalDBPort(non_relational_db=connect_db(), db_name="ldap-roles"), collection_name=settings.USER_ROLES_COLLECTION_NAME)

class UserService:
    def __init__(self, ldap_port: LDAPPort):
        self.ldap_port = ldap_port

    def _ensure_single_entry(self, entry):
        """Normalize possible LDAPPort return shapes.

        LDAP adapters may return a list of entries or a single entry object/dict.
        This helper returns the first entry if a non-empty list is provided,
        None if the list is empty, or the original entry otherwise.
        """
        if isinstance(entry, list):
            return entry[0] if entry else None
        return entry

    async def get_all_users(self) -> list[User]:
        first_or_none = lambda v: v[0] if isinstance(v, list) and v else v or None

        logger.info("Fetching all users from LDAP")
        users_data = await self.ldap_port.get_all_users()
        logger.debug("Users data fetched:", users_data=users_data)
        if not users_data:
            logger.info("No users found in LDAP")
            raise UserNotFoundError("No users found.")
        users = []
        for user in users_data:
            username_val = first_or_none(user.get("uid"))
            mail_val = first_or_none(user.get("mail"))
            telephone_val = first_or_none(user.get("telephoneNumber"))
            first_name_val = (
                first_or_none(user.get("givenName"))
                or (
                    lambda cn, sn: " ".join(cn.split()[:-len(sn.split())]) if cn and sn and cn.endswith(sn) else cn
                )(first_or_none(user.get("cn")), first_or_none(user.get("sn")))
            )
            last_name_val = first_or_none(user.get("sn"))
            organization_val = first_or_none(user.get("ou", "Unknown"))

            # Attempt to fetch role ids for this username from the user_roles collection
            roles_for_user = []
            try:
                if username_val:
                    user_roles_doc = user_role_service.non_relational_db_port.find_entry(
                        user_role_service.collection, {"username": username_val}
                    )
                    logger.debug("Fetched user roles document for user", username=username_val, user_roles_doc=user_roles_doc)
                    if user_roles_doc:
                        role_ids = user_roles_doc.get("roles", []) or []
                        try:
                            # Resolve role ids to Role models
                            roles_for_user = role_service.get_roles_by_ids(role_ids) if role_ids else []
                            logger.debug("Resolved roles for user", username=username_val, roles=roles_for_user)
                        except Exception as e:
                            # If roles can't be resolved by ID, fall back to organization-based roles
                            logger.debug("Could not resolve roles by ID for user, falling back to organization", username=username_val, role_ids=role_ids, error=str(e))
                            try:
                                if organization_val and organization_val != "Unknown":
                                    roles_for_user = role_service.get_roles_by_organization(organization_val)
                                    logger.debug("Resolved roles for user by organization", username=username_val, organization=organization_val, roles=roles_for_user)
                            except Exception:
                                logger.debug("Could not resolve roles by organization for user", username=username_val, organization=organization_val)
            except Exception:
                logger.exception("Error fetching user roles for user", username=username_val)

            users.append(User(
                username=username_val,
                mail=mail_val,
                telephone_number=telephone_val,
                first_name=first_name_val,
                last_name=last_name_val,
                organization=organization_val,
                roles=roles_for_user,
                password="asd324ewrf!@#QWEqwe"  # Placeholder, not returned by LDAP
            ))

        return users
    
    async def get_user_roles(self, user_mail: str) -> list[str]:
        logger.info("Fetching roles for user by mail:", user_mail=user_mail)
        
        # First, retrieve the user data from the mail
        user_data = await self.get_user(user_mail=user_mail)
        logger.debug("Retrieved user data for mail:", mail=user_mail, user_data=user_data)
        
        if not user_data:
            logger.info("Could not retrieve user data for mail:", user_mail=user_mail)
            raise UserNotFoundError(user_mail)
        
        # Extract username from user_data
        username = user_data['uid'].value if 'uid' in user_data and user_data['uid'].value else None
        logger.debug("Extracted username from user data:", username=username)
        
        if not username:
            logger.info("Could not extract username from user data:", user_mail=user_mail)
            raise UserNotFoundError(user_mail)
        
        # Then, retrieve the roles for that user
        user_roles_doc = user_role_service.non_relational_db_port.find_entry(
            user_role_service.collection, {"username": username}
        )
        logger.debug("Fetched user roles document:", username=username, user_roles_doc=user_roles_doc)
        
        if user_roles_doc:
            role_ids = user_roles_doc.get("roles", []) or []
            logger.debug("Role IDs fetched for user:", username=username, role_ids=role_ids)
            roles = role_service.get_roles_by_ids(role_ids) if role_ids else []
            logger.info("Retrieved roles for user:", username=username, roles=roles)
            return roles
        else:
            logger.info("No roles found for user:", username=username)
            return []

    async def get_user(self, user_mail: str = None, user_id: str = None, username: str = None):
        """Fetch user from LDAP by mail, user_id, or username.
        
        Args:
            user_mail: User's email address
            user_id: User's ID (alias for username)
            username: User's username (uid attribute in LDAP)
        
        Returns:
            User data dictionary/object from LDAP
        
        Raises:
            UserNotFoundError: If user not found
        """
        # Determine which attribute to search by
        search_value = None
        search_attribute = None
        
        if username or user_id:
            # Prefer username/user_id over mail
            search_value = username or user_id
            search_attribute = "uid"
        elif user_mail:
            search_value = user_mail
            search_attribute = "mail"
        else:
            raise InvalidUserDataError("Either user_mail, user_id, or username must be provided")
        
        logger.info("Fetching user from LDAP", attribute=search_attribute, value=search_value)
        user_data = await self.ldap_port.get_user_by_attribute(search_attribute, search_value)
        # Normalise shapes: LDAPPort may return a list or a single entry
        user_data = self._ensure_single_entry(user_data)
        if not user_data:
            logger.info("User not found", attribute=search_attribute, value=search_value)
            raise UserNotFoundError(f"User not found with {search_attribute}={search_value}")
        logger.info("User data found", attribute=search_attribute, value=search_value, user_data=user_data)
        return user_data
    
    async def create_user(self, user: User) -> User:
        logger.info("Creating user in LDAP:", username=user.mail)
        
        check_email = await self.ldap_port.get_user_by_attribute("mail", f"{user.mail}")
        logger.info("Mail existence check result:", exists=check_email, mail=user.mail)
        
        base_username = f"{user.first_name[0]}{user.last_name.split()[-1]}".lower()
        check_username = await self.ldap_port.get_user_by_attribute("uid", f"{base_username}")
        logger.info("Username existence check result:", exists=check_username, base_username=base_username)
            
        username = f"{base_username}"
        counter = 1
        while check_username:
            username = f"{base_username}{counter}"
            check_username = await self.ldap_port.get_user_by_attribute("uid", username)
            counter += 1
            logger.info("Username existence check result:", exists=check_username)
            
        user.username = username
        logger.info("Final username to be used:", username=user.username)
            
        check_organization = await self.ldap_port.get_user_by_attribute("ou", f"{user.organization}")
        logger.info("Organization existence check result:", exists=check_organization, organization=user.organization)
        
        if check_email:
            logger.info("Email already exists. User not created.")
            raise UserAlreadyExistsError(user)
    
        if not check_organization:
            logger.info("Organization does not exist. User not created.")
            raise InvalidUserDataError("Organization does not exist.")
        # Check if role or roles exist for the organization unit
        roles = role_service.get_roles_by_organization(user.organization)
        logger.debug("Roles fetched for user's organization unit:", organization=user.organization, roles=roles)
        if not roles:
            logger.info("No roles found for the user's organization unit. User not created.", organization=user.organization)
            raise InvalidUserDataError("No roles found for the user's organization unit.")
                
        if user.roles:
            logger.debug("Adding roles to user before creation:", username=user.username, roles=user.roles)
            # Check which roles (if any) do not exist in the roles collection
            existing_role_names = {r.name for r in roles}
            missing_roles = [ur.name for ur in user.roles if ur.name not in existing_role_names]
            if missing_roles:
                logger.info(
                    "One or more roles do not exist in roles collection. User not created.",
                    username=user.username,
                    missing_roles=missing_roles,
                )
                raise InvalidUserDataError(f"One or more roles do not exist in roles collection: {', '.join(missing_roles)}")
            added_roles = user_role_service.add_roles_to_user(user.username, user.roles)
            logger.info("Roles added to user:", username=user.username, roles=user.roles, added_count=added_roles)
        
        if user.roles and not added_roles:
            logger.info("Failed to add roles to user. User not created.", username=user.username, roles=user.roles)
            raise FailureUserCreationError("Failed to add roles to user.")
        
        response = await self.ldap_port.create_user(user)
        
        logger.info("User creation response from LDAP:", response=response)
        if response.get('result', 1) != 0:
            logger.error("Failed to create user in LDAP:", response=response)
            raise FailureUserCreationError("Failed to create user in LDAP.", details=str(response))
        return user

    async def delete_user(self, user_mail: str):
        logger.info("Deleting user from LDAP:", user_mail=user_mail)
        check_email = await self.ldap_port.get_user_by_attribute("mail", f"{user_mail}")
        logger.info("Mail existence check result:", exists=check_email, mail=user_mail)
        
        if not check_email:
            logger.info("Email does not exist. User not found for deletion.")
            raise UserNotFoundError(user_mail)
        deleted = await self.ldap_port.delete_user(user_mail)
        
        if not deleted:
            logger.error("Failed to delete user in LDAP:", mail=user_mail)
            raise FailureUserDeletionError("Failed to delete user in LDAP.")

    async def authenticate_user(self, user_dn: str, password: str, client_ip: str = None) -> bool:
        logger.info("Searching user by mail for authentication", mail=user_dn)
        user_data = await self.ldap_port.get_user_by_attribute("mail", user_dn)
        # Normalise shapes: LDAPPort may return a list or a single entry
        user_data = self._ensure_single_entry(user_data)
        if not user_data:
            logger.info("User not found for mail", mail=user_dn)
            raise UserNotFoundError(user_dn)
        logger.info("User data found for mail", mail=user_dn, user_data=user_data)
        uid = user_data['uid'].value if 'uid' in user_data and user_data['uid'].value else None
        ou = user_data['ou'].value if 'ou' in user_data and user_data['ou'].value else None

        if not uid or not ou:
            logger.info("User found but missing uid or ou", user=user_data)
            raise InvalidUserDataError("User record missing uid or ou.")
        
        user_dn = f"uid={uid},ou={ou},dc=ldap,dc=com"
        logger.info("Constructed user_dn for authentication", user_dn=user_dn)

        is_authenticated = await self.ldap_port.authenticate(user_dn, password)
        logger.info("Authentication result:", user_dn=user_dn, is_authenticated=is_authenticated)
        
        if is_authenticated:
            client_ip = client_ip or "unknown"
            await self.ldap_port.add_login_record(user_dn, client_ip)
            await self.ldap_port.prune_login_records(user_dn, keep_last=settings.LOGIN_HISTORY_LIMIT)

        # is_first_login = await self.ldap_port.is_first_login(user_dn)
        # logger.info("Is first login check:", user_dn=user_dn, is_first_login=is_first_login)
        
        is_locked = await self.ldap_port.is_account_locked(user_dn)
        logger.info("Is locked down?", user_dn=user_dn, is_locked=is_locked)
        if is_locked:
            if hasattr(is_locked, "strftime"):
                readable_date = (is_locked + datetime.timedelta(seconds=300)).strftime("%Y-%m-%d %H:%M:%S")
            else:
                try:
                    # Try to parse is_locked as a datetime string
                    dt = datetime.datetime.strptime(str(is_locked), "%Y-%m-%d %H:%M:%S")
                    readable_date = (dt + datetime.timedelta(seconds=300)).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    readable_date = str(is_locked)
            raise UserLockedDownError(user_dn=user_dn, date_until=readable_date)

        if not is_authenticated:
            logger.info("Authentication failed for user", user_dn=user_dn)
            raise UserInvalidCredentialsError("Invalid credentials provided.")
        
        return is_authenticated
    
    async def modify_user_data(self, user_mail: str, new_data: dict):
        logger.info("Modifying user data in LDAP:", mail=user_mail, new_data=new_data)
        user_dn = await self.ldap_port.get_user_by_attribute("mail", f"{user_mail}")
        # Normalise shapes: LDAPPort may return a list or a single entry
        user_dn = self._ensure_single_entry(user_dn)
        logger.info("Mail existence check result:", exists=user_dn, mail=user_mail)
        
        if not user_dn:
            logger.info("Email does not exist. User not found for modification.")
            raise UserNotFoundError(user_mail)

        user_exists = user_dn['uid'].value if 'uid' in user_dn else None
        logger.info("User DN fetched for modification:", user_dn=user_exists)
        if not user_exists:
            logger.info("User DN not found in record. Cannot modify user.")
            raise InvalidUserDataError("User DN not found in record.")
        
        modified = await self.ldap_port.modify_user_data(user_dn, new_data)
        if not modified:
            logger.error("Failed to modify user data in LDAP:", mail=user_mail)
            raise FailureUserCreationError("Failed to modify user data in LDAP.")

        # Ensure we return a User instance that matches the API response_model.
        # The incoming `new_data` is expected to be a User model from the route,
        # but make sure the username matches the one in LDAP (uid).

        if hasattr(new_data, 'username') and user_exists:
            new_data.username = user_exists

        return new_data
    
    async def modify_user_password(self, user_mail: str, new_password: str):
        logger.info("Modifying user password in LDAP:", mail=user_mail)
        user_dn = await self.ldap_port.get_user_by_attribute("mail", f"{user_mail}")
        # Normalise shapes: LDAPPort may return a list or a single entry
        user_dn = self._ensure_single_entry(user_dn)
        logger.info("Mail existence check result:", exists=user_dn, mail=user_mail)
        
        if not user_dn:
            logger.info("Email does not exist. User not found for password modification.")
            raise UserNotFoundError(user_mail)

        user_exists = user_dn['uid'].value if 'uid' in user_dn else None
        logger.info("User DN fetched for password modification:", user_dn=user_exists)
        if not user_exists:
            logger.info("User DN not found in record. Cannot modify password.")
            raise InvalidUserDataError("User DN not found in record.")
        
        modified = await self.ldap_port.modify_user_password(user_dn, new_password)
        if not modified:
            logger.error("Failed to modify user password in LDAP:", mail=user_mail)
            raise FailureUserCreationError("Failed to modify user password in LDAP.")

        return True
    
    async def get_users_by_organization(self, org_unit_name: str) -> list[User]:
        """Fetch all users belonging to a specific organization unit.
        
        Args:
            org_unit_name: The organization unit name to filter by
        
        Returns:
            List of User objects from the organization
        
        Raises:
            UserNotFoundError: If no users found in organization
        """
        logger.info("Fetching users by organization:", organization=org_unit_name)
        # Get all users from LDAP and filter by organization
        all_users = await self.ldap_port.get_all_users()
        logger.debug("All users fetched from LDAP:", count=len(all_users) if all_users else 0)
        
        # Filter users by organization unit
        first_or_none = lambda v: v[0] if isinstance(v, list) and v else v or None
        users_data = [user for user in all_users if first_or_none(user.get("ou")) == org_unit_name]
        logger.debug("Users data fetched for organization:", organization=org_unit_name, users_data=users_data)
        
        if not users_data:
            logger.info("No users found in organization:", organization=org_unit_name)
            raise UserNotFoundError(f"No users found in organization: {org_unit_name}")
        
        # Normalize to list if single entry returned
        if not isinstance(users_data, list):
            users_data = [users_data]
        
        users = []
        first_or_none = lambda v: v[0] if isinstance(v, list) and v else v or None
        
        for user in users_data:
            username_val = first_or_none(user.get("uid"))
            mail_val = first_or_none(user.get("mail"))
            telephone_val = first_or_none(user.get("telephoneNumber"))
            first_name_val = (
                first_or_none(user.get("givenName"))
                or (
                    lambda cn, sn: " ".join(cn.split()[:-len(sn.split())]) if cn and sn and cn.endswith(sn) else cn
                )(first_or_none(user.get("cn")), first_or_none(user.get("sn")))
            )
            last_name_val = first_or_none(user.get("sn"))
            organization_val = first_or_none(user.get("ou", "Unknown"))

            # Attempt to fetch role ids for this username from the user_roles collection
            roles_for_user = []
            try:
                if username_val:
                    user_roles_doc = user_role_service.non_relational_db_port.find_entry(
                        user_role_service.collection, {"username": username_val}
                    )
                    logger.debug("Fetched user roles document for user", username=username_val, user_roles_doc=user_roles_doc)
                    if user_roles_doc:
                        role_ids = user_roles_doc.get("roles", []) or []
                        try:
                            # Resolve role ids to Role models
                            roles_for_user = role_service.get_roles_by_ids(role_ids) if role_ids else []
                            logger.debug("Resolved roles for user", username=username_val, roles=roles_for_user)
                        except Exception as e:
                            # If roles can't be resolved by ID, fall back to organization-based roles
                            logger.debug("Could not resolve roles by ID for user, falling back to organization", username=username_val, role_ids=role_ids, error=str(e))
                            try:
                                if organization_val and organization_val != "Unknown":
                                    roles_for_user = role_service.get_roles_by_organization(organization_val)
                                    logger.debug("Resolved roles for user by organization", username=username_val, organization=organization_val, roles=roles_for_user)
                            except Exception:
                                logger.debug("Could not resolve roles by organization for user", username=username_val, organization=organization_val)
            except Exception:
                logger.exception("Error fetching user roles for user", username=username_val)

            users.append(User(
                username=username_val,
                mail=mail_val,
                telephone_number=telephone_val,
                first_name=first_name_val,
                last_name=last_name_val,
                organization=organization_val,
                roles=roles_for_user,
                password="asd324ewrf!@#QWEqwe"  # Placeholder, not returned by LDAP
            ))

        return users

    async def get_last_logins(self, user_mail: str, limit: int = 5):
        logger.info("Fetching last login history for user:", mail=user_mail, limit=limit)
        user_dn = await self.ldap_port.get_user_by_attribute("mail", user_mail)
        if not user_dn:
            raise UserNotFoundError(user_mail)
        # Normalise user_dn shapes: LDAPPort may return a list of entries or a single entry dict/object
        if isinstance(user_dn, list):
            # If it's a list, take the first entry (most searches expect the first match)
            user_dn = user_dn[0] if user_dn else None

        if not user_dn:
            raise UserNotFoundError(user_mail)

        dn = f"uid={user_dn['uid'].value},ou={user_dn['ou'].value},dc=ldap,dc=com"
        logger.info("Constructed DN for fetching login history:", dn=dn)
        history = await self.ldap_port.get_login_history(dn)
        return history[-limit:]  # last N entries
