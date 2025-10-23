import structlog
from app.ports.outbound.ldap_port import LDAPPort
from app.domain.entities.organization_unit import OrganizationUnit
from app.handlers.errors.organization_exception_handler import (
    OrganizationNotFoundError,
    OrganizationAlreadyExistsError,
    InvalidOrganizationDataError,
    UnauthorizedOrganizationError,
    FailureOrganizationCreationError,
    FailureOrganizationDeletionError
)

logger = structlog.get_logger(__name__)

class OrganizationUnitService:
    def __init__(self, ldap_port: LDAPPort):
        self.ldap_port = ldap_port

    async def get_organization_all(self):
        logger.info("Fetching all organization units")
        response = await self.ldap_port.get_organization_all()
        if not response:
            raise OrganizationNotFoundError("No organization units found.")
        return response

    async def create_organization(self, org_data: OrganizationUnit):
        logger.info("Creating organization unit", org_data=org_data)
        logger.info("Checking if organization unit already exists", org_name=org_data.name)
        check_exists = await self.ldap_port.get_organization_by_name(org_data.name)
        if check_exists:
            raise OrganizationAlreadyExistsError(f"Organization '{org_data.name}' already exists.")

        response = await self.ldap_port.create_organization(org_data)
        
        if not response:
            raise FailureOrganizationCreationError(f"Failed to create organization '{org_data.name}'.")

        return response

    async def update_organization(self, org_id, org_data: OrganizationUnit):
        logger.info("Updating organization unit", org_id=org_id, org_data=org_data)
        return await self.ldap_port.update(org_id, org_data)

    async def delete_organization(self, org_name: str):
        logger.info("Deleting organization unit", org_name=org_name)

        check_exists = await self.ldap_port.get_organization_by_name(org_name)
        if not check_exists:
            raise OrganizationNotFoundError(f"Organization with name '{org_name}' not found.")

        response = await self.ldap_port.delete_organization(org_name)

        return response