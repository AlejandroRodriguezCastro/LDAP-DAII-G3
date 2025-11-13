from fastapi import APIRouter, Request
import structlog
from app.domain.entities.organization_unit import OrganizationUnit
from app.domain.services.organization_unit_service import OrganizationUnitService
from app.config.ldap_singleton import get_ldap_port_instance
from app.handlers.authentication.authentication_handler import _require_roles
from app.config.settings import settings

logger = structlog.get_logger(__name__)

router = APIRouter(
    prefix="/organization_units",
    tags=["organization_units"]
)


@router.get("/")
async def read_organization_units(request: Request):
    logger.info("GET /organization_units called")
    await _require_roles(request, settings.SUPER_ADMIN_ROLES)
    ldap_port_instance = await get_ldap_port_instance()
    org_unit_service = OrganizationUnitService(ldap_port_instance)
    organization_units = await org_unit_service.get_organization_all()
    return {"message": "List of organization units", "organization_units": organization_units}

@router.delete("/")
async def delete_organization_units(request: Request):
    logger.info("DELETE /organization_units called")
    # only admins can delete all
    await _require_roles(request, [settings.SUPER_ADMIN_ROLES[1]])
    ldap_port_instance = await get_ldap_port_instance()
    org_unit_service = OrganizationUnitService(ldap_port_instance)
    await org_unit_service.delete_organization_all()
    return {"message": "All organization units deleted"}

@router.delete("/{org_unit_name}")
async def delete_organization_unit(org_unit_name: str, request: Request):
    logger.info(f"DELETE /organization_units/{org_unit_name} called")
    await _require_roles(request, [settings.SUPER_ADMIN_ROLES[1]])
    ldap_port_instance = await get_ldap_port_instance()
    org_unit_service = OrganizationUnitService(ldap_port_instance)
    await org_unit_service.delete_organization(org_unit_name)
    return {"message": f"Organization unit '{org_unit_name}' deleted"}

@router.post("/")
async def create_organization_unit(org_unit: OrganizationUnit, request: Request):
    logger.info("POST /organization_units called")
    await _require_roles(request, [settings.SUPER_ADMIN_ROLES[1]])
    ldap_port_instance = await get_ldap_port_instance()
    org_unit_service = OrganizationUnitService(ldap_port_instance)
    await org_unit_service.create_organization(org_unit)
    return {"message": f"Organization unit '{org_unit.name}' created"}
    # Emergencias
    # Movilidad
    # EDA
    # Analytics
    # Cultura
    # LDAP
    # Reclamos
    # Residuos
    