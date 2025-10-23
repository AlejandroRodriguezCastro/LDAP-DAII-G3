
from app.api.v1.authentication.auth import router as auth_router
from app.api.v1.users.user import router as user_router
from app.api.v1.roles.roles import router as roles_router
from app.api.v1.organization_unit.organization_unit import router as org_unit_router

all_routers = [
    auth_router,
    user_router,
    roles_router,
    org_unit_router
]