from fastapi import FastAPI
from contextlib import asynccontextmanager
import structlog
from app.api.v1.routes import all_routers
from app.config.settings import settings
from app.config.ldap_singleton import get_ldap_port_instance
from app.utils.logging import configure_logging
from app.config.exception_config import register_exception_handlers

configure_logging()

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up FastAPI application ...")
    ldap_instance = await get_ldap_port_instance()
    yield
    # Cleanup LDAP connection on shutdown
    if hasattr(ldap_instance, "conn") and ldap_instance.conn.bound:
        ldap_instance.conn.unbind()
        logger.info("LDAP connection purged on shutdown.")
    
app = FastAPI(title=settings.APP_NAME, version="1.0.0", lifespan=lifespan)
logger.info("FastAPI application instance created.")
logger.info("Registering exception handlers ...")
register_exception_handlers(app)

for router in all_routers:
    app.include_router(router, prefix="/v1")


@app.get("/")
async def root():
    return {"message": "FastAPI OpenLDAP AD Service"}

