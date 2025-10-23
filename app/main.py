from fastapi import FastAPI
from contextlib import asynccontextmanager
import structlog
from app.api.v1.routes import all_routers
from app.config.settings import settings
from app.config.ldap_singleton import get_ldap_port_instance
from app.utils.logging import configure_logging
from app.config.exception_config import register_exception_handlers
from app.config.mongo_settings import connect_db, disconnect_db
from fastapi.middleware.cors import CORSMiddleware
import logging
logging.getLogger("pymongo").setLevel(logging.WARNING)

configure_logging()

logger = structlog.get_logger()



@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up FastAPI application ...")
    # Connect to MongoDB
    logger.info("Connecting to MongoDB ...")
    connect_db()
    logger.info("MongoDB connection established.")
    ldap_instance = await get_ldap_port_instance()
    yield
    # Cleanup LDAP connection on shutdown
    if hasattr(ldap_instance, "conn") and ldap_instance.conn.bound:
        ldap_instance.conn.unbind()
        logger.info("LDAP connection purged on shutdown.")
    # Disconnect MongoDB
    disconnect_db()
    logger.info("MongoDB connection closed.")
    
app = FastAPI(title=settings.APP_NAME, version="1.0.0", lifespan=lifespan)
logger.info("FastAPI application instance created.")

# Configure CORS middleware using values from settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_methods=settings.CORS_ALLOWED_METHODS,
    allow_headers=settings.CORS_ALLOWED_HEADERS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
)
logger.info("Registering exception handlers ...")
register_exception_handlers(app)

for router in all_routers:
    app.include_router(router, prefix="/v1")


@app.get("/")
async def root():
    return {"message": "FastAPI OpenLDAP AD Service"}

