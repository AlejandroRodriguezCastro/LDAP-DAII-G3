import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

from app.utils.helpers.expiration_parser import parse_expiration

class Settings(BaseSettings):
    APP_NAME: str
    LOG_LEVEL: str
    CORS_ALLOWED_ORIGINS: list[str] = ["*"]
    CORS_ALLOWED_METHODS: list[str] = ["*"]
    CORS_ALLOWED_HEADERS: list[str] = ["*"]
    CORS_ALLOW_CREDENTIALS: bool = True
    DATABASE_URL: str
    QUEUE_URL: str
    LDAP_URL: str
    LDAP_BIND_DN: str
    LDAP_BIND_PASSWORD: str
    SECRET_KEY: str
    TOKEN_EXPIRATION: str
    MONGO_USER: str
    MONGO_PASSWORD: str
    MONGO_URI: str
    MONGO_DB_NAME: str
    ROLES_COLLECTION_NAME: str = "roles"
    USER_ROLES_COLLECTION_NAME: str = "user_roles"
    PASSWORD_RECOVERY_COLLECTION_NAME: str = "password_recovery_tokens"
    LOGIN_HISTORY_LIMIT: int = 5
    SUPER_ADMIN_ROLES: list[str] = ["super_admin_read", "super_admin_write"]
    ADMIN_ROLES: list[str] = ["admin_read", "admin_write"]
    
    # Email configuration for password recovery
    SMTP_SERVER: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SENDER_EMAIL: str
    SENDER_PASSWORD: str
    SMTP_USE_TLS: bool = True
    PASSWORD_RECOVERY_TOKEN_EXPIRATION: str = "24h"  # Token expiration time
    PASSWORD_RECOVERY_LINK_TEMPLATE: str = "http://ec2-44-217-132-156.compute-1.amazonaws.com/reset-password?token={token}"  # Frontend recovery link
    
    model_config = SettingsConfigDict(env_file=os.path.join(os.path.dirname(__file__), ".env"), extra="ignore")

    @property
    def token_expiration_timedelta(self):
        return parse_expiration(self.TOKEN_EXPIRATION)
        
@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()