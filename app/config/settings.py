import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

from app.utils.helpers.expiration_parser import parse_expiration

class Settings(BaseSettings):
    APP_NAME: str
    LOG_LEVEL: str
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
    model_config = SettingsConfigDict(env_file=os.path.join(os.path.dirname(__file__), ".env"), extra="ignore")

    @property
    def token_expiration_timedelta(self):
        return parse_expiration(self.TOKEN_EXPIRATION)
        
@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()