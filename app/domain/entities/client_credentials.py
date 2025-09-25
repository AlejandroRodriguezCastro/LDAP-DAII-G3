from pydantic import BaseModel
from app.config.settings import settings

class ClientCredentials(BaseModel):
    username: str
    password: str
    redirect_uris: list[str] = []
    roles: list[str] = []