from pydantic import BaseModel
from app.config.settings import settings

class ClientCredentials(BaseModel):
    username: str
    password: str
    redirect_uris: list[str] = []
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "username": "client_id",
                "password": "client_secret",
                "redirect_uris": ["http://localhost/callback"]
            }
        }
    }
    