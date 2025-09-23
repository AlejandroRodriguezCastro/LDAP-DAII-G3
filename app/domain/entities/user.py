from pydantic import BaseModel, EmailStr, Field
from typing import List
from .roles import Role

class User(BaseModel):
    username: str = ""
    mail: EmailStr
    roles: List[Role] = Field(default_factory=list)
    id: str = Field(default_factory=lambda: "user_" + str(id(object())))
    uidNumber: int = 0
    gidNumber: int = 0
    is_active: bool = True
    telephoneNumber: str = ""
    postalAddress: str = ""
    address: str = ""
    first_name: str 
    last_name: str 
    dnPath: str = "" # Distinguished Name Path in LDAP, just one domain
    organization: str 
    created_at: str = Field(default_factory=lambda: "2024-01-01T00:00:00Z") # Placeholder for creation timestamp
    updated_at: str = Field(default_factory=lambda: "2024-01-01T00:00:00Z") # Placeholder for update timestamp
