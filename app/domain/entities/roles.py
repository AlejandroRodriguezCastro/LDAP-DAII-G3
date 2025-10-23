from pydantic import BaseModel, Field
from .organization_unit import OrganizationUnit

class Role(BaseModel):
    name: str
    description: str = ""
    id: str = Field(default_factory=lambda: "role_" + str(id(object())))
    created_at: str = Field(default_factory=lambda: "2024-01-01T00:00:00Z") # Placeholder for creation timestamp
    updated_at: str = Field(default_factory=lambda: "2024-01-01T00:00:00Z") # Placeholder for update timestamp
    organization_units: list[OrganizationUnit] = Field(default_factory=list)