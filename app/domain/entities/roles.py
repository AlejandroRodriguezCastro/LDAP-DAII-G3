from pydantic import BaseModel, Field

class Role(BaseModel):
    name: str
    description: str = ""
    created_at: str = Field(default_factory=lambda: "2024-01-01T00:00:00Z") # Placeholder for creation timestamp
    updated_at: str = Field(default_factory=lambda: "2024-01-01T00:00:00Z") # Placeholder for update timestamp
    organization: str