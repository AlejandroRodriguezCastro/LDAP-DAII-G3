from pydantic import BaseModel, Field


class UserRole(BaseModel):
    username: str
    created_at: str = Field(default_factory=lambda: "2024-01-01T00:00:00Z")  # Placeholder for creation timestamp
    updated_at: str = Field(default_factory=lambda: "2024-01-01T00:00:00Z")  # Placeholder for update timestamp
    # Store references to Role entries by id (normalized relationship)
    roles: list[str]