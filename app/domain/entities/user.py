from datetime import datetime, UTC
from pydantic import BaseModel, EmailStr, Field, field_validator
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
    telephone_number: str
    postalAddress: str = ""
    address: str = ""
    first_name: str 
    last_name: str 
    dnPath: str = "" # Distinguished Name Path in LDAP, just one domain
    organization: str 
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    password: str = Field(..., min_length=12, max_length=128)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v):
        import re
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")
        return v

    def touch(self):
        """Update the updated_at field to the current UTC time."""
        self.updated_at = datetime.now(UTC).isoformat()

    @field_validator("telephone_number")
    @classmethod
    def validate_telephone_number(cls, v):
        import re
        # Accepts E.164 (+1234567890), or local (10-15 digits, optional dashes/spaces)
        pattern = r"^(\+\d{10,15}|\d{10,15}|(\+\d{1,3}[- ]?)?\d{6,14})$"
        if not re.match(pattern, v.replace(" ", "").replace("-", "")):
            raise ValueError("Invalid telephone number format. Please use E.164 format (+1234567890) or local format (10-15 digits).")
        return v
