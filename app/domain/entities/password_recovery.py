from pydantic import BaseModel, Field, EmailStr
from datetime import datetime, UTC
import uuid


class PasswordRecoveryToken(BaseModel):
    """Represents a password recovery token stored in the database"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_email: EmailStr
    token: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    expires_at: str  # Should be set when creating the token
    is_used: bool = False
    used_at: str | None = None


class PasswordRecoveryRequest(BaseModel):
    """Request body for initiating password recovery"""
    mail: EmailStr


class PasswordResetRequest(BaseModel):
    """Request body for resetting password with recovery token"""
    token: str
    new_password: str = Field(..., min_length=12, max_length=128)

    @classmethod
    def validate_password_strength(cls, v):
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
