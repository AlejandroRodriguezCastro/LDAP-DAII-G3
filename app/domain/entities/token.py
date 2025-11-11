import jwt
from typing import List
from pydantic import BaseModel, Field
from app.config.settings import settings

class Token(BaseModel):
    sub: str = Field(..., description="Subject: Unique identifier for the client (client_id)")
    aud: str = Field(..., description="Audience: Intended recipient of the token")
    iss: str = Field(..., description="Issuer: Entity that issued the token")
    exp: int = Field(..., description="Expiration time (as UNIX timestamp): Token expiry in seconds since epoch")
    nbf: int = Field(..., description="Not Before (as UNIX timestamp): Token is valid from this time")
    iat: int = Field(..., description="Issued At (as UNIX timestamp): Time at which the token was issued")
    jti: str = Field(..., description="JWT ID: Unique identifier for this token")
    roles: List[str] = Field(..., description="Roles: List of roles or permissions assigned to the subject")
    email: str = Field(..., description="Email address of the subject")
    scope: List[str] = Field(default_factory=list, description="Scopes granted to the subject")
    typ: str = Field(default="access", description="Type of the token (e.g., access, refresh)")

    def to_jwt(self, secret: str = settings.SECRET_KEY, algorithm: str = "HS256") -> str:
        payload = {
            "sub": self.sub,
            "aud": self.aud,
            "iss": self.iss,
            "exp": self.exp,
            "nbf": self.nbf,
            "iat": self.iat,
            "jti": self.jti,
            "roles": self.roles,
            "azp": self.sub,
            "email": self.email,
            "scope": self.scope,
            "typ": self.typ,
        }
        return jwt.encode(payload, secret, algorithm=algorithm)

    def decode_jwt(self, algorithms: List[str] = ["HS256"]) -> dict:
        return jwt.decode(self.jwt_token, key=settings.SECRET_KEY, audience="ldap.com", issuer="auth_server",
                          options={"verify_signature": True, "verify_exp": True, "require": ["exp", "nbf", "iat", "aud", "iss", "sub"]},
                          algorithms=algorithms)

class TokenValidationRequest(BaseModel):
    jwt_token: str

    def decode_jwt(self, algorithms: List[str] = ["HS256"]) -> dict:
        return jwt.decode(self.jwt_token, key=settings.SECRET_KEY, audience="ldap.com", issuer="auth_server",
                          options={"verify_signature": True, "verify_exp": True, "require": ["exp", "nbf", "iat", "aud", "iss", "sub"]},
                          algorithms=algorithms)