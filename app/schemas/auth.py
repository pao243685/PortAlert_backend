from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)


class UserOut(BaseModel):
    id: int
    email: EmailStr
    totp_enabled: bool
    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginOut(BaseModel):
    """Sin 2FA trae access_token; con 2FA trae mfa_required + mfa_token."""

    access_token: str | None = None
    token_type: str = "bearer"
    mfa_required: bool = False
    mfa_token: str | None = None


class TotpCode(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


class LoginTotpIn(TotpCode):
    mfa_token: str


class TotpSetupOut(BaseModel):
    secret: str
    otpauth_uri: str
