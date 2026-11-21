from pydantic import BaseModel, EmailStr, Field, model_validator

from app.core.passwords import problems


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def _politica_de_contrasena(self):
        faltan = problems(self.password, str(self.email))
        if faltan:
            raise ValueError("La contraseña debe tener: " + "; ".join(faltan) + ".")
        return self


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
