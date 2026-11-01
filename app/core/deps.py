from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_access_token
from app.models import User

oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(
    token: str = Depends(oauth2), db: Session = Depends(get_db)
) -> User:
    user_id = decode_access_token(token)
    user = db.get(User, user_id) if user_id else None
    if not user:
        raise HTTPException(401, "Token inválido")
    return user