# app/dependencies.py

from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from . import schemas, security, database

# Aponta para a URL que o cliente usará para obter o token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

def get_user_by_email(email: str) -> schemas.UserInDB | None:
    user_data = database.fake_users_db.get(email)
    if user_data:
        return schemas.UserInDB(**user_data)
    return None

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, security.SECRET_KEY, algorithms=[security.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = schemas.TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    user = get_user_by_email(token_data.email)
    if user is None:
        raise credentials_exception
    return user