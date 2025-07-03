# app/routers/auth.py

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from datetime import timedelta

from .. import schemas, security, dependencies, database

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

@router.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = dependencies.get_user_by_email(form_data.username)
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/password-recovery/{email}")
def recover_password(email: schemas.EmailStr):
    user = dependencies.get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")
    
    password_reset_token_expires = timedelta(minutes=security.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
    reset_token = security.create_token(
        data={"sub": user.email}, expires_delta=password_reset_token_expires
    )
    print(f"Token de reset para {email}: {reset_token}")
    return {"msg": "Token de recuperação gerado.", "reset_token": reset_token}

@router.post("/reset-password/")
def reset_password(request: schemas.PasswordResetRequest):
    try:
        payload = jwt.decode(request.token, security.SECRET_KEY, algorithms=[security.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido ou expirado")

    user_data = database.fake_users_db.get(email)
    if user_data is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

    user_data["hashed_password"] = security.get_password_hash(request.new_password)
    return {"msg": "Senha atualizada com sucesso."}