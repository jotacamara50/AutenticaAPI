# app/security.py

from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from jose import jwt

# Configurações de Segurança e JWT
SECRET_KEY = "a_sua_chave_secreta_super_segura_aqui"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = 15

# Contexto de hashing de senha
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str):
    return pwd_context.hash(password)

def create_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt