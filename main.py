# main.py

from datetime import datetime, timedelta, timezone
from typing import Annotated, List

# Novas importações para upload de arquivos
from fastapi import FastAPI, HTTPException, status, Depends, Body, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field

from passlib.context import CryptContext
from jose import JWTError, jwt

# --- Configurações de Segurança e JWT ---
SECRET_KEY = "a_sua_chave_secreta_super_segura_aqui"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = 15

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Segurança (Hashing de Senha) ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Bancos de Dados Simulados ---
fake_users_db = {} 
# Novo "banco" para guardar informações dos documentos
fake_documents_db = []

# --- Modelos Pydantic (Schemas) ---

class TokenData(BaseModel):
    email: str | None = None

class User(BaseModel):
    id: int
    email: str
    class Config:
        from_attributes = True

class UserInDB(User):
    hashed_password: str

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    email: EmailStr

class PasswordResetRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)

# Novo modelo para a resposta do upload
class DocumentOut(BaseModel):
    id: int
    filename: str
    content_type: str
    uploader_id: int
    uploaded_at: datetime

# --- Instância da Aplicação FastAPI ---
app = FastAPI(
    title="API de Autenticação e Documentos",
    description="Projeto para estudo de FastAPI com autenticação JWT e upload de arquivos.",
    version="0.1.0"
)

# --- Funções de Utilitário e Dependências ---

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str):
    return pwd_context.hash(password)

def get_user_by_email(email: str) -> UserInDB | None:
    user_data = fake_users_db.get(email)
    if user_data:
        return UserInDB(**user_data)
    return None

def create_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    user = get_user_by_email(token_data.email)
    if user is None:
        raise credentials_exception
    return user

# --- Endpoints de Autenticação e Usuários ---

@app.post("/token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = get_user_by_email(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email ou senha incorretos")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserOut)
async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user

@app.post("/users/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(user_in: UserCreate):
    db_user = get_user_by_email(user_in.email)
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email já cadastrado.")

    hashed_password = get_password_hash(user_in.password)
    user_id = len(fake_users_db) + 1
    new_user_data = {"id": user_id, "email": user_in.email, "hashed_password": hashed_password}
    fake_users_db[user_in.email] = new_user_data
    return new_user_data

@app.post("/password-recovery/{email}")
def recover_password(email: EmailStr):
    user = get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")
    
    password_reset_token_expires = timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
    reset_token = create_token(data={"sub": user.email}, expires_delta=password_reset_token_expires)
    print(f"Token de reset para {email}: {reset_token}")
    return {"msg": "Token de recuperação gerado.", "reset_token": reset_token}

@app.post("/reset-password/")
def reset_password(request: PasswordResetRequest):
    try:
        payload = jwt.decode(request.token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido ou expirado")

    user_data = fake_users_db.get(email)
    if user_data is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

    user_data["hashed_password"] = get_password_hash(request.new_password)
    return {"msg": "Senha atualizada com sucesso."}


# --- NOVO ENDPOINT PARA DOCUMENTOS ---

@app.post("/documents/upload", response_model=DocumentOut, status_code=status.HTTP_201_CREATED)
async def upload_document(
    current_user: Annotated[User, Depends(get_current_user)],
    file: UploadFile = File(...)
):
    """
    Endpoint protegido para upload de documentos.
    Requer autenticação via token JWT.
    """
    # Em um app real, aqui você salvaria o arquivo em disco ou em um serviço de nuvem (S3, Azure Blob, etc.)
    # Exemplo:
    # file_location = f"files/{file.filename}"
    # with open(file_location, "wb+") as file_object:
    #     file_object.write(file.file.read())
    
    print(f"Usuário '{current_user.email}' fez o upload do arquivo '{file.filename}'.")
    
    doc_id = len(fake_documents_db) + 1
    
    # Criamos um registro com os metadados do arquivo
    document_data = {
        "id": doc_id,
        "filename": file.filename,
        "content_type": file.content_type,
        "uploader_id": current_user.id,
        "uploaded_at": datetime.now(timezone.utc)
    }
    
    # "Salvamos" o registro no nosso banco de dados simulado
    fake_documents_db.append(document_data)
    
    return document_data