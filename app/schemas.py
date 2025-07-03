# app/schemas.py

from pydantic import BaseModel, EmailStr, Field
from datetime import datetime

class TokenData(BaseModel):
    email: str | None = None

class User(BaseModel):
    id: int
    email: EmailStr
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

class DocumentOut(BaseModel):
    id: int
    filename: str
    content_type: str
    uploader_id: int
    uploaded_at: datetime