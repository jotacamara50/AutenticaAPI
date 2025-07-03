# app/routers/users.py

from fastapi import APIRouter, Depends, HTTPException, status
from typing import Annotated

from .. import schemas, dependencies, database, security

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)

@router.post("/register", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def create_user(user_in: schemas.UserCreate):
    db_user = dependencies.get_user_by_email(user_in.email)
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email já cadastrado.")

    hashed_password = security.get_password_hash(user_in.password)
    user_id = len(database.fake_users_db) + 1
    new_user_data = {"id": user_id, "email": user_in.email, "hashed_password": hashed_password}
    database.fake_users_db[user_in.email] = new_user_data
    return new_user_data

@router.get("/me", response_model=schemas.UserOut)
async def read_users_me(
    current_user: Annotated[schemas.User, Depends(dependencies.get_current_user)]
):
    return current_user