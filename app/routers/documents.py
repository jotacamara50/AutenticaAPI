# app/routers/documents.py

from fastapi import APIRouter, Depends, UploadFile, File, status
from typing import Annotated
from datetime import datetime, timezone

from .. import schemas, dependencies, database

router = APIRouter(
    prefix="/documents",
    tags=["Documents"]
)

@router.post("/upload", response_model=schemas.DocumentOut, status_code=status.HTTP_201_CREATED)
async def upload_document(
    current_user: Annotated[schemas.User, Depends(dependencies.get_current_user)],
    file: UploadFile = File(...)
):
    print(f"Usuário '{current_user.email}' fez o upload do arquivo '{file.filename}'.")
    
    doc_id = len(database.fake_documents_db) + 1
    
    document_data = {
        "id": doc_id,
        "filename": file.filename,
        "content_type": file.content_type,
        "uploader_id": current_user.id,
        "uploaded_at": datetime.now(timezone.utc)
    }
    
    database.fake_documents_db.append(document_data)
    
    return document_data