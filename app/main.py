# app/main.py

from fastapi import FastAPI
from .routers import auth, users, documents

app = FastAPI(
    title="API de Autenticação e Documentos",
    description="Projeto para estudo de FastAPI com autenticação JWT e upload de arquivos.",
    version="0.2.0" # Versão atualizada!
)

# Inclui os roteadores na aplicação principal
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(documents.router)

@app.get("/", tags=["Root"])
def read_root():
    """
    Endpoint raiz que retorna uma mensagem de boas-vindas.
    """
    return {"message": "Bem-vindo à API estruturada!"}