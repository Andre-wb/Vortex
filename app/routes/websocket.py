from fastapi import APIRouter, WebSocket
from app.services.chat_service import ChatService

router = APIRouter()

# Создаем экземпляр сервиса
chat_service = ChatService()

@router.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await chat_service.handle_connection(websocket, client_id)