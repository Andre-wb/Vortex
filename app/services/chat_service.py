from fastapi import WebSocket
import json
import vortex_chat

class ChatService:
    def __init__(self):
        self.active_connections = {}
        self.chat_stats = vortex_chat.ChatStats()
        self.encryption_key = 42

    async def handle_connection(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        print(f"✅ {client_id} подключился")

        await self.send_system_message(websocket, f"👋 Привет, {client_id}! Чат защищен Rust-шифрованием")
        await self.broadcast_system(f"📢 {client_id} присоединился к чату", exclude=client_id)

        try:
            while True:
                data = await websocket.receive_text()
                await self.process_message(client_id, websocket, data)

        except Exception as e:
            print(f"❌ {client_id} отключился: {e}")
        finally:
            await self.disconnect_client(client_id)

    async def process_message(self, client_id: str, websocket: WebSocket, data: str):
        message_data = json.loads(data)

        if message_data["type"] == "message":
            text = message_data["text"]

            # Шифруем
            encrypted = vortex_chat.encrypt_message(text.encode(), self.encryption_key)
            msg_hash = vortex_chat.hash_message(encrypted)
            self.chat_stats.add_message(len(text))

            print(f"💬 {client_id}: {text}")
            print(f"🔒 Зашифровано: {len(encrypted)} байт")
            print(f"🔑 Хэш: {msg_hash[:16]}...")

            # Рассылаем всем
            await self.broadcast_message(client_id, encrypted, msg_hash)

            # Подтверждение
            await websocket.send_json({
                "type": "delivery",
                "status": "sent",
                "hash": msg_hash[:8]
            })

    async def broadcast_message(self, sender_id: str, encrypted: bytes, msg_hash: str):
        for conn_id, conn in self.active_connections.items():
            if conn_id != sender_id:
                decrypted = vortex_chat.decrypt_message(encrypted, self.encryption_key)
                await conn.send_json({
                    "type": "message",
                    "from": sender_id,
                    "text": decrypted.decode(),
                    "hash": msg_hash[:8],
                    "encrypted_size": len(encrypted)
                })

    async def broadcast_system(self, message: str, exclude: str = None):
        for conn_id, conn in self.active_connections.items():
            if conn_id != exclude:
                await self.send_system_message(conn, message)

    async def send_system_message(self, websocket: WebSocket, message: str):
        await websocket.send_json({
            "type": "system",
            "message": message
        })

    async def disconnect_client(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            await self.broadcast_system(f"👋 {client_id} покинул чат")

# Создаем глобальный экземпляр для использования в других модулях
chat_service = ChatService()