import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

clients = {}


@router.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await websocket.accept()
    clients[client_id] = websocket

    # Immediately mark connection ready
    await websocket.send_json({
        "type": "handshake_complete"
    })

    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            if message["type"] == "message":

                # Broadcast to all other clients
                for other_id, other_ws in clients.items():
                    if other_id != client_id:
                        await other_ws.send_json({
                            "type": "message",
                            "from": client_id,
                            "text": message["text"]
                        })

    except WebSocketDisconnect:
        clients.pop(client_id, None)