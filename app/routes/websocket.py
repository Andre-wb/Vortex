import json
import base64
from fastapi import WebSocket
from vortex_chat import decrypt_message, encrypt_message

class SecureClient:
    def __init__(self, websocket: WebSocket):
        self.ws = websocket
        self.private_key = None
        self.public_key = None
        self.session_key = None
        self.handshake_complete = False

clients = {}

async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await websocket.accept()

    client = SecureClient(websocket)
    clients[client_id] = client

    # Generate ephemeral keypair
    priv, pub = generate_keypair()
    client.private_key = priv
    client.public_key = pub

    # Send hello
    await websocket.send_json({
        "type": "hello",
        "public_key": base64.b64encode(pub).decode()
    })

    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            # --- HANDSHAKE ---
            if message["type"] == "hello":
                peer_pub = base64.b64decode(message["public_key"])
                session_key = derive_session_key(client.private_key, peer_pub)
                client.session_key = session_key
                client.handshake_complete = True

                await websocket.send_json({
                    "type": "handshake_complete"
                })

            # --- ENCRYPTED MESSAGE ---
            elif message["type"] == "message":

                if not client.handshake_complete:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Handshake not completed"
                    })
                    continue

                plaintext = message["text"].encode()
                nonce, ciphertext = encrypt_message(client.session_key, plaintext)

                # echo encrypted -> decrypt before sending
                decrypted = decrypt_message(client.session_key, nonce, ciphertext)

                await websocket.send_json({
                    "type": "message",
                    "from": client_id,
                    "text": decrypted.decode()
                })

    except Exception:
        clients.pop(client_id, None)