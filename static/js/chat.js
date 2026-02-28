const clientId = 'user_' + Math.random().toString(36).substr(2, 8);
document.getElementById('client-id').textContent = clientId;

let ws = null;
let selectedPeer = null;
let handshakeComplete = false;

const messagesDiv = document.getElementById('messages');
const statusText = document.getElementById('status-text');
const statusIndicator = document.getElementById('status-indicator');
const sendBtn = document.getElementById('send-btn');
const peerSelect = document.getElementById('peer-select');

sendBtn.disabled = true;

// ------------------- LOAD PEERS -------------------

async function loadPeers() {
    const res = await fetch('/peers');
    const peers = await res.json();

    peerSelect.innerHTML = '';

    peers.forEach(peer => {
        const option = document.createElement('option');
        option.value = peer[0];
        option.textContent = `${peer[0]}:${peer[1]}`;
        peerSelect.appendChild(option);
    });
}

// ------------------- CONNECT -------------------

function connect() {
    if (!selectedPeer) {
        alert("Select peer first!");
        return;
    }

    ws = new WebSocket(`ws://${selectedPeer}:9000/ws/${clientId}`);

    ws.onopen = () => {
        addSystemMessage("🔐 Establishing secure channel...");
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.type === "handshake_complete") {
            handshakeComplete = true;
            statusText.textContent = 'Secure';
            statusIndicator.className = 'status-indicator connected';
            sendBtn.disabled = false;
            addSystemMessage("✅ Secure session established");
        }

        if (data.type === "message") {
            addMessage(data.from, data.text, false);
        }

        if (data.type === "error") {
            addSystemMessage("❌ " + data.message);
        }
    };

    ws.onclose = () => {
        handshakeComplete = false;
        sendBtn.disabled = true;
        statusText.textContent = 'Disconnected';
        statusIndicator.className = 'status-indicator';
    };
}

// ------------------- SEND MESSAGE -------------------

function sendMessage() {
    const input = document.getElementById('message-input');
    const text = input.value.trim();

    if (!handshakeComplete) {
        alert("Secure channel not ready");
        return;
    }

    if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;

    ws.send(JSON.stringify({
        type: 'message',
        text: text
    }));

    addMessage('You', text, true);
    input.value = '';
}