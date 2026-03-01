const clientId = 'user_' + Math.random().toString(36).substr(2, 8);

let ws = null;
let handshakeComplete = false;

const messagesDiv = document.getElementById('messages');
const statusText = document.getElementById('status-text');
const statusIndicator = document.getElementById('status-indicator');
const sendBtn = document.getElementById('send-btn');

sendBtn.disabled = true;

function connect() {

    ws = new WebSocket(`ws://${location.host}/ws/${clientId}`);

    ws.onopen = () => {
        addSystemMessage("🔐 Connecting...");
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

function addMessage(from, text, isMine) {
    const div = document.createElement('div');
    div.className = isMine ? 'message my-message' : 'message peer-message';
    div.textContent = `${from}: ${text}`;
    messagesDiv.appendChild(div);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function addSystemMessage(text) {
    const div = document.createElement('div');
    div.className = 'message system';
    div.textContent = text;
    messagesDiv.appendChild(div);
}

connect();