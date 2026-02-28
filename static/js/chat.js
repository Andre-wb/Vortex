const clientId = 'user_' + Math.random().toString(36).substr(2, 8);
document.getElementById('client-id').textContent = clientId;

let ws = null;
let selectedPeer = null;

const messagesDiv = document.getElementById('messages');
const statusText = document.getElementById('status-text');
const statusIndicator = document.getElementById('status-indicator');
const sendBtn = document.getElementById('send-btn');
const peerSelect = document.getElementById('peer-select');

sendBtn.disabled = true;

// ------------------- LOAD PEERS -------------------

async function loadPeers() {
    try {
        const res = await fetch('/peers');
        const peers = await res.json();

        peerSelect.innerHTML = '';

        peers.forEach(peer => {
            const option = document.createElement('option');
            option.value = peer[0];  // IP
            option.textContent = `${peer[0]}:${peer[1]}`;
            peerSelect.appendChild(option);
        });

    } catch (err) {
        console.error("Failed to load peers:", err);
    }
}

// ------------------- CONNECT -------------------

function connect() {
    if (!selectedPeer) {
        alert("Select peer first!");
        return;
    }

    ws = new WebSocket(`ws://${selectedPeer}:9000/ws/${clientId}`);

    ws.onopen = () => {
        statusText.textContent = 'В сети';
        statusIndicator.className = 'status-indicator connected';
        sendBtn.disabled = false;
        addSystemMessage('✅ Подключено к пиру');
    };

    ws.onclose = () => {
        statusText.textContent = 'Отключено';
        statusIndicator.className = 'status-indicator';
        sendBtn.disabled = true;
        addSystemMessage('❌ Соединение закрыто');
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.type === 'message') {
            addMessage(data.from, data.text, false);
        }
    };
}

// ------------------- SEND MESSAGE -------------------

function sendMessage() {
    const input = document.getElementById('message-input');
    const text = input.value.trim();

    if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;

    ws.send(JSON.stringify({
        type: 'message',
        text: text
    }));

    addMessage('Вы', text, true);
    input.value = '';
}

// ------------------- UI HELPERS -------------------

function addMessage(sender, text, isMine) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isMine ? 'my-message' : 'peer-message'}`;

    const header = document.createElement('div');
    header.className = 'message-header';
    header.innerHTML = `
        <span>${sender}</span>
        <span>${new Date().toLocaleTimeString()}</span>
    `;

    const content = document.createElement('div');
    content.textContent = text;

    messageDiv.appendChild(header);
    messageDiv.appendChild(content);

    messagesDiv.appendChild(messageDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function addSystemMessage(text) {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message system';
    messageDiv.textContent = text;
    messagesDiv.appendChild(messageDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

// ------------------- EVENTS -------------------

peerSelect.addEventListener('change', (e) => {
    selectedPeer = e.target.value;
});

document.getElementById('connect-btn').addEventListener('click', connect);

// Initial load
loadPeers();