// Генерируем уникальный ID
const clientId = 'user_' + Math.random().toString(36).substr(2, 8);
document.getElementById('client-id').textContent = clientId;

let ws = null;
const messagesDiv = document.getElementById('messages');
const statusText = document.getElementById('status-text');
const statusIndicator = document.getElementById('status-indicator');
const sendBtn = document.getElementById('send-btn');

function connect() {
    ws = new WebSocket(`ws://${window.location.host}/ws/${clientId}`);

    ws.onopen = () => {
        statusText.textContent = 'В сети';
        statusIndicator.className = 'status-indicator connected';
        sendBtn.disabled = false;
        addSystemMessage('✅ Подключено к защищенному чату');
    };

    ws.onclose = () => {
        statusText.textContent = 'Отключено';
        statusIndicator.className = 'status-indicator';
        sendBtn.disabled = true;
        addSystemMessage('❌ Потеряно соединение... Переподключение...');
        setTimeout(connect, 2000);
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);

        switch(data.type) {
            case 'message':
                addMessage(data.from, data.text, false, data.hash, data.encrypted_size);
                break;
            case 'system':
                addSystemMessage(data.message);
                break;
            case 'delivery':
                const lastMsg = messagesDiv.lastChild;
                if (lastMsg && lastMsg.classList.contains('my-message')) {
                    const footer = lastMsg.querySelector('.message-footer');
                    if (footer) {
                        footer.innerHTML += ' ✓';
                    }
                }
                break;
        }
    };
}

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

function addMessage(sender, text, isMine, hash = null, encryptedSize = null) {
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

    const footer = document.createElement('div');
    footer.className = 'message-footer';
    if (hash) {
        footer.innerHTML = `<span class="security-badge">🔒 ${hash}</span>`;
    }
    if (encryptedSize) {
        footer.innerHTML += `<span>📦 ${encryptedSize} байт</span>`;
    }

    messageDiv.appendChild(header);
    messageDiv.appendChild(content);
    if (hash || encryptedSize) {
        messageDiv.appendChild(footer);
    }

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

// Запускаем подключение
connect();