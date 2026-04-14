// Counter
let count = 0;
function increment() {
    count++;
    const el = document.getElementById('count');
    el.textContent = count;
    el.style.transform = 'scale(1.3)';
    setTimeout(() => el.style.transform = 'scale(1)', 150);

    // Color shift based on count
    const hue = (count * 15) % 360;
    el.style.color = `hsl(${hue}, 70%, 60%)`;
}

// Live clock
function updateClock() {
    const now = new Date();
    const h = String(now.getHours()).padStart(2, '0');
    const m = String(now.getMinutes()).padStart(2, '0');
    const s = String(now.getSeconds()).padStart(2, '0');
    document.getElementById('clock').textContent = `${h}:${m}:${s}`;
}
setInterval(updateClock, 1000);
updateClock();

// Floating particles
const container = document.getElementById('particles');
for (let i = 0; i < 20; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    p.style.left = Math.random() * 100 + '%';
    p.style.animationDuration = (5 + Math.random() * 10) + 's';
    p.style.animationDelay = Math.random() * 5 + 's';
    p.style.width = p.style.height = (2 + Math.random() * 4) + 'px';
    container.appendChild(p);
}

// Feature hover counter
document.querySelectorAll('.feature').forEach(f => {
    let hoverCount = 0;
    f.addEventListener('mouseenter', () => {
        hoverCount++;
        if (hoverCount > 3) {
            f.style.background = 'rgba(124, 58, 237, 0.25)';
            f.style.borderColor = '#7c3aed';
        }
    });
});

console.log('Vortex Demo Page loaded! JS is working in sandbox.');
