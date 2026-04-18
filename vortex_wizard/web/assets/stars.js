/* Minimalistic multi-layer starfield.
 *
 * Adapted from the portfolio project's stars.js. Tuned down for a quiet,
 * minimalistic look: fewer stars, no color glow, subtle twinkle, gentle
 * cursor parallax. Pure white pinpoints on a black canvas — no decoration.
 */
(() => {
    'use strict';

    if (window.__vortexStarsInstalled) return;
    window.__vortexStarsInstalled = true;

    document.addEventListener('DOMContentLoaded', () => {
        if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
            return;
        }

        const isTouch =
            ('ontouchstart' in window) ||
            navigator.maxTouchPoints > 0 ||
            navigator.msMaxTouchPoints > 0;

        const canvas = document.createElement('canvas');
        Object.assign(canvas.style, {
            position: 'fixed',
            inset: '0',
            width: '100%',
            height: '100%',
            pointerEvents: 'none',
            zIndex: '0',
        });
        canvas.id = 'vortex-stars';
        document.body.prepend(canvas);
        const ctx = canvas.getContext('2d', { alpha: true });

        const small = window.innerWidth < 1024;
        // Global density multiplier — tuned low for a calm, minimal look.
        const density = small ? 0.25 : 0.45;
        const alphaMul = 0.65;

        // Only 5 layers (vs 9), no "near" bright stars, no color glow.
        const LAYERS_BASE = [
            { cnt: 260, cursorSpeed: 0.6, sz: [0.14, 0.40], al: [0.18, 0.38] },
            { cnt: 200, cursorSpeed: 1.0, sz: [0.22, 0.55], al: [0.24, 0.48] },
            { cnt: 150, cursorSpeed: 1.6, sz: [0.30, 0.70], al: [0.32, 0.58] },
            { cnt: 100, cursorSpeed: 2.3, sz: [0.40, 0.90], al: [0.40, 0.70] },
            { cnt:  60, cursorSpeed: 3.2, sz: [0.55, 1.10], al: [0.48, 0.82] },
        ];

        const LAYERS = LAYERS_BASE.map(L => ({
            ...L,
            cnt: Math.round(L.cnt * density),
            al: [L.al[0] * alphaMul, L.al[1] * alphaMul],
        }));

        let stars = [], W = 0, H = 0;
        let dirX = 0, dirY = 0;
        let smDirX = 0, smDirY = 0;
        let tick = 0;

        function resize() {
            const dpr = Math.min(window.devicePixelRatio || 1, 2);
            W = window.innerWidth;
            H = window.innerHeight;
            canvas.width = W * dpr;
            canvas.height = H * dpr;
            canvas.style.width = W + 'px';
            canvas.style.height = H + 'px';
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        }

        function initStars() {
            stars = [];
            LAYERS.forEach((L, li) => {
                for (let i = 0; i < L.cnt; i++) {
                    stars.push({
                        x: Math.random() * W,
                        y: Math.random() * H,
                        sz: L.sz[0] + Math.random() * (L.sz[1] - L.sz[0]),
                        al: L.al[0] + Math.random() * (L.al[1] - L.al[0]),
                        tp: Math.random() * Math.PI * 2,
                        ts: 0.003 + Math.random() * 0.008,
                        li,
                    });
                }
            });
        }

        if (!isTouch) {
            window.addEventListener('mousemove', e => {
                dirX = (e.clientX / W - 0.5) * 2;
                dirY = (e.clientY / H - 0.5) * 2;
            }, { passive: true });
        }

        function draw() {
            requestAnimationFrame(draw);
            tick++;

            if (!isTouch) {
                smDirX += (dirX - smDirX) * 0.04;
                smDirY += (dirY - smDirY) * 0.04;
            }

            ctx.clearRect(0, 0, W, H);

            for (let i = 0; i < stars.length; i++) {
                const s = stars[i];
                const L = LAYERS[s.li];

                // Gentle cursor parallax — no autonomous drift so the field feels still.
                const moveX = smDirX * L.cursorSpeed * 0.15;
                const moveY = smDirY * L.cursorSpeed * 0.15;

                s.x = ((s.x + moveX) % W + W) % W;
                s.y = ((s.y + moveY) % H + H) % H;

                // Subtle twinkle — always visible, never drops to zero
                const tw = 0.75 + 0.25 * Math.sin(tick * s.ts + s.tp);
                const a  = s.al * tw;

                // Pure white star — no colored glow
                ctx.beginPath();
                ctx.arc(s.x, s.y, s.sz, 0, 6.2832);
                ctx.fillStyle = 'rgba(255,255,255,' + a.toFixed(3) + ')';
                ctx.fill();
            }
        }

        resize();
        initStars();
        draw();

        let rt;
        window.addEventListener('resize', () => {
            clearTimeout(rt);
            rt = setTimeout(() => { resize(); initStars(); }, 120);
        });
    });
})();
