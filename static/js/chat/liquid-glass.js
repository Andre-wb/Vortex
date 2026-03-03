let _lgReady      = false;
let _lgSvgReady   = false;
let _lgHoudiniReg = false;
let _lgObserver   = null;
let _lgStyleEl    = null;
let _lgSvgEl      = null;

function _isMobileGPU() {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return true;
    const dbgInfo  = gl.getExtension('WEBGL_debug_renderer_info');
    const renderer = dbgInfo ? gl.getParameter(dbgInfo.UNMASKED_RENDERER_WEBGL).toLowerCase() : '';
    return /adreno|mali|powervr|apple gpu|sgx/.test(renderer);
}

function _registerHoudini() {
    if (_lgHoudiniReg || !window.CSS?.registerProperty) return;
    _lgHoudiniReg = true;
    [
        { name: '--lg-mx',   syntax: '<percentage>', inherits: false, initialValue: '50%'  },
        { name: '--lg-my',   syntax: '<percentage>', inherits: false, initialValue: '30%'  },
        { name: '--lg-irid', syntax: '<angle>',      inherits: false, initialValue: '0deg' },
    ].forEach(p => { try { CSS.registerProperty(p); } catch (_) {} });
}

function _injectSVG(useDistort) {
    if (_lgSvgReady) return;
    _lgSvgReady = true;
    _lgSvgEl = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    _lgSvgEl.setAttribute('style', 'position:fixed;width:0;height:0;overflow:hidden;pointer-events:none;z-index:-1');
    _lgSvgEl.setAttribute('aria-hidden', 'true');
    if (useDistort) {
        _lgSvgEl.innerHTML = `<defs><filter id="lg-distort" x="-22%" y="-22%" width="144%" height="144%" color-interpolation-filters="sRGB"><feTurbulence type="turbulence" baseFrequency="0.018 0.022" numOctaves="3" seed="4" result="turb"><animate attributeName="baseFrequency" values="0.018 0.022;0.023 0.017;0.018 0.022" dur="8s" repeatCount="indefinite" calcMode="spline" keySplines=".45 0 .55 1;.45 0 .55 1"/><animate attributeName="seed" values="4;9;2;14;6;4" dur="22s" repeatCount="indefinite" calcMode="discrete"/></feTurbulence><feDisplacementMap in="SourceGraphic" in2="turb" scale="5.5" xChannelSelector="R" yChannelSelector="G" result="dR"/><feDisplacementMap in="SourceGraphic" in2="turb" scale="3.8" xChannelSelector="G" yChannelSelector="B" result="dG"/><feDisplacementMap in="SourceGraphic" in2="turb" scale="2.2" xChannelSelector="B" yChannelSelector="R" result="dB"/><feColorMatrix in="dR" type="matrix" values="1 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 1 0" result="oR"/><feColorMatrix in="dG" type="matrix" values="0 0 0 0 0  0 1 0 0 0  0 0 0 0 0  0 0 0 1 0" result="oG"/><feColorMatrix in="dB" type="matrix" values="0 0 0 0 0  0 0 0 0 0  0 0 1 0 0  0 0 0 1 0" result="oB"/><feBlend in="oR" in2="oG" mode="screen" result="rg"/><feBlend in="rg" in2="oB" mode="screen" result="rgb"/><feComposite in="rgb" in2="SourceGraphic" operator="atop"/></filter></defs>`;
    } else {
        _lgSvgEl.innerHTML = `<defs><filter id="lg-distort"><feComposite operator="atop"/></filter></defs>`;
    }
    document.body.appendChild(_lgSvgEl);
}

function _injectCSS() {
    if (document.getElementById('liquid-glass-style')) return;
    _lgStyleEl = document.createElement('style');
    _lgStyleEl.id = 'liquid-glass-style';
    _lgStyleEl.textContent = `
    .lg-outer {
        display: inline-flex;
        position: relative;
        margin:  -9px;
        padding:  9px;
        filter: url(#lg-distort);
    }
    .lg-outer.block { display: block; }
    .lg-outer.flex  { display: flex; }
    .lg-outer.grid  { display: grid; }

    .lg {
        --lg-mx: 50%;
        --lg-my: 30%;
        --lg-irid: 0deg;
        position: relative;
        isolation: isolate;
        overflow: hidden;
        border-radius: 14px;
        transform: translateZ(0);
        will-change: transform;
        background: rgba(255, 255, 255, 0.035);
        backdrop-filter:         blur(20px) saturate(160%) brightness(1.08);
        -webkit-backdrop-filter: blur(20px) saturate(160%) brightness(1.08);
        border-top:    1px solid rgba(255, 255, 255, 0.42);
        border-left:   1px solid rgba(255, 255, 255, 0.22);
        border-right:  1px solid rgba(255, 255, 255, 0.08);
        border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        box-shadow:
            inset 0  1.5px 0  rgba(255, 255, 255, 0.30),
            inset 1px 0    0  rgba(255, 255, 255, 0.10),
            inset 0 -1px   0  rgba(0, 0, 0, 0.12),
            0  4px 16px -2px  rgba(0, 0, 0, 0.30),
            0 12px 40px -8px  rgba(0, 0, 0, 0.20),
            0  1px  3px       rgba(0, 0, 0, 0.18),
            0  0   36px -14px rgba(180, 160, 255, 0.18);
        transition:
            transform    0.20s cubic-bezier(0.34, 1.56, 0.64, 1),
            box-shadow   0.20s ease,
            background   0.20s ease,
            border-color 0.20s ease;
        animation: lg-irid-spin 12s linear infinite;
    }

    .lg::before {
        content: '';
        position: absolute;
        inset: 0;
        border-radius: inherit;
        pointer-events: none;
        z-index: 1;
        background:
            radial-gradient(ellipse 55% 38% at var(--lg-mx) var(--lg-my),
                rgba(255,255,255,0.20) 0%, rgba(255,255,255,0.06) 40%, transparent 64%),
            radial-gradient(ellipse 92% 72% at var(--lg-mx) var(--lg-my),
                rgba(255,255,255,0.04) 0%, transparent 68%),
            linear-gradient(148deg,
                rgba(255,255,255,0.10) 0%, rgba(255,255,255,0.02) 38%,
                transparent 65%, rgba(255,255,255,0.03) 100%);
        transition: background 0.04s linear;
    }

    .lg::after {
        content: '';
        position: absolute;
        inset: 0;
        border-radius: inherit;
        pointer-events: none;
        z-index: 2;
        background: conic-gradient(
            from var(--lg-irid) at 50% 50%,
            hsla(210,100%,85%,0.000), hsla(255,100%,90%,0.038),
            hsla(300,100%,85%,0.025), hsla(345,100%,90%,0.038),
            hsla( 30,100%,85%,0.025), hsla( 90,100%,90%,0.038),
            hsla(150,100%,85%,0.025), hsla(210,100%,85%,0.000)
        );
        mix-blend-mode: overlay;
        opacity: 0.9;
        animation: lg-irid-spin 12s linear infinite;
    }

    .lg-grain {
        position: absolute;
        inset: 0;
        border-radius: inherit;
        pointer-events: none;
        z-index: 3;
        will-change: background-position;
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.80' numOctaves='4' stitchTiles='stitch'/%3E%3CfeColorMatrix type='saturate' values='0'/%3E%3C/filter%3E%3Crect width='200' height='200' filter='url(%23n)' opacity='0.9'/%3E%3C/svg%3E");
        background-size: 200px 200px;
        mix-blend-mode: soft-light;
        opacity: 0.08;
        animation: lg-grain-shift 0.14s steps(1) infinite;
    }

    .lg > * { position: relative; z-index: 4; }

    .lg.lg-interactive { cursor: pointer; }
    .lg.lg-interactive:hover {
        background: rgba(255, 255, 255, 0.055);
        border-top-color:  rgba(255, 255, 255, 0.52);
        border-left-color: rgba(255, 255, 255, 0.28);
        box-shadow:
            inset 0  1.5px 0  rgba(255, 255, 255, 0.38),
            inset 1px 0    0  rgba(255, 255, 255, 0.14),
            inset 0 -1px   0  rgba(0, 0, 0, 0.10),
            0  8px 24px -4px  rgba(0, 0, 0, 0.38),
            0 20px 52px -8px  rgba(0, 0, 0, 0.26),
            0  2px  5px       rgba(0, 0, 0, 0.22),
            0  0   52px -14px rgba(160, 130, 255, 0.28);
        transform: translateY(-1.5px) translateZ(0);
    }
    .lg.lg-interactive:active {
        transform: translateY(0.5px) scale(0.992) translateZ(0);
        transition-duration: 0.08s;
    }

    .lg-reply {
        display: flex;
        flex-direction: column;
        gap: 2px;
        padding: 7px 11px;
        margin-bottom: 8px;
        border-radius: 8px;
        box-shadow:
            inset 2.5px 0   0 rgba(255,255,255,0.32),
            inset 0     1px 0 rgba(255,255,255,0.14),
            inset 0    -1px 0 rgba(0,0,0,0.10),
            0 2px 8px -2px rgba(0,0,0,0.20);
    }

    .lg-reply .lg-sender {
        font-size: 11px;
        font-weight: 700;
        color: rgba(255,255,255,0.82);
        letter-spacing: 0.015em;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        position: relative;
        z-index: 4;
    }

    .lg-reply .lg-text {
        font-size: 12px;
        color: rgba(255,255,255,0.46);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        position: relative;
        z-index: 4;
    }

    .lg.lg-own {
        background: rgba(120, 80, 210, 0.05);
        border-top-color:  rgba(210,175,255,0.30);
        border-left-color: rgba(210,175,255,0.16);
        box-shadow:
            inset 0  1.5px 0  rgba(225,195,255,0.22),
            inset 1px 0    0  rgba(200,170,255,0.10),
            inset 0 -1px   0  rgba(0,0,0,0.12),
            0  4px 16px -2px  rgba(0,0,0,0.28),
            0 12px 36px -8px  rgba(0,0,0,0.18),
            0  0   28px -10px rgba(150,100,255,0.18);
    }
    .lg.lg-own::after {
        background: conic-gradient(
            from var(--lg-irid) at 50% 50%,
            hsla(250,100%,85%,0.000), hsla(280,100%,90%,0.045),
            hsla(310,100%,85%,0.030), hsla(340,100%,90%,0.045),
            hsla(270,100%,85%,0.030), hsla(250,100%,85%,0.000)
        );
    }
    .lg.lg-own .lg-sender { color: rgba(222,196,255,0.88); }
    .lg.lg-own:hover {
        background: rgba(130,90,220,0.08);
        border-top-color: rgba(210,175,255,0.42);
    }

    @keyframes lg-irid-spin {
        from { --lg-irid:   0deg; }
        to   { --lg-irid: 360deg; }
    }

    @keyframes lg-grain-shift {
        0%  { background-position:   0px   0px; }
        12% { background-position: -42px -28px; }
        25% { background-position:  28px  46px; }
        37% { background-position: -64px  18px; }
        50% { background-position:  12px -54px; }
        62% { background-position: -36px  66px; }
        75% { background-position:  58px  -8px; }
        87% { background-position: -16px  38px; }
    }

    @media (prefers-reduced-motion: reduce) {
        .lg            { animation: none; transition: none; }
        .lg::after     { animation: none; }
        .lg-grain      { animation: none; will-change: auto; }
    }
    `;
    document.head.appendChild(_lgStyleEl);
}

const _tracked = new WeakSet();

function _attachPointerTracking(el) {
    if (_tracked.has(el)) return;
    _tracked.add(el);
    el.addEventListener('pointermove', e => {
        const r = el.getBoundingClientRect();
        el.style.setProperty('--lg-mx', ((e.clientX - r.left) / r.width  * 100).toFixed(1) + '%');
        el.style.setProperty('--lg-my', ((e.clientY - r.top)  / r.height * 100).toFixed(1) + '%');
    }, { passive: true });
    el.addEventListener('pointerleave', () => {
        el.style.setProperty('--lg-mx', '50%');
        el.style.setProperty('--lg-my', '30%');
    }, { passive: true });
}

function _startObserver() {
    const attach = node => {
        if (!(node instanceof HTMLElement)) return;
        if (node.classList.contains('lg')) _attachPointerTracking(node);
        node.querySelectorAll?.('.lg').forEach(_attachPointerTracking);
    };
    document.querySelectorAll('.lg').forEach(_attachPointerTracking);
    _lgObserver = new MutationObserver(ms => ms.forEach(m => m.addedNodes.forEach(attach)));
    _lgObserver.observe(document.body, { childList: true, subtree: true });
}

const _BLOCK_DISPLAYS = new Set([
    'block', 'flex', 'grid',
    'inline-block', 'inline-flex', 'inline-grid',
    'contents', 'table', 'list-item',
]);

export function initLiquidGlass() {
    if (_lgReady) return;
    _lgReady = true;
    _registerHoudini();
    _injectSVG(!_isMobileGPU());
    _injectCSS();
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _startObserver, { once: true });
    } else {
        _startObserver();
    }
}

export function destroyLiquidGlass() {
    _lgObserver?.disconnect();
    _lgObserver   = null;
    _lgStyleEl?.remove();
    _lgStyleEl    = null;
    _lgSvgEl?.remove();
    _lgSvgEl      = null;
    _lgReady      = false;
    _lgSvgReady   = false;
    _lgHoudiniReg = false;
}

export function wrapWithDistortion(el) {
    const w = document.createElement('div');
    w.className = 'lg-outer';
    const d = window.getComputedStyle(el).display;
    if (_BLOCK_DISPLAYS.has(d)) {
        const cls = (d === 'flex' || d === 'inline-flex') ? 'flex'
            : (d === 'grid' || d === 'inline-grid') ? 'grid'
                : 'block';
        w.classList.add(cls);
    }
    el.parentNode?.insertBefore(w, el);
    w.appendChild(el);
    return w;
}

export function createReplyQuote(sender, text, isOwn = false, onClick) {
    initLiquidGlass();
    const el = document.createElement('div');
    el.className = `lg lg-reply lg-interactive${isOwn ? ' lg-own' : ''}`;

    const grain = document.createElement('div');
    grain.className = 'lg-grain';
    el.appendChild(grain);

    const senderEl = document.createElement('span');
    senderEl.className   = 'lg-sender';
    senderEl.textContent = sender;

    const textEl = document.createElement('span');
    textEl.className   = 'lg-text';
    textEl.textContent = text;

    el.appendChild(senderEl);
    el.appendChild(textEl);

    if (onClick) {
        el.addEventListener('click', e => { e.stopPropagation(); onClick(); });
    }
    _attachPointerTracking(el);
    return el;
}