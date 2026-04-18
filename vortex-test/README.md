# vortex-test

Standalone local preview of the `vortexx.sol` controller website,
populated with fake data covering every state the UI can show:

- **Entry URLs**: Cloudflare tunnel, Tor `.onion`, IPFS, direct
- **Mirrors**: healthy / dead / unchecked / no-Tor-proxy / IPFS
- **Peers**: sealed+fresh (weight 1.0), sealed+stale (0.8 / 0.5 / 0.2),
  unsealed (capped 0.5), Solana-only dual-verified, controller-only,
  unverified bootstrap
- **Integrity**: verified build with 158 files, real Ed25519 signature

Nothing connects to the real network — every HTTP response comes from
`serve.py` and is signed with a throwaway key generated at startup.

## Run

```bash
cd vortex-test
pip install fastapi uvicorn cryptography
python serve.py
# → open http://localhost:7700
```

## Files

```
vortex-test/
├── serve.py      # mock FastAPI server + fake data
├── public/       # copied-verbatim controller website
│   ├── index.html
│   ├── style.css
│   ├── app.js
│   ├── i18n.js
│   ├── favicon.ico
│   ├── icons/
│   └── locales/  # 130+ languages
└── README.md
```

## What to look at

- Open in Safari / Chrome — the signature check in `app.js` verifies
  every envelope against the pubkey shown in the fingerprint card.
- Pick a language from the top-right picker to see RTL + Cyrillic + CJK
  variations.
- Ctrl-click → Inspect → Network to see the shape of every mock JSON
  response (useful for frontend work).
- Edit `serve.py` → change `ENTRY_URLS`, `MIRRORS`, `PEERS` → reload.
