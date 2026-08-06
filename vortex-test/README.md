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

---

## License

Vortex is **dual-licensed** under the **GNU Affero General Public License
v3.0-or-later** (see `LICENSE`) or a **commercial license** (see
`LICENSE-COMMERCIAL.md`).

```
Copyright (C) 2026 Andrey Karavaev, Boris Maltsev

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
```

---

## Authors

**Boris Maltsev**

[![GitHub](https://img.shields.io/badge/GitHub-BorisMalts-181717?style=flat-square&logo=github)](https://github.com/BorisMalts)

**Andrey Karavaev**

[![GitHub](https://img.shields.io/badge/GitHub-Andre--wb-181717?style=flat-square&logo=github)](https://github.com/Andre-wb)
