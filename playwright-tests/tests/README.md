# `playwright-tests/tests/` — E2E Spec Files

One `*.spec.js` per feature area. Runs against a live Vortex node; uses the fixtures from `../fixtures.js`.

## Selected specs

| File                      | Covers                                                       |
| ------------------------- | ------------------------------------------------------------ |
| `auth.spec.js`            | Register + login (password / seed / passkey), 2FA, QR login. |
| `rooms.spec.js`           | Create / join / leave / rename / delete room, key delivery.  |
| `chat.spec.js`            | Send / edit / delete / react / reply / thread / pin / search.|
| `files.spec.js`           | Upload (single + resumable), download, media viewer.         |
| `calls.spec.js`           | 1-to-1 voice, small group voice, screenshare handshake.     |
| `federation.spec.js`      | Two-node round-trip (requires `NODE2_URL`).                 |
| `i18n.spec.js`            | Language switch persists + English fallback for missing keys.|
| `bots.spec.js`            | Bot create / publish / install / message delivery.           |
| `pwa.spec.js`             | Service worker install + offline dashboard + update flow.    |

## Conventions

- One `test.describe` per feature; one `test` per user-visible outcome.
- Use fixtures — do not re-register users inside test bodies. `fixtures.js` provides `loggedInPage`, `createdRoom`, `pairOfClients`.
- Use role-based selectors (`getByRole`, `getByLabel`) before CSS selectors.
- Never sleep; always `await expect(locator).toBeVisible()` or `await page.waitForResponse(...)`.
- Each spec must clean up after itself unless the test is explicitly marked `@cleanup:manual`.

## Running a single spec

```bash
cd playwright-tests
npx playwright test tests/chat.spec.js --project=chromium --headed
```

## Adding a spec

1. Create `tests/<feature>.spec.js`.
2. Import fixtures: `const { test, expect } = require("../fixtures");`.
3. Cover the happy path + one failure path.
4. Keep run time under 30s per spec; if it's longer, split.

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
