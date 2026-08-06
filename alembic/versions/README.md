# `alembic/versions/` — Migration History

One Python file per schema revision. The files form a singly-linked list — each has a `down_revision` pointer to the previous migration.

## Reading the history

```bash
alembic history --verbose       # chronological graph
alembic current                 # head the connected DB is at
alembic show <revision>         # full details of a specific migration
```

## Generating a new revision

```bash
# Always from the repo root, with the venv active
alembic revision --autogenerate -m "short description"
```

Autogen reads `app.base.Base.metadata` and produces a starter migration. **Always review** the generated file:

- Check renames didn't become drop+add.
- Add data migrations (`op.execute(...)` or a scoped Session) where needed.
- Write a sensible `downgrade()`.

## File contents

Every migration file has:

```python
revision      = "abcdef123456"
down_revision = "0123456789ab"
branch_labels = None
depends_on    = None

def upgrade() -> None: ...
def downgrade() -> None: ...
```

## Conventions

- One logical change per migration. Don't bundle "add column X" + "rename table Y" into one file.
- No ORM model imports. Use `sqlalchemy.Table(...)` or raw `op.execute(sa.text(...))`.
- Batch mode on SQLite is auto-enabled via `render_as_batch=True` in `../env.py` — writing SQLite-safe ALTER sequences is essentially free.
- If a migration is lossy (drops a column with data), add a one-line comment explaining why the operator can't undo it.

## Troubleshooting

- **"Can't locate revision identified by <hex>"** — make sure every file downloaded; a missing middle migration breaks the chain.
- **Diverged heads** — happens when two branches both generate a migration; run `alembic merge heads -m "merge <a> and <b>"` to produce a merge migration.

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
