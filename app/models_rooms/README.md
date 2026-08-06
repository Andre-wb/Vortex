# `app/models_rooms/` — Room-scoped SQLAlchemy Models

ORM models that are **tightly coupled to rooms** — they are partitioned by `room_id` and generally migrate together. Split out from `../models/` so the global tables (User, Bot, Contact, etc.) can evolve independently of room-internal schemas.

## Files

| File             | Model(s)                                                                                 |
| ---------------- | ---------------------------------------------------------------------------------------- |
| `rooms.py`       | `Room`, `RoomMember`, `RoomInvite`. The core room table.                                 |
| `messages.py`    | `Message`, `MessageEdit`, `MessageReaction`, `MessagePoll`, `MessagePoll{Option,Vote}`, `Thread`, `Attachment`. |
| `encryption.py`  | `RoomKey`, `RoomKeyDelivery`, `RoomRatchetState`. Per-room key material and ratchet bookkeeping. |
| `permissions.py` | `Role`, `RoomRole`, `Permission`, `RolePermission`. Fine-grained per-room RBAC.          |
| `admin.py`       | `RoomBan`, `RoomKick`, `RoomAuditEntry`. Moderator-visible log.                          |
| `public_keys.py` | `RoomPublicKeyRegistry`, `SealedRoomKey`. Public-key room support (anyone can join without per-user invite). |
| `enums.py`       | Shared enums — `RoomKind`, `MessageKind`, `ReactionKind`, `StreamState`, …              |
| `spaces.py`      | `Space`, `SpaceCategory`, `SpaceMember`, `SpaceRole`, `SpaceEmoji`. Community container around rooms. |
| `feeds.py`       | `ChannelFeed`, `ChannelPost`, `ChannelComment`, `ChannelSubscriber`, `RssFeed`.          |
| `stickers.py`    | `StickerPack`, `Sticker`, `StickerInstall`.                                              |
| `collections.py` | `Folder`, `FolderItem` — client-managed room organisation.                               |
| `discussions.py` | `ForumTopic`, `ForumPost`. Forum-style rooms.                                            |
| `analytics.py`   | `RoomAnalyticsDaily`, `RoomAnalyticsHourly`. Aggregates for the admin dashboard.         |
| `federation.py`  | `FederatedMirror`, `FederationSeq`. Per-room federation bookkeeping.                     |

## Conventions

- Every table carries `room_id` as a foreign key to `rooms.id`.
- Indexes on `(room_id, created_at)` for append-only tables (messages, audit, analytics).
- Composite primary keys on bridge tables (`room_id + user_id` for memberships, `room_id + role_id` for role assignments).
- **Key material** in `encryption.py` is encrypted-at-rest with a per-node master key before it hits the DB — the plaintext lives only in memory, and only for rooms the node is an active member of.

## Partitioning in PostgreSQL

For large deployments, `messages` and `analytics` tables are declared partitionable on `room_id` modulo N. The partition DDL is **not** in this folder (it's in `alembic/versions/<rev>_partition_messages.py`) so operators can pick the shard count at migration time.

## Testing

Fixtures for these models live in `conftest.py` at the repo root (`room_with_members`, `message_with_thread`, `encrypted_room`). Most feature tests under `app/tests/` consume them.

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
