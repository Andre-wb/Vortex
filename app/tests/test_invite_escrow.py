"""O4: invite-escrow схема + storage (offline-join по анонимной ссылке, ADR-005).

Double-gate: сервер гейтит FETCH по ЧЛЕНСТВУ (_require_member), фрагмент-priv —
DECRYPT. Инвалидация на КАЖДОЙ ротации room key (rotate/kick/leave).
"""

import secrets
from datetime import datetime, timedelta, timezone

import pytest
from conftest import login_user, make_user, random_str


def _set_invite_expiry(room_id, invite_pub, when):
    """Прямо выставляет expires_at инвайта (для TTL-тестов) через сессию app-БД."""
    from app.database import SessionLocal
    from app.models_rooms import RoomInvite

    db = SessionLocal()
    try:
        iv = db.query(RoomInvite).filter(RoomInvite.room_id == room_id, RoomInvite.invite_pub == invite_pub).first()
        assert iv is not None
        iv.expires_at = when
        db.commit()
        return iv.expires_at
    finally:
        db.close()


def _get_invite_expiry(room_id, invite_pub):
    from app.database import SessionLocal
    from app.models_rooms import RoomInvite

    db = SessionLocal()
    try:
        iv = db.query(RoomInvite).filter(RoomInvite.room_id == room_id, RoomInvite.invite_pub == invite_pub).first()
        return iv.expires_at if iv else None
    finally:
        db.close()


def _classical_key() -> dict:
    return {"ephemeral_pub": secrets.token_hex(32), "ciphertext": secrets.token_hex(60)}


def _escrow_body(hybrid=False) -> dict:
    body = {"invite_pub": secrets.token_hex(32)}
    if hybrid:
        body.update(
            {
                "hybrid": True,
                "x25519_ephemeral_pub": secrets.token_hex(32),
                "kyber_ciphertext": secrets.token_hex(1088),
                "ciphertext": secrets.token_hex(60),
                "invite_kyber_pub": secrets.token_hex(1184),
            }
        )
    else:
        body.update({"ephemeral_pub": secrets.token_hex(32), "ciphertext": secrets.token_hex(60)})
    return body


def _create_room(client, headers):
    r = client.post(
        "/api/rooms",
        json={
            "name": f"room_{random_str(6)}",
            "is_private": True,
            "encrypted_room_key": _classical_key(),
        },
        headers=headers,
    )
    assert r.status_code in (200, 201), r.text
    b = r.json()
    room = b.get("room", b)
    return room.get("id") or b.get("id"), room.get("invite_code") or b.get("invite_code")


def _store(client, headers, room_id, body):
    return client.post(f"/api/rooms/{room_id}/invite-escrow", json=body, headers=headers)


def _fetch(client, headers, room_id, invite_pub):
    return client.get(f"/api/rooms/{room_id}/invite-escrow", params={"invite_pub": invite_pub}, headers=headers)


def _list_invites(client, headers, room_id):
    return client.get(f"/api/rooms/{room_id}/invites", headers=headers).json()["invites"]


@pytest.fixture
def enforce(monkeypatch):
    monkeypatch.setattr("app.config.Config.JOIN_APPROVAL_ENFORCED", True)


def test_store_fetch_hybrid_roundtrip(client):
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, _ = _create_room(client, o_h)
    body = _escrow_body(hybrid=True)

    assert _store(client, o_h, room_id, body).status_code == 200
    got = _fetch(client, o_h, room_id, body["invite_pub"]).json()
    assert got["has_escrow"] is True
    assert got.get("hybrid") is True
    assert got["kyber_ciphertext"] == body["kyber_ciphertext"]
    assert got["x25519_ephemeral_pub"] == body["x25519_ephemeral_pub"]


def test_store_fetch_classical(client):
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, _ = _create_room(client, o_h)
    body = _escrow_body(hybrid=False)
    assert _store(client, o_h, room_id, body).status_code == 200
    got = _fetch(client, o_h, room_id, body["invite_pub"]).json()
    assert got["ephemeral_pub"] == body["ephemeral_pub"]
    assert "kyber_ciphertext" not in got


def test_fetch_requires_membership(client):
    """LOAD-BEARING: не-член НЕ может забрать escrow (double-gate, не single)."""
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, _ = _create_room(client, o_h)
    body = _escrow_body()
    _store(client, o_h, room_id, body)

    outsider = make_user(client, suffix=f"x{random_str(6)}")
    x_h = login_user(client, outsider["username"], outsider["password"])
    assert _fetch(client, x_h, room_id, body["invite_pub"]).status_code == 403


def test_pending_joiner_cannot_fetch_escrow(client, enforce):
    """LOAD-BEARING: pending-заявитель (O3, не RoomMember) НЕ забирает escrow —
    иначе escrow обошёл бы апрув (double-gate по членству, не по ссылке)."""
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, invite = _create_room(client, o_h)
    client.put(f"/api/rooms/{room_id}", json={"join_approval": True}, headers=o_h)
    body = _escrow_body()
    _store(client, o_h, room_id, body)

    stranger = make_user(client, suffix=f"s{random_str(6)}")
    s_h = login_user(client, stranger["username"], stranger["password"])
    jr = client.post(f"/api/rooms/join/{invite}", headers=s_h)
    assert jr.json().get("pending") is True  # заявитель — не член
    assert _fetch(client, s_h, room_id, body["invite_pub"]).status_code == 403


def test_store_accepts_exact_client_body_shape(client):
    """Seam client↔server (advisor): O5a-эндпоинт принимает ТОЧНО ту форму тела,
    что строит клиентский createInviteLink (O5b) — invite_pub + invite_kyber_pub +
    полный гибрид-конверт, реальные длины. Иначе Pydantic молча отбросил бы (K4a-урок)."""
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, _ = _create_room(client, o_h)
    # Ровно поля/длины, что шлёт createInviteLink:
    body = {
        "invite_pub": secrets.token_hex(32),  # X25519 pub, 64 hex
        "invite_kyber_pub": secrets.token_hex(1184),  # ML-KEM-768 pub, 2368 hex
        "hybrid": True,
        "x25519_ephemeral_pub": secrets.token_hex(32),  # 64 hex
        "kyber_ciphertext": secrets.token_hex(1088),  # ML-KEM ct, 2176 hex
        "ciphertext": secrets.token_hex(60),  # 120 hex
    }
    assert _store(client, o_h, room_id, body).status_code == 200
    got = _fetch(client, o_h, room_id, body["invite_pub"]).json()
    assert got["has_escrow"] is True
    assert got["kyber_ciphertext"] == body["kyber_ciphertext"]  # kyber НЕ отброшен
    inv = next((i for i in _list_invites(client, o_h, room_id) if i["invite_pub"] == body["invite_pub"]), None)
    assert inv and inv["invite_kyber_pub"] == body["invite_kyber_pub"]


def test_ttl_set_on_new_invite_and_fresh_served(client):
    """O7: store ставит будущий expires_at; свежий инвайт (в пределах TTL) отдаётся."""
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, _ = _create_room(client, o_h)
    body = _escrow_body()
    _store(client, o_h, room_id, body)
    exp = _get_invite_expiry(room_id, body["invite_pub"])
    assert exp is not None  # TTL проставлен
    assert _fetch(client, o_h, room_id, body["invite_pub"]).json()["has_escrow"] is True


def _escrow_row_exists(room_id, invite_pub):
    from app.database import SessionLocal
    from app.models_rooms import RoomInviteEscrow

    db = SessionLocal()
    try:
        return (
            db.query(RoomInviteEscrow)
            .filter(RoomInviteEscrow.room_id == room_id, RoomInviteEscrow.invite_pub == invite_pub)
            .first()
            is not None
        )
    finally:
        db.close()


def test_expired_invite_escrow_not_served(client):
    """LOAD-BEARING O7: ЖИВАЯ escrow-строка + ИСТЁКШИЙ invite → fetch → has_escrow=false
    (leak-window bounded; проверка на invite.expires_at ДО escrow-lookup — единственная
    точка, на которой держится TTL)."""
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, _ = _create_room(client, o_h)
    body = _escrow_body()
    _store(client, o_h, room_id, body)
    _set_invite_expiry(room_id, body["invite_pub"], datetime.now(timezone.utc) - timedelta(hours=1))
    # escrow-строка ЖИВА (истёк только invite) — доказываем, что не-отдача из-за TTL, не из-за отсутствия escrow
    assert _escrow_row_exists(room_id, body["invite_pub"]) is True
    assert _fetch(client, o_h, room_id, body["invite_pub"]).json()["has_escrow"] is False


def test_expired_invite_excluded_from_list(client):
    """LOAD-BEARING O7: истёкший инвайт не в /invites → re-wrap его НЕ ре-армит
    (иначе TTL декоративен — ротация оживляла бы истёкшую ссылку вечно)."""
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, _ = _create_room(client, o_h)
    body = _escrow_body()
    _store(client, o_h, room_id, body)
    _set_invite_expiry(room_id, body["invite_pub"], datetime.now(timezone.utc) - timedelta(hours=1))
    assert not any(i["invite_pub"] == body["invite_pub"] for i in _list_invites(client, o_h, room_id))


def test_rewrap_does_not_extend_ttl(client):
    """O7: re-wrap (повторный store) НЕ сбрасывает expires_at — иначе постоянный
    re-wrap продлевал бы утёкшую ссылку бесконечно."""
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, _ = _create_room(client, o_h)
    body = _escrow_body(hybrid=True)
    _store(client, o_h, room_id, body)
    exp1 = _get_invite_expiry(room_id, body["invite_pub"])
    # re-wrap: тот же invite_pub, другой конверт
    body2 = dict(body)
    body2["ciphertext"] = secrets.token_hex(60)
    _store(client, o_h, room_id, body2)
    exp2 = _get_invite_expiry(room_id, body["invite_pub"])
    assert exp1 == exp2  # TTL не продлён


def test_list_invites_requires_membership(client):
    """/invites (re-wrap target list) гейтится членством — не-член → 403."""
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, _ = _create_room(client, o_h)
    _store(client, o_h, room_id, _escrow_body())
    outsider = make_user(client, suffix=f"x{random_str(6)}")
    x_h = login_user(client, outsider["username"], outsider["password"])
    assert client.get(f"/api/rooms/{room_id}/invites", headers=x_h).status_code == 403


def test_store_requires_caller_has_key(client):
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, invite = _create_room(client, o_h)
    # B вступает (член без ключа) → не может создать escrow
    b = make_user(client, suffix=f"b{random_str(6)}")
    b_h = login_user(client, b["username"], b["password"])
    client.post(f"/api/rooms/join/{invite}", headers=b_h)
    assert _store(client, b_h, room_id, _escrow_body()).status_code == 403


def test_store_registers_persistent_invite(client):
    """store создаёт RoomInvite (личность) — виден в /invites (для re-wrap)."""
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, _ = _create_room(client, o_h)
    body = _escrow_body(hybrid=True)
    _store(client, o_h, room_id, body)
    invites = _list_invites(client, o_h, room_id)
    row = next((i for i in invites if i["invite_pub"] == body["invite_pub"]), None)
    assert row is not None
    assert row["invite_kyber_pub"] == body["invite_kyber_pub"]  # PQ-pub персистит


def test_revoke_removes_invite_and_escrow(client):
    """revoke удаляет И обёртку, И личность — иначе ротация оживила бы утёкшую ссылку."""
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, _ = _create_room(client, o_h)
    body = _escrow_body()
    _store(client, o_h, room_id, body)
    r = client.delete(f"/api/rooms/{room_id}/invite-escrow", params={"invite_pub": body["invite_pub"]}, headers=o_h)
    assert r.status_code == 200 and r.json()["revoked"] is True
    assert _fetch(client, o_h, room_id, body["invite_pub"]).json()["has_escrow"] is False
    assert not any(i["invite_pub"] == body["invite_pub"] for i in _list_invites(client, o_h, room_id))


def test_rotate_deletes_escrow_but_invite_persists(client):
    """LOAD-BEARING two-table: ротация удаляет ОБЁРТКУ (escrow), но ЛИЧНОСТЬ
    (RoomInvite) персистит → онлайн-член сможет re-wrap по persisted invite_pub
    (иначе invite_pub терялся бы и re-wrap был невозможен)."""
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, _ = _create_room(client, o_h)
    body = _escrow_body(hybrid=True)
    _store(client, o_h, room_id, body)

    assert client.post(f"/api/rooms/{room_id}/rotate-key", headers=o_h).status_code == 200
    assert _fetch(client, o_h, room_id, body["invite_pub"]).json()["has_escrow"] is False
    # личность жива + Kyber-pub персистит (иначе re-wrap потерял бы PQ)
    row = next((i for i in _list_invites(client, o_h, room_id) if i["invite_pub"] == body["invite_pub"]), None)
    assert row is not None and row["invite_kyber_pub"] == body["invite_kyber_pub"]


def test_store_upsert_rewrap(client):
    """Re-wrap = повторный store для того же invite_pub перезаписывает обёртку
    (член заново оборачивает НОВЫЙ room key после ротации, имея его)."""
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, _ = _create_room(client, o_h)
    body = _escrow_body(hybrid=True)
    _store(client, o_h, room_id, body)
    body2 = dict(body)
    body2["ciphertext"] = secrets.token_hex(60)
    _store(client, o_h, room_id, body2)
    got = _fetch(client, o_h, room_id, body["invite_pub"]).json()
    assert got["has_escrow"] is True and got["ciphertext"] == body2["ciphertext"]


def test_kick_invalidates_escrow(client):
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, invite = _create_room(client, o_h)
    b = make_user(client, suffix=f"b{random_str(6)}")
    b_id = b["data"].get("user_id") or b["data"].get("id")
    b_h = login_user(client, b["username"], b["password"])
    client.post(f"/api/rooms/join/{invite}", headers=b_h)

    o_h = login_user(client, owner["username"], owner["password"])
    body = _escrow_body()
    _store(client, o_h, room_id, body)
    assert client.post(f"/api/rooms/{room_id}/kick/{b_id}", headers=o_h).status_code == 200
    assert _fetch(client, o_h, room_id, body["invite_pub"]).json()["has_escrow"] is False
    # sweep удаляет ТОЛЬКО обёртку — личность инвайта персистит (для re-wrap)
    assert any(i["invite_pub"] == body["invite_pub"] for i in _list_invites(client, o_h, room_id))


def test_leave_invalidates_escrow(client):
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, invite = _create_room(client, o_h)
    b = make_user(client, suffix=f"b{random_str(6)}")
    b_h = login_user(client, b["username"], b["password"])
    client.post(f"/api/rooms/join/{invite}", headers=b_h)

    o_h = login_user(client, owner["username"], owner["password"])
    body = _escrow_body()
    _store(client, o_h, room_id, body)
    # B покидает комнату → ротация → инвалидация escrow
    b_h = login_user(client, b["username"], b["password"])
    assert client.delete(f"/api/rooms/{room_id}/leave", headers=b_h).status_code == 200
    o_h = login_user(client, owner["username"], owner["password"])
    assert _fetch(client, o_h, room_id, body["invite_pub"]).json()["has_escrow"] is False
