"""O3: энфорс join_approval + approve-flow + согласование auth O1 (ADR-005).

Энфорс за Config.JOIN_APPROVAL_ENFORCED (дефолт OFF — дормантно). Ключевой тест —
негатив-реконсиляция: обычный член НЕ может обойти апрув через provision-key.
"""
import secrets

import pytest

from conftest import make_user, login_user, random_str


def _classical_key() -> dict:
    return {"ephemeral_pub": secrets.token_hex(32), "ciphertext": secrets.token_hex(60)}


def _uid(u: dict) -> int:
    d = u.get("data", {})
    uid = d.get("user_id") or d.get("id")
    if not uid:
        pytest.skip("no user id")
    return uid


def _create_room(client, headers):
    r = client.post("/api/rooms", json={
        "name": f"room_{random_str(6)}", "is_private": True,
        "encrypted_room_key": _classical_key(),
    }, headers=headers)
    assert r.status_code in (200, 201), r.text
    b = r.json()
    room = b.get("room", b)
    return room.get("id") or b.get("id"), room.get("invite_code") or b.get("invite_code")


def _set_approval(client, headers, room_id, on=True):
    r = client.put(f"/api/rooms/{room_id}", json={"join_approval": on}, headers=headers)
    assert r.status_code in (200, 201), r.text


@pytest.fixture
def enforce(monkeypatch):
    monkeypatch.setattr("app.config.Config.JOIN_APPROVAL_ENFORCED", True)


def test_enforced_join_becomes_pending_not_member(client, enforce):
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, invite = _create_room(client, o_h)
    _set_approval(client, o_h, room_id, True)

    stranger = make_user(client, suffix=f"s{random_str(6)}")
    s_h = login_user(client, stranger["username"], stranger["password"])
    r = client.post(f"/api/rooms/join/{invite}", headers=s_h)
    assert r.status_code == 200, r.text
    assert r.json().get("pending") is True
    assert r.json().get("joined") is False
    # заявитель — НЕ член: key-bundle → 403
    kb = client.get(f"/api/rooms/{room_id}/key-bundle", headers=s_h)
    assert kb.status_code == 403


def test_negative_reconciliation_member_cannot_bypass_approval(client, enforce):
    """LOAD-BEARING: обычный член с ключом провижнит незнакомца на approval-комнате
    → 403; незнакомец НЕ становится членом (обход апрува закрыт)."""
    owner = make_user(client, suffix=f"o{random_str(6)}")
    member = make_user(client, suffix=f"m{random_str(6)}")
    stranger = make_user(client, suffix=f"s{random_str(6)}")
    member_id, stranger_id = _uid(member), _uid(stranger)

    o_h = login_user(client, owner["username"], owner["password"])
    room_id, invite = _create_room(client, o_h)
    _set_approval(client, o_h, room_id, True)
    # owner (OWNER → _can_admit=True) провижнит ключ для member → member станет членом с ключом
    r0 = client.post(f"/api/rooms/{room_id}/provision-key",
                     json={"for_user_id": member_id, **_classical_key()}, headers=o_h)
    assert r0.status_code == 200, r0.text

    # member (роль MEMBER, есть ключ) пробует провижнить незнакомца → 403 (_can_admit=False)
    m_h = login_user(client, member["username"], member["password"])
    assert client.get(f"/api/rooms/{room_id}/key-bundle", headers=m_h).json()["has_key"] is True
    r = client.post(f"/api/rooms/{room_id}/provision-key",
                    json={"for_user_id": stranger_id, **_classical_key()}, headers=m_h)
    assert r.status_code == 403, r.text

    # незнакомец НЕ член
    st_h = login_user(client, stranger["username"], stranger["password"])
    assert client.get(f"/api/rooms/{room_id}/key-bundle", headers=st_h).status_code == 403


def test_admin_approve_join_admits_and_stores_key(client, enforce):
    owner = make_user(client, suffix=f"o{random_str(6)}")
    stranger = make_user(client, suffix=f"s{random_str(6)}")
    stranger_id = _uid(stranger)

    o_h = login_user(client, owner["username"], owner["password"])
    room_id, invite = _create_room(client, o_h)
    _set_approval(client, o_h, room_id, True)

    # stranger подаёт заявку
    st_h = login_user(client, stranger["username"], stranger["password"])
    client.post(f"/api/rooms/join/{invite}", headers=st_h)

    # owner видит заявку и одобряет с pre-wrap ключом
    o_h = login_user(client, owner["username"], owner["password"])
    lst = client.get(f"/api/rooms/{room_id}/join-requests", headers=o_h).json()["requests"]
    assert any(q["user_id"] == stranger_id for q in lst)
    key = _classical_key()
    ap = client.post(f"/api/rooms/{room_id}/approve-join",
                     json={"user_id": stranger_id, "encrypted_room_key": key}, headers=o_h)
    assert ap.status_code == 200, ap.text
    assert ap.json()["added"] is True and ap.json()["key_stored"] is True

    # stranger теперь член с ключом; заявка удалена
    st_h = login_user(client, stranger["username"], stranger["password"])
    got = client.get(f"/api/rooms/{room_id}/key-bundle", headers=st_h).json()
    assert got["has_key"] is True and got["ephemeral_pub"] == key["ephemeral_pub"]
    o_h = login_user(client, owner["username"], owner["password"])
    lst2 = client.get(f"/api/rooms/{room_id}/join-requests", headers=o_h).json()["requests"]
    assert not any(q["user_id"] == stranger_id for q in lst2)


def test_reject_join_removes_request(client, enforce):
    owner = make_user(client, suffix=f"o{random_str(6)}")
    stranger = make_user(client, suffix=f"s{random_str(6)}")
    stranger_id = _uid(stranger)
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, invite = _create_room(client, o_h)
    _set_approval(client, o_h, room_id, True)
    st_h = login_user(client, stranger["username"], stranger["password"])
    client.post(f"/api/rooms/join/{invite}", headers=st_h)

    o_h = login_user(client, owner["username"], owner["password"])
    r = client.post(f"/api/rooms/{room_id}/reject-join", json={"user_id": stranger_id}, headers=o_h)
    assert r.status_code == 200 and r.json()["rejected"] is True
    lst = client.get(f"/api/rooms/{room_id}/join-requests", headers=o_h).json()["requests"]
    assert not any(q["user_id"] == stranger_id for q in lst)


def test_channel_join_also_gated(client, enforce):
    """Sweep-покрытие: join_channel — тоже user-facing JOIN-путь; при энфорсе →
    pending, не член (иначе апрув канала обходится через /channels/join)."""
    owner = make_user(client, suffix=f"o{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    r = client.post("/api/channels", json={
        "name": f"ch_{random_str(6)}", "encrypted_room_key": _classical_key(),
    }, headers=o_h)
    if r.status_code not in (200, 201):
        pytest.skip(f"channel create unavailable: {r.status_code}")
    ch = r.json(); ch = ch.get("room", ch)
    channel_id = ch.get("id")
    invite = ch.get("invite_code")
    if not (channel_id and invite):
        pytest.skip("no channel id/invite")
    client.put(f"/api/rooms/{channel_id}", json={"join_approval": True}, headers=o_h)

    stranger = make_user(client, suffix=f"s{random_str(6)}")
    st_h = login_user(client, stranger["username"], stranger["password"])
    jr = client.post(f"/api/channels/join/{invite}", headers=st_h)
    assert jr.status_code == 200, jr.text
    assert jr.json().get("pending") is True
    assert jr.json().get("joined") is False


def test_dormant_when_flag_off_join_adds_member_directly(client):
    """Config OFF (дефолт): join_approval=True комната НЕ гейтится — join добавляет
    членом сразу (существующие комнаты не ломаются до осознанного флипа)."""
    owner = make_user(client, suffix=f"o{random_str(6)}")
    stranger = make_user(client, suffix=f"s{random_str(6)}")
    o_h = login_user(client, owner["username"], owner["password"])
    room_id, invite = _create_room(client, o_h)
    _set_approval(client, o_h, room_id, True)   # флаг комнаты ВКЛ, но Config OFF

    st_h = login_user(client, stranger["username"], stranger["password"])
    r = client.post(f"/api/rooms/join/{invite}", headers=st_h)
    assert r.status_code == 200, r.text
    assert r.json().get("joined") is True          # добавлен сразу, не pending
    assert r.json().get("pending") is not True
