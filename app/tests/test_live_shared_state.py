"""Разделяемое состояние живых сессий: голос, сцена, запись, звонки, трансляции.

Записи живут в Rust (`vortex-live`), Python зовёт их через
`app/chats/live_backend.py`. Здесь проверяется контракт, который видят
потребители: кто в канале, кто говорит, идёт ли запись, есть ли активный
звонок и что показывает трансляция.
"""

import secrets

import pytest

from app.chats import live_backend as _live


class Account:
    """Учётная запись в том виде, в каком её читает мост."""

    def __init__(self, user_id, username, display_name=None, avatar_emoji=None, avatar_url=None):
        self.id = user_id
        self.username = username
        self.display_name = display_name
        self.avatar_emoji = avatar_emoji
        self.avatar_url = avatar_url


@pytest.fixture
def ann():
    return Account(950_001, "ann", "Ann")


@pytest.fixture
def bob():
    return Account(950_002, "bob")


@pytest.fixture
def channel_id():
    return secrets.randbelow(1_000_000) + 9_000_000


@pytest.fixture
def voice_room(client, logged_user):
    r = client.post(
        "/api/rooms",
        json={
            "name": f"voice_{secrets.token_hex(4)}",
            "is_public": True,
            "is_voice": True,
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        },
        headers=logged_user["headers"],
    )
    assert r.status_code in (200, 201), r.text
    return r.json()


@pytest.fixture
def channel(client, logged_user):
    r = client.post(
        "/api/channels",
        json={"name": f"chan_{secrets.token_hex(4)}", "description": ""},
        headers=logged_user["headers"],
    )
    assert r.status_code in (200, 201), r.text
    return r.json()


class TestVoicePresence:
    def test_a_participant_is_seen_by_every_worker_after_joining(self, channel_id, ann):
        joined = _live.voice_join(channel_id, ann)

        assert joined["already_in"] is False
        assert joined["participant"]["display_name"] == "Ann"
        assert [held["user_id"] for held in _live.voice_participants(channel_id)] == [ann.id]

    def test_joining_twice_does_not_double_the_participant(self, channel_id, ann):
        _live.voice_join(channel_id, ann)
        assert _live.voice_join(channel_id, ann)["already_in"] is True
        assert _live.voice_count(channel_id) == 1

    def test_a_participant_without_a_display_name_is_shown_by_username(self, channel_id, bob):
        joined = _live.voice_join(channel_id, bob)
        assert joined["participant"]["display_name"] == "bob"
        assert joined["participant"]["avatar_emoji"] == "\U0001f464"

    def test_leaving_gives_back_who_left_and_only_once(self, channel_id, ann):
        _live.voice_join(channel_id, ann)

        assert _live.voice_leave(channel_id, ann.id)["participant"]["user_id"] == ann.id
        assert _live.voice_leave(channel_id, ann.id)["participant"] is None
        assert _live.voice_count(channel_id) == 0

    def test_muting_without_a_flag_flips_the_one_that_is_there(self, channel_id, ann):
        _live.voice_join(channel_id, ann)

        assert _live.voice_mute(channel_id, ann.id)["is_muted"] is True
        assert _live.voice_mute(channel_id, ann.id)["is_muted"] is False

    def test_muting_touches_only_the_participant_it_names(self, channel_id, ann, bob):
        _live.voice_join(channel_id, ann)
        _live.voice_join(channel_id, bob)

        _live.voice_mute(channel_id, ann.id, True, None)
        assert _live.voice_find(channel_id, bob.id)["is_muted"] is False

    def test_nobody_outside_the_channel_is_muted(self, channel_id, ann):
        assert _live.voice_mute(channel_id, ann.id) is None
        assert _live.voice_find(channel_id, ann.id) is None


class TestStage:
    def test_the_admin_who_opens_the_stage_speaks_first(self, channel_id, ann):
        assert _live.stage_open(channel_id, ann.id) == [ann.id]

        status = _live.stage_status(channel_id, ann.id)
        assert status["stage_mode"] is True
        assert status["is_speaker"] is True

    def test_without_a_stage_everyone_may_speak(self, channel_id, ann):
        status = _live.stage_status(channel_id, ann.id)
        assert status["stage_mode"] is False
        assert status["is_speaker"] is True
        assert status["speakers"] == []

    def test_a_listener_promoted_to_speaker_is_seen_by_every_worker(self, channel_id, ann, bob):
        _live.stage_open(channel_id, ann.id)

        assert _live.stage_add(channel_id, bob.id) == sorted([ann.id, bob.id])
        assert _live.stage_status(channel_id, bob.id)["is_speaker"] is True

    def test_demoting_the_last_speaker_leaves_the_stage_open(self, channel_id, ann):
        _live.stage_open(channel_id, ann.id)

        assert _live.stage_remove(channel_id, ann.id) == []
        assert _live.stage_status(channel_id, ann.id)["stage_mode"] is True

    def test_a_stage_nobody_opened_promotes_nobody(self, channel_id, bob):
        assert _live.stage_add(channel_id, bob.id) is None
        assert _live.stage_close(channel_id) is False


class TestRecording:
    def test_a_recording_is_started_once_and_stopped_once(self, channel_id, ann):
        started = _live.recording_start(channel_id, ann.id)
        assert started["already_started"] is False
        assert _live.recording_start(channel_id, ann.id)["already_started"] is True

        assert _live.recording_status(channel_id)["recording"] is True
        assert _live.recording_stop(channel_id)["stopped"] is True
        assert _live.recording_stop(channel_id)["stopped"] is False
        assert _live.recording_status(channel_id)["recording"] is False

    def test_the_recording_remembers_who_was_in_the_channel(self, channel_id, ann, bob):
        _live.voice_join(channel_id, ann)
        _live.voice_join(channel_id, bob)
        _live.recording_start(channel_id, ann.id)

        assert _live.recording_status(channel_id)["started_by"] == ann.id


class TestGroupCalls:
    def _start(self, room_id, ann, bob):
        return _live.call_start(
            room_id,
            ann.id,
            "group_audio",
            [_live.identity_of(ann), _live.identity_of(bob)],
            False,
            6,
            200,
        )

    def test_starting_a_call_rings_everyone_the_room_holds(self, channel_id, ann, bob):
        started = self._start(channel_id, ann, bob)

        assert started["already_active"] is False
        assert started["topology"] == "mesh"
        assert started["call"]["state"] == "ringing"
        assert started["call"]["participant_count"] == 1

    def test_a_room_that_already_rings_does_not_ring_a_second_call(self, channel_id, ann, bob):
        first = self._start(channel_id, ann, bob)
        again = self._start(channel_id, ann, bob)

        assert again["already_active"] is True
        assert again["call_id"] == first["call_id"]

    def test_the_second_participant_to_connect_makes_the_call_active(self, channel_id, ann, bob):
        call_id = self._start(channel_id, ann, bob)["call_id"]

        joined = _live.call_join(call_id, bob.id)
        assert joined["status"] == "ok"
        assert joined["call"]["state"] == "active"
        assert joined["call"]["participant_count"] == 2

    def test_nobody_the_call_did_not_invite_joins_it(self, channel_id, ann, bob):
        call_id = self._start(channel_id, ann, bob)["call_id"]
        assert _live.call_join(call_id, 950_099)["status"] == "not_invited"

    def test_the_call_ends_when_the_last_participant_leaves(self, channel_id, ann, bob):
        call_id = self._start(channel_id, ann, bob)["call_id"]

        left = _live.call_leave(call_id, ann.id)
        assert left["status"] == "ok"
        assert left["ended"] is True
        assert _live.call_active(channel_id) is None
        assert _live.call_leave(call_id, ann.id)["status"] == "missing"

    def test_only_the_initiator_ends_the_call_for_everyone(self, channel_id, ann, bob):
        call_id = self._start(channel_id, ann, bob)["call_id"]
        _live.call_join(call_id, bob.id)

        assert _live.call_end(call_id, bob.id)["status"] == "not_initiator"
        assert _live.call_end(call_id, ann.id)["status"] == "ok"
        assert _live.call_status(call_id) is None

    def test_a_call_nobody_answered_is_rung_out_exactly_once(self, channel_id, ann, bob):
        call_id = self._start(channel_id, ann, bob)["call_id"]

        assert _live.call_ring_out(call_id) is not None
        assert _live.call_ring_out(call_id) is None

    def test_a_call_that_became_active_is_not_rung_out(self, channel_id, ann, bob):
        call_id = self._start(channel_id, ann, bob)["call_id"]
        _live.call_join(call_id, bob.id)

        assert _live.call_ring_out(call_id) is None
        assert _live.call_active(channel_id) is not None

    def test_whoever_declined_may_be_invited_again(self, channel_id, ann, bob):
        call_id = self._start(channel_id, ann, bob)["call_id"]
        assert _live.call_decline(call_id, bob.id) == "ok"

        added = _live.call_add(call_id, ann.id, bob)
        assert added["status"] == "ok"

    def test_somebody_outside_the_call_invites_nobody_into_it(self, channel_id, ann, bob):
        call_id = self._start(channel_id, ann, bob)["call_id"]
        outsider = Account(950_098, "carol")

        assert _live.call_add(call_id, outsider.id, outsider)["status"] == "not_a_participant"


class TestStreams:
    def _open(self, room_id, host, **overrides):
        opening = {
            "title": "Показ",
            "description": "",
            "allow_reactions": True,
            "allow_donations": False,
            "donation_card": "",
            "donation_message": "",
            "auto_accept_speakers": False,
        }
        opening.update(overrides)
        return _live.stream_open(
            room_id,
            host,
            opening["title"],
            opening["description"],
            opening["allow_reactions"],
            opening["allow_donations"],
            opening["donation_card"],
            opening["donation_message"],
            opening["auto_accept_speakers"],
        )

    def test_opening_a_stream_seats_the_host(self, channel_id, ann):
        opened = self._open(channel_id, ann)

        assert opened["status"] == "ok"
        assert opened["stream"]["viewer_count"] == 1
        assert opened["stream"]["participants"][0]["role"] == "host"

    def test_a_channel_that_is_live_opens_no_second_stream(self, channel_id, ann):
        self._open(channel_id, ann)
        assert self._open(channel_id, ann)["status"] == "already_live"

    def test_a_viewer_joins_muted_and_the_peak_remembers_the_audience(self, channel_id, ann, bob):
        self._open(channel_id, ann)

        seated = _live.stream_join(channel_id, bob, False)
        assert seated["status"] == "ok"
        assert seated["already_in"] is False
        assert seated["stream"]["viewer_count"] == 2

        _live.stream_leave(channel_id, bob.id)
        assert _live.stream_status(channel_id)["viewer_peak"] == 2

    def test_a_raised_hand_stands_in_a_queue_every_worker_reads(self, channel_id, ann, bob):
        self._open(channel_id, ann)
        _live.stream_join(channel_id, bob, False)

        assert _live.stream_raise_hand(channel_id, bob.id)["status"] == "raised"
        assert _live.stream_status(channel_id)["hand_queue"] == [bob.id]
        assert [held["user_id"] for held in _live.stream_hands(channel_id)] == [bob.id]

    def test_whoever_already_speaks_does_not_raise_a_hand(self, channel_id, ann):
        self._open(channel_id, ann)
        assert _live.stream_raise_hand(channel_id, ann.id)["status"] == "already_speaks"

    def test_a_stream_that_accepts_speakers_promotes_the_hand_at_once(self, channel_id, ann, bob):
        self._open(channel_id, ann, auto_accept_speakers=True)
        _live.stream_join(channel_id, bob, False)

        raised = _live.stream_raise_hand(channel_id, bob.id)
        assert raised["status"] == "auto_accepted"
        assert raised["participant"]["role"] == "speaker"
        assert _live.stream_status(channel_id)["hand_queue"] == []

    def test_granting_the_right_to_speak_lowers_the_hand_it_answers(self, channel_id, ann, bob):
        self._open(channel_id, ann)
        _live.stream_join(channel_id, bob, False)
        _live.stream_raise_hand(channel_id, bob.id)

        granted = _live.stream_grant(channel_id, ann.id, bob.id, role="speaker")
        assert granted["status"] == "ok"
        assert granted["participant"]["hand_raised"] is False
        assert _live.stream_status(channel_id)["hand_queue"] == []

    def test_a_viewer_grants_nothing(self, channel_id, ann, bob):
        self._open(channel_id, ann)
        _live.stream_join(channel_id, bob, False)

        assert _live.stream_grant(channel_id, bob.id, ann.id, can_speak=True)["status"] == "not_allowed"

    def test_the_host_is_never_kicked_from_its_own_stream(self, channel_id, ann):
        self._open(channel_id, ann)
        assert _live.stream_kick(channel_id, ann.id, ann.id)["status"] == "cannot_kick_host"

    def test_reactions_are_counted_where_every_worker_reads_them(self, channel_id, ann):
        self._open(channel_id, ann)

        assert _live.stream_react(channel_id, ann.id, "❤️")["status"] == "ok"
        assert _live.stream_react(channel_id, ann.id, "❤️")["status"] == "ok"
        assert _live.stream_status(channel_id)["reaction_counts"]["❤️"] == 2

    def test_a_stream_with_reactions_switched_off_counts_none(self, channel_id, ann):
        self._open(channel_id, ann, allow_reactions=False)
        assert _live.stream_react(channel_id, ann.id, "❤")["status"] == "disabled"

    def test_a_donation_is_kept_with_who_sent_it(self, channel_id, ann, bob):
        self._open(channel_id, ann, allow_donations=True)
        _live.stream_join(channel_id, bob, False)

        donated = _live.stream_donate(channel_id, bob.id, "500", "RUB", "спасибо")
        assert donated["status"] == "ok"
        assert donated["donation"]["user_id"] == bob.id
        assert donated["donation"]["amount"] == "500"

    def test_the_host_leaving_ends_the_stream_for_everyone(self, channel_id, ann, bob):
        self._open(channel_id, ann)
        _live.stream_join(channel_id, bob, False)

        left = _live.stream_leave(channel_id, ann.id)
        assert left["stream_ended"] is True
        assert _live.stream_status(channel_id) is None

    def test_stopping_the_stream_reports_the_peak(self, channel_id, ann, bob):
        self._open(channel_id, ann)
        _live.stream_join(channel_id, bob, False)

        assert _live.stream_stop(channel_id)["viewer_peak"] == 2
        assert _live.stream_stop(channel_id)["status"] == "missing"


class TestSchedule:
    def test_a_planned_stream_is_seen_by_every_worker(self, channel_id, ann):
        planned = _live.schedule_plan(channel_id, "Показ", "2030-08-04T09:15:30Z", ann.id, "Ann")

        assert planned["scheduled_at"] == "2030-08-04T09:15:30Z"
        assert _live.schedule_find(channel_id) == planned
        assert _live.schedule_forget(channel_id) is True
        assert _live.schedule_forget(channel_id) is False

    def test_a_moment_nobody_can_read_is_not_planned_at_all(self, channel_id, ann):
        assert _live.schedule_plan(channel_id, "Показ", "завтра", ann.id, "Ann") is None
        assert _live.schedule_find(channel_id) is None

    def test_a_due_schedule_is_claimed_by_exactly_one_worker(self, channel_id, ann):
        _live.schedule_plan(channel_id, "Показ", "2020-01-01T00:00:00Z", ann.id, "Ann")

        claimed = _live.schedule_claim_due()
        assert claimed is not None
        assert _live.schedule_find(channel_id) is None

    def test_a_schedule_whose_moment_has_not_come_is_claimed_by_nobody(self, channel_id, ann):
        _live.schedule_plan(channel_id, "Показ", "2030-08-04T09:15:30Z", ann.id, "Ann")
        assert _live.schedule_find(channel_id) is not None


class TestLiveRoutes:
    def test_a_voice_channel_lists_who_joined_it(self, client, logged_user, voice_room):
        room_id = voice_room["id"]
        joined = client.post(f"/api/voice/{room_id}/join", headers=logged_user["headers"])
        assert joined.status_code == 200
        assert joined.json()["already_in"] is False

        listed = client.get(f"/api/voice/{room_id}/participants", headers=logged_user["headers"])
        seated = listed.json()["participants"]
        assert [held["username"] for held in seated] == [logged_user["username"]]

    def test_leaving_a_voice_channel_twice_is_refused_the_second_time(
        self, client, logged_user, voice_room
    ):
        room_id = voice_room["id"]
        client.post(f"/api/voice/{room_id}/join", headers=logged_user["headers"])

        assert client.post(f"/api/voice/{room_id}/leave", headers=logged_user["headers"]).status_code == 200
        assert client.post(f"/api/voice/{room_id}/leave", headers=logged_user["headers"]).status_code == 400

    def test_a_schedule_the_server_cannot_read_is_refused(self, client, logged_user, channel):
        room_id = channel["id"]
        r = client.post(
            f"/api/stream/{room_id}/schedule",
            json={"title": "Показ", "scheduled_at": "завтра"},
            headers=logged_user["headers"],
        )
        assert r.status_code == 400

    def test_a_schedule_the_server_can_read_is_accepted(self, client, logged_user, channel):
        room_id = channel["id"]
        r = client.post(
            f"/api/stream/{room_id}/schedule",
            json={"title": "Показ", "scheduled_at": "2030-08-04T09:15:30Z"},
            headers=logged_user["headers"],
        )
        assert r.status_code == 200
        assert r.json()["scheduled_at"] == "2030-08-04T09:15:30Z"


class TestSharedStateUnavailable:
    """Решение владельца: нет общего состояния — нет живой сессии, а не счёт в памяти."""

    def test_a_voice_channel_that_cannot_be_shared_answers_503(
        self, client, logged_user, voice_room, monkeypatch
    ):
        from app.chats import voice as voice_routes

        def refuse(*_args, **_kwargs):
            raise _live.LiveUnavailableError("общее состояние живых сессий недоступно")

        monkeypatch.setattr(voice_routes._live, "voice_join", refuse)
        r = client.post(f"/api/voice/{voice_room['id']}/join", headers=logged_user["headers"])
        assert r.status_code == 503

    def test_a_stream_that_cannot_be_shared_answers_503(
        self, client, logged_user, channel, monkeypatch
    ):
        from app.chats import stream as stream_routes

        def refuse(*_args, **_kwargs):
            raise _live.LiveUnavailableError("общее состояние живых сессий недоступно")

        monkeypatch.setattr(stream_routes._live, "stream_status", refuse)
        r = client.get(f"/api/stream/{channel['id']}/status", headers=logged_user["headers"])
        assert r.status_code == 503


class TestRenewal:
    """WS-цикл продлевает запись, пока держит сокет, и не теряет кадры на тике."""

    @staticmethod
    def _voice_room(tc):
        from conftest import random_digits, random_str

        tag = random_str(8)
        tc.post(
            "/api/authentication/register",
            json={
                "username": f"live_{tag}",
                "password": "Str0ng_abcd!@",
                "display_name": f"Live {tag}",
                "phone": f"+49{random_digits(9)}",
                "avatar_emoji": "\U0001f512",
                "x25519_public_key": secrets.token_hex(32),
            },
        )
        csrf = tc.get("/api/authentication/csrf-token").json().get("csrf_token", "")
        tc.post(
            "/api/authentication/login",
            json={"phone_or_username": f"live_{tag}", "password": "Str0ng_abcd!@"},
            headers={"X-CSRF-Token": csrf},
        )
        r = tc.post(
            "/api/rooms",
            json={
                "name": f"livevoice_{tag}",
                "is_public": True,
                "is_voice": True,
                "encrypted_room_key": {
                    "ephemeral_pub": secrets.token_hex(32),
                    "ciphertext": secrets.token_hex(60),
                },
            },
            headers={"X-CSRF-Token": csrf},
        )
        return r.json()["id"], csrf

    def test_a_silent_socket_keeps_renewing_the_presence(self, monkeypatch):
        import time as _time

        from starlette.testclient import TestClient

        from app.chats import voice as voice_routes
        from app.main import app

        renewals = []
        real_renew = voice_routes._live.voice_renew

        def counting(room_id, user_id):
            renewals.append((room_id, user_id))
            return real_renew(room_id, user_id)

        monkeypatch.setattr(voice_routes._live, "RENEWAL_SECONDS", 0.1)
        monkeypatch.setattr(voice_routes._live, "voice_renew", counting)

        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id, _csrf = self._voice_room(tc)
            with tc.websocket_connect(f"/ws/voice-signal/{room_id}") as ws:
                ws.receive_json()
                _time.sleep(0.5)

                listed = tc.get(f"/api/voice/{room_id}/participants").json()
                assert len(listed["participants"]) == 1

        assert renewals, "молчащий сокет ни разу не продлил присутствие"

    def test_a_frame_that_arrives_on_a_renewal_tick_is_not_lost(self, monkeypatch):
        import time as _time

        from conftest import random_digits, random_str
        from starlette.testclient import TestClient

        from app.chats import voice as voice_routes
        from app.main import app

        monkeypatch.setattr(voice_routes._live, "RENEWAL_SECONDS", 0.01)

        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id, csrf = self._voice_room(tc)
            invite = tc.get(f"/api/rooms/{room_id}", headers={"X-CSRF-Token": csrf}).json()[
                "invite_code"
            ]
            host_token = tc.cookies.get("access_token")

            tag = random_str(8)
            tc.post(
                "/api/authentication/register",
                json={
                    "username": f"peer_{tag}",
                    "password": "Str0ng_abcd!@",
                    "display_name": f"Peer {tag}",
                    "phone": f"+49{random_digits(9)}",
                    "avatar_emoji": "\U0001f512",
                    "x25519_public_key": secrets.token_hex(32),
                },
            )
            peer_csrf = tc.get("/api/authentication/csrf-token").json().get("csrf_token", "")
            tc.post(
                "/api/authentication/login",
                json={"phone_or_username": f"peer_{tag}", "password": "Str0ng_abcd!@"},
                headers={"X-CSRF-Token": peer_csrf},
            )
            joined = tc.post(
                f"/api/rooms/join/{invite}", headers={"X-CSRF-Token": peer_csrf}
            )
            assert joined.status_code in (200, 201), joined.text
            host_tc = TestClient(app, raise_server_exceptions=False)
            host_tc.cookies.set("access_token", host_token)

            with host_tc.websocket_connect(f"/ws/voice-signal/{room_id}") as host_ws:
                host_ws.receive_json()
                with tc.websocket_connect(f"/ws/voice-signal/{room_id}") as peer_ws:
                    peer_ws.receive_json()
                    host_ws.receive_json()

                    for index in range(50):
                        _time.sleep(0.01)
                        peer_ws.send_json({"type": "ice-candidate", "index": index})

                    seen = [host_ws.receive_json()["index"] for _ in range(50)]

        assert seen == list(range(50))
