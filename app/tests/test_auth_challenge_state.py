"""Одноразовые челленджи аутентификации в общем состоянии (крейт `vortex-auth`).

Челленджи входа по ключу, QR-сессии, челленджи passkey и привязки кошелька живут
в Rust и переживают границу воркера. Здесь проверяется контракт, который видят
потребители: челлендж тратится ровно один раз, назначение и привязка подменить
нельзя, а приманка неотличима от челленджа, которого никогда не было.
"""

import secrets

import pytest

from app.security import auth_state_backend as _auth_state

KEY = "ab" * 32
OTHER_KEY = "cd" * 32


class TestLoginChallenges:
    def test_a_challenge_is_spent_once(self):
        issued = _auth_state.login_issue(701, KEY)
        assert len(issued.challenge_id) == 32
        assert len(issued.challenge) == 32
        assert issued.expires_in == 60

        claimed = _auth_state.login_claim(issued.challenge_id, KEY)
        assert claimed.taken is True
        assert claimed.user_id == 701
        assert _auth_state.login_claim(issued.challenge_id, KEY).outcome == "missing"

    def test_another_key_never_claims_the_challenge(self):
        issued = _auth_state.login_issue(702, KEY)
        assert _auth_state.login_claim(issued.challenge_id, OTHER_KEY).outcome == "mismatch"

    def test_a_decoy_answers_like_a_challenge_that_never_existed(self):
        decoy = _auth_state.login_issue_decoy()
        assert _auth_state.login_claim(decoy.challenge_id, KEY).outcome == "missing"
        assert _auth_state.login_claim(secrets.token_hex(16), KEY).outcome == "missing"

    def test_an_identifier_outside_the_alphabet_is_refused(self):
        with pytest.raises(ValueError):
            _auth_state.login_claim("bad:id", KEY)

    def test_a_key_that_is_not_a_key_is_refused_at_issue(self):
        with pytest.raises(ValueError):
            _auth_state.login_issue(703, "short")


class TestLoginChallengesOverHttp:
    def test_an_unknown_identifier_answers_like_a_known_one(self, client, fresh_user):
        known = client.get(
            f"/api/authentication/challenge?identifier={fresh_user['username']}"
        ).json()
        unknown = client.get(
            f"/api/authentication/challenge?identifier=nobody_{secrets.token_hex(4)}"
        ).json()

        assert set(known) == set(unknown)
        assert len(known["challenge_id"]) == len(unknown["challenge_id"]) == 32
        assert len(known["challenge"]) == len(unknown["challenge"]) == 64
        assert known["expires_in"] == unknown["expires_in"]
        assert known["server_pubkey"] == unknown["server_pubkey"]
        assert known["server_pubkey"] != "0" * 64

    def test_a_decoy_challenge_does_not_let_anyone_in(self, client):
        decoy = client.get(
            f"/api/authentication/challenge?identifier=nobody_{secrets.token_hex(4)}"
        ).json()
        csrf = client.get("/api/authentication/csrf-token").json().get("csrf_token", "")

        answered = client.post(
            "/api/authentication/login-key",
            json={
                "challenge_id": decoy["challenge_id"],
                "pubkey": KEY,
                "proof": "ee" * 32,
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert answered.status_code == 401

    def test_a_login_that_cannot_reach_shared_state_answers_503(self, client, monkeypatch):
        from app.authentication import key_login

        def refuse(*_args, **_kwargs):
            raise RuntimeError("общее состояние аутентификации недоступно")

        monkeypatch.setattr(key_login._auth_state, "login_issue_decoy", refuse)
        answered = client.get(
            f"/api/authentication/challenge?identifier=nobody_{secrets.token_hex(4)}"
        )
        assert answered.status_code == 503


class TestQrSessions:
    def test_a_session_is_answered_confirmed_and_handed_over_once(self):
        opened = _auth_state.qr_open()
        assert len(opened.session_id) == 48
        assert opened.expires_in == 300

        assert _auth_state.qr_hand_over(opened.session_id).outcome == "pending"

        answer = _auth_state.qr_answer(opened.session_id)
        assert answer.ready is True
        assert answer.challenge == opened.challenge

        assert _auth_state.qr_confirm(opened.session_id, 705) == "confirmed"
        assert _auth_state.qr_confirm(opened.session_id, 705) == "already_confirmed"

        handover = _auth_state.qr_hand_over(opened.session_id)
        assert handover.taken is True
        assert handover.user_id == 705
        assert _auth_state.qr_hand_over(opened.session_id).outcome == "missing"

    def test_the_challenge_of_a_session_is_answered_once(self):
        opened = _auth_state.qr_open()
        _auth_state.qr_answer(opened.session_id)
        assert _auth_state.qr_answer(opened.session_id).outcome == "challenge_missing"

    def test_a_confirmed_session_is_never_answered_again(self):
        opened = _auth_state.qr_open()
        _auth_state.qr_answer(opened.session_id)
        _auth_state.qr_confirm(opened.session_id, 706)
        assert _auth_state.qr_answer(opened.session_id).outcome == "already_confirmed"

    def test_a_qr_challenge_is_never_spent_as_a_key_login_one(self):
        opened = _auth_state.qr_open()
        assert _auth_state.login_claim(opened.challenge_id, KEY).outcome == "mismatch"

    def test_a_session_nobody_opened_is_missing(self):
        assert _auth_state.qr_answer(secrets.token_hex(24)).outcome == "session_missing"
        assert _auth_state.qr_hand_over(secrets.token_hex(24)).outcome == "missing"


class TestQrSessionsOverHttp:
    def test_a_fresh_session_is_not_confirmed_yet(self, client):
        csrf = client.get("/api/authentication/csrf-token").json().get("csrf_token", "")
        opened = client.post(
            "/api/authentication/qr-init", headers={"X-CSRF-Token": csrf}
        )
        assert opened.status_code == 200
        body = opened.json()
        assert body["expires_in"] == 300
        assert len(body["challenge"]) == 64

        checked = client.get(f"/api/authentication/qr-check/{body['session_id']}")
        assert checked.status_code == 200
        assert checked.json() == {"confirmed": False}

    def test_a_session_nobody_opened_is_not_found(self, client):
        answered = client.get(f"/api/authentication/qr-check/{secrets.token_hex(24)}")
        assert answered.status_code == 404

    def test_a_confirm_without_a_session_is_refused(self, client):
        csrf = client.get("/api/authentication/csrf-token").json().get("csrf_token", "")
        answered = client.post(
            "/api/authentication/qr-confirm",
            json={"session_id": secrets.token_hex(24), "pubkey": KEY, "proof": "ee" * 32},
            headers={"X-CSRF-Token": csrf},
        )
        assert answered.status_code == 401


class TestPasskeyChallenges:
    def test_a_registration_challenge_returns_to_its_own_account(self):
        challenge = secrets.token_bytes(64)
        session = _auth_state.passkey_open_registration(challenge, 710)

        claimed = _auth_state.passkey_claim_registration(session, 710)
        assert claimed.taken is True
        assert claimed.challenge == challenge

    def test_a_registration_challenge_of_one_account_is_not_claimed_by_another(self):
        session = _auth_state.passkey_open_registration(secrets.token_bytes(64), 711)
        assert _auth_state.passkey_claim_registration(session, 712).outcome == "wrong_account"

    def test_a_login_challenge_is_never_spent_as_a_registration_one(self):
        session = _auth_state.passkey_open_login(secrets.token_bytes(64))
        assert _auth_state.passkey_claim_registration(session, 713).outcome == "wrong_purpose"

    def test_a_registration_challenge_is_never_spent_as_a_login_one(self):
        session = _auth_state.passkey_open_registration(secrets.token_bytes(64), 714)
        assert _auth_state.passkey_claim_login(session).outcome == "wrong_purpose"

    def test_a_challenge_is_spent_even_when_it_was_claimed_wrongly(self):
        session = _auth_state.passkey_open_login(secrets.token_bytes(64))
        assert _auth_state.passkey_claim_registration(session, 715).outcome == "wrong_purpose"
        assert _auth_state.passkey_claim_login(session).outcome == "missing"


class TestWalletChallenges:
    def test_the_message_handed_out_is_the_message_accepted_back(self):
        issued = _auth_state.wallet_issue(720)
        assert issued.ttl_seconds == 300

        checked = _auth_state.wallet_check(720, issued.challenge)
        assert checked.matched is True
        assert checked.message.startswith(b"vortex:link-wallet:v1:720:")

    def test_the_message_of_one_account_is_not_the_message_of_another(self):
        mine = _auth_state.wallet_issue(721)
        _auth_state.wallet_issue(722)
        assert _auth_state.wallet_check(722, mine.challenge).outcome == "mismatch"

    def test_a_burnt_challenge_cannot_be_spent_twice(self):
        issued = _auth_state.wallet_issue(723)
        _auth_state.wallet_burn(723)
        assert _auth_state.wallet_check(723, issued.challenge).outcome == "no_challenge"

    def test_what_is_not_base64_is_told_apart_from_a_wrong_message(self):
        _auth_state.wallet_issue(724)
        assert _auth_state.wallet_check(724, "не base64!").outcome == "not_base64"


class TestHandoffReplay:
    def test_a_token_is_accepted_once(self):
        jti = secrets.token_hex(16)
        assert _auth_state.handoff_seen(jti) is False
        assert _auth_state.handoff_accept(jti) is True
        assert _auth_state.handoff_seen(jti) is True
        assert _auth_state.handoff_accept(jti) is False

    def test_an_identifier_outside_the_alphabet_is_refused(self):
        with pytest.raises(ValueError):
            _auth_state.handoff_seen("bad:jti")

    def test_a_handoff_that_cannot_consult_shared_state_is_refused(self, monkeypatch):
        from app.session import handoff_token

        def refuse(*_args, **_kwargs):
            raise RuntimeError("общее состояние аутентификации недоступно")

        monkeypatch.setattr(handoff_token._auth_state, "handoff_seen", refuse)
        with pytest.raises(handoff_token.HandoffUnavailableError):
            handoff_token._replay_seen(secrets.token_hex(16))


class TestSharedStateUnavailable:
    """Решение владельца: без общего состояния челлендж не выдаётся, а не живёт в памяти воркера."""

    def test_a_passkey_step_that_cannot_record_the_challenge_answers_503(self, client, monkeypatch):
        from app.authentication import passkey as passkey_routes

        def refuse(*_args, **_kwargs):
            raise RuntimeError("общее состояние аутентификации недоступно")

        monkeypatch.setattr(passkey_routes._auth_state, "passkey_open_login", refuse)
        csrf = client.get("/api/authentication/csrf-token").json().get("csrf_token", "")
        answered = client.post(
            "/api/authentication/passkey/login-options", headers={"X-CSRF-Token": csrf}
        )
        assert answered.status_code == 503

    def test_a_qr_init_that_cannot_record_the_session_answers_503(self, client, monkeypatch):
        from app.authentication import qr_login as qr_routes

        def refuse(*_args, **_kwargs):
            raise RuntimeError("общее состояние аутентификации недоступно")

        monkeypatch.setattr(qr_routes._auth_state, "qr_open", refuse)
        csrf = client.get("/api/authentication/csrf-token").json().get("csrf_token", "")
        answered = client.post("/api/authentication/qr-init", headers={"X-CSRF-Token": csrf})
        assert answered.status_code == 503

    def test_a_wallet_challenge_that_cannot_be_recorded_answers_503(
        self, client, logged_user, monkeypatch
    ):
        from app.security import premium_check

        def refuse(*_args, **_kwargs):
            raise RuntimeError("общее состояние аутентификации недоступно")

        monkeypatch.setattr(premium_check._auth_state, "wallet_issue", refuse)
        answered = client.get("/api/premium/challenge", headers=logged_user["headers"])
        assert answered.status_code == 503
