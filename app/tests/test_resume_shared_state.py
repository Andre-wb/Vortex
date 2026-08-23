"""Разделяемое состояние возобновления: сессии дозагрузки файла и курсоры переноса.

Записи живут в Rust (`vortex-resume`), Python зовёт их через
`app/session/resume_backend.py`. Здесь проверяется контракт, который видят
потребители: что вернёт план кусков, что покажет статус сессии и что
происходит с курсором клиента.
"""

import secrets

import pytest

from app.session import resume_backend as _resume


@pytest.fixture
def upload_id():
    return secrets.token_urlsafe(24)


@pytest.fixture
def client_key():
    return secrets.token_hex(32)


def _open(upload_id, total_chunks=4):
    _resume.upload_open(upload_id, 3, 7, "payload.bin", 4096, total_chunks, "ab" * 32)


class TestChunkPlan:
    def test_a_file_shorter_than_one_chunk_still_takes_one(self):
        assert _resume.upload_plan(1, 1024 * 1024) == (1024 * 1024, 1)

    def test_a_remainder_takes_a_chunk_of_its_own(self):
        assert _resume.upload_plan(1024 * 1024 + 1, 1024 * 1024)[1] == 2

    def test_an_asked_chunk_size_is_kept_inside_the_agreed_bounds(self):
        limits = _resume.upload_limits()
        assert _resume.upload_plan(1_000_000, 1)[0] == limits["min_chunk_bytes"]
        assert _resume.upload_plan(1_000_000, 1 << 40)[0] == limits["max_chunk_bytes"]

    def test_an_empty_file_names_no_plan(self):
        with pytest.raises(ValueError):
            _resume.upload_plan(0, 1024 * 1024)

    def test_a_file_needing_more_chunks_than_allowed_is_refused(self):
        limits = _resume.upload_limits()
        too_big = limits["min_chunk_bytes"] * (limits["max_chunks"] + 1)
        with pytest.raises(ValueError):
            _resume.upload_plan(too_big, limits["min_chunk_bytes"])


class TestUploadSessions:
    def test_an_opened_session_is_found_again(self, upload_id):
        _open(upload_id)
        told = _resume.upload_find(upload_id)
        assert told["state"] == "live"
        assert told["total_chunks"] == 4
        assert told["file_name"] == "payload.bin"
        assert told["missing"] == [0, 1, 2, 3]
        assert told["complete"] is False

    def test_an_unknown_token_names_no_session(self, upload_id):
        assert _resume.upload_find(upload_id)["state"] == "missing"

    def test_a_token_outside_the_alphabet_is_refused(self):
        with pytest.raises(ValueError):
            _resume.upload_find("has space")

    def test_a_received_chunk_moves_the_progress(self, upload_id):
        _open(upload_id)
        taken = _resume.upload_receive(upload_id, 1)
        assert taken["outcome"] == "accepted"
        assert taken["progress"] == 25.0
        assert taken["missing"] == [0, 2, 3]

    def test_the_same_chunk_twice_is_taken_once(self, upload_id):
        _open(upload_id)
        _resume.upload_receive(upload_id, 0)
        again = _resume.upload_receive(upload_id, 0)
        assert again["outcome"] == "already_held"
        assert again["received_count"] == 1

    def test_a_chunk_outside_the_plan_is_refused(self, upload_id):
        _open(upload_id)
        assert _resume.upload_receive(upload_id, 4)["outcome"] == "outside_plan"

    def test_every_chunk_completes_the_session(self, upload_id):
        _open(upload_id, total_chunks=3)
        for index in range(3):
            _resume.upload_receive(upload_id, index)
        told = _resume.upload_find(upload_id)
        assert told["complete"] is True
        assert told["missing"] == []
        assert told["progress"] == 100.0

    def test_a_chunk_for_an_unknown_session_is_refused(self, upload_id):
        assert _resume.upload_receive(upload_id, 0)["outcome"] == "missing"

    def test_a_closed_session_is_gone(self, upload_id):
        _open(upload_id)
        assert _resume.upload_close(upload_id) is True
        assert _resume.upload_close(upload_id) is False
        assert _resume.upload_find(upload_id)["state"] == "missing"

    def test_sessions_do_not_shadow_each_other(self, upload_id):
        other = secrets.token_urlsafe(24)
        _open(upload_id)
        _open(other, total_chunks=2)
        _resume.upload_receive(upload_id, 0)
        assert _resume.upload_find(other)["received_count"] == 0

    def test_a_file_name_with_a_line_break_is_refused(self, upload_id):
        with pytest.raises(ValueError):
            _resume.upload_open(upload_id, 3, 7, "a\nb.bin", 4096, 4, "ab" * 32)


class TestSessionCursors:
    def test_a_saved_cursor_is_read_back(self, client_key):
        saved = _resume.cursor_save(client_key, 17.5, [3, 1])
        assert saved["last_bmp_ts"] == 17.5
        assert saved["rooms"] == [1, 3]
        assert _resume.cursor_find(client_key)["rooms"] == [1, 3]

    def test_an_unknown_client_names_no_cursor(self, client_key):
        assert _resume.cursor_find(client_key) is None

    def test_a_later_save_replaces_the_earlier_one(self, client_key):
        _resume.cursor_save(client_key, 1.0, [1])
        _resume.cursor_save(client_key, 2.0, [2])
        assert _resume.cursor_find(client_key)["last_bmp_ts"] == 2.0

    def test_rooms_are_stored_sorted_and_without_repeats(self, client_key):
        assert _resume.cursor_save(client_key, 1.0, [9, 3, 9, 1])["rooms"] == [1, 3, 9]

    def test_a_stamp_before_the_epoch_settles_at_zero(self, client_key):
        assert _resume.cursor_save(client_key, -5.0, [])["last_bmp_ts"] == 0.0

    def test_a_room_list_is_cut_at_the_agreed_limit(self, client_key):
        limit = _resume.upload_limits()["max_cursor_rooms"]
        saved = _resume.cursor_save(client_key, 1.0, list(range(1, limit + 11)))
        assert len(saved["rooms"]) == limit

    def test_a_forgotten_cursor_is_gone(self, client_key):
        _resume.cursor_save(client_key, 1.0, [1])
        assert _resume.cursor_forget(client_key) is True
        assert _resume.cursor_forget(client_key) is False
        assert _resume.cursor_find(client_key) is None

    def test_an_empty_key_names_no_client(self):
        with pytest.raises(ValueError):
            _resume.cursor_find("")

    def test_an_over_long_key_is_refused(self):
        with pytest.raises(ValueError):
            _resume.cursor_save("a" * 129, 1.0, [])

    def test_a_key_that_would_split_a_store_key_is_refused(self):
        with pytest.raises(ValueError):
            _resume.cursor_save("has:colon", 1.0, [])
