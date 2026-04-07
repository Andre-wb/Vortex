"""
test_files_advanced.py — Comprehensive tests for files_advanced and resumable upload.

Covers:
  - GET /api/files/compression-presets
  - GET /api/files/gallery/{room_id}
  - GET /api/files/search/{room_id}
  - GET /api/files/stats/{room_id}
  - GET /api/files/preview/{room_id}/{file_id}
  - POST /api/files/distributed/register
  - GET  /api/files/distributed/{file_hash}
  - GET  /api/files/distributed/list
  - POST /api/files/upload-init
  - GET  /api/files/upload-status/{upload_id}
  - DELETE /api/files/upload-cancel/{upload_id}
"""
from __future__ import annotations

import hashlib
import secrets

import pytest

from conftest import make_user, login_user, random_str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _register_and_login(client) -> dict:
    u = make_user(client)
    h = login_user(client, u["username"], u["password"])
    return h


def _create_room(client, headers: dict, *, name: str | None = None) -> dict:
    r = client.post("/api/rooms", json={
        "name": name or f"room_{random_str()}",
        "is_public": True,
        "encrypted_room_key": {
            "ephemeral_pub": secrets.token_hex(32),
            "ciphertext": secrets.token_hex(60),
        },
    }, headers=headers)
    assert r.status_code in (200, 201), f"create room failed: {r.text}"
    return r.json()


def _valid_sha256() -> str:
    return hashlib.sha256(b"test_file_content").hexdigest()


# ── Compression Presets (no auth required) ───────────────────────────────────

class TestCompressionPresets:

    def test_compression_presets_unauthenticated(self, client):
        """Compression presets endpoint is publicly accessible."""
        r = client.get("/api/files/compression-presets")
        assert r.status_code == 200

    def test_compression_presets_has_presets_key(self, client):
        r = client.get("/api/files/compression-presets")
        body = r.json()
        assert "presets" in body

    def test_compression_presets_contains_expected_levels(self, client):
        r = client.get("/api/files/compression-presets")
        presets = r.json()["presets"]
        for level in ("original", "high", "medium", "low", "data_saver"):
            assert level in presets, f"Missing preset: {level}"

    def test_compression_presets_has_max_file_size(self, client):
        r = client.get("/api/files/compression-presets")
        body = r.json()
        assert "max_file_size_mb" in body
        assert isinstance(body["max_file_size_mb"], (int, float))
        assert body["max_file_size_mb"] > 0

    def test_compression_presets_has_supported_formats(self, client):
        r = client.get("/api/files/compression-presets")
        body = r.json()
        assert "supported_formats" in body
        fmt = body["supported_formats"]
        assert "images" in fmt
        assert "video" in fmt
        assert "audio" in fmt

    def test_compression_preset_original_quality_100(self, client):
        r = client.get("/api/files/compression-presets")
        orig = r.json()["presets"]["original"]
        assert orig["image_quality"] == 100

    def test_compression_preset_data_saver_smallest(self, client):
        r = client.get("/api/files/compression-presets")
        presets = r.json()["presets"]
        # data_saver should have lowest image quality
        assert presets["data_saver"]["image_quality"] < presets["low"]["image_quality"]


# ── Gallery ───────────────────────────────────────────────────────────────────

class TestGallery:

    def test_gallery_unauthenticated_returns_401(self, anon_client):
        r = anon_client.get("/api/files/gallery/999")
        assert r.status_code in (401, 403)

    def test_gallery_member_sees_empty_gallery(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]
        r = client.get(f"/api/files/gallery/{room_id}", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert "media" in body
        assert isinstance(body["media"], list)

    def test_gallery_response_has_pagination_fields(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]
        r = client.get(f"/api/files/gallery/{room_id}", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert "total" in body
        assert "page" in body
        assert "per_page" in body
        assert "pages" in body

    def test_gallery_default_page_is_one(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]
        r = client.get(f"/api/files/gallery/{room_id}", headers=h)
        assert r.json()["page"] == 1

    def test_gallery_page_param(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]
        r = client.get(f"/api/files/gallery/{room_id}?page=2", headers=h)
        assert r.status_code == 200
        assert r.json()["page"] == 2

    def test_gallery_media_type_images_filter(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]
        r = client.get(f"/api/files/gallery/{room_id}?media_type=images", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert "media" in body

    def test_gallery_media_type_videos_filter(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]
        r = client.get(f"/api/files/gallery/{room_id}?media_type=videos", headers=h)
        assert r.status_code == 200

    def test_gallery_media_type_audio_filter(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]
        r = client.get(f"/api/files/gallery/{room_id}?media_type=audio", headers=h)
        assert r.status_code == 200

    def test_gallery_media_type_documents_filter(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]
        r = client.get(f"/api/files/gallery/{room_id}?media_type=documents", headers=h)
        assert r.status_code == 200

    def test_gallery_non_member_forbidden(self, client):
        # Owner creates a private room; another user tries to access gallery
        h_owner = _register_and_login(client)
        room = _create_room(client, h_owner)
        room_id = room["id"]

        h_other = _register_and_login(client)
        r = client.get(f"/api/files/gallery/{room_id}", headers=h_other)
        assert r.status_code in (403, 404)

    def test_gallery_nonexistent_room_not_accessible(self, client):
        h = _register_and_login(client)
        r = client.get("/api/files/gallery/9999999", headers=h)
        assert r.status_code in (403, 404)


# ── File Search ────────────────────────────────────────────────────────────────

class TestFileSearch:

    def test_search_unauthenticated_returns_401(self, anon_client):
        r = anon_client.get("/api/files/search/999")
        assert r.status_code in (401, 403)

    def test_search_member_returns_results_list(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]
        r = client.get(f"/api/files/search/{room_id}", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert "results" in body
        assert isinstance(body["results"], list)
        assert "count" in body

    def test_search_with_query_param(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]
        r = client.get(f"/api/files/search/{room_id}?q=test", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == len(body["results"])

    def test_search_with_file_type_filter(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]
        r = client.get(f"/api/files/search/{room_id}?file_type=image", headers=h)
        assert r.status_code == 200

    def test_search_with_sender_id_filter(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]
        r = client.get(f"/api/files/search/{room_id}?sender_id=1", headers=h)
        assert r.status_code == 200

    def test_search_non_member_forbidden(self, client):
        h_owner = _register_and_login(client)
        room = _create_room(client, h_owner)
        room_id = room["id"]

        h_other = _register_and_login(client)
        r = client.get(f"/api/files/search/{room_id}", headers=h_other)
        assert r.status_code in (403, 404)

    def test_search_combined_filters(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]
        r = client.get(f"/api/files/search/{room_id}?q=doc&file_type=application/pdf", headers=h)
        assert r.status_code == 200
        body = r.json()
        # All returned results should match pdf mime
        for item in body["results"]:
            assert "pdf" in item.get("mime_type", "")


# ── File Stats ────────────────────────────────────────────────────────────────

class TestFileStats:

    def test_stats_unauthenticated_returns_401(self, anon_client):
        r = anon_client.get("/api/files/stats/999")
        assert r.status_code in (401, 403)

    def test_stats_member_sees_stats(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]
        r = client.get(f"/api/files/stats/{room_id}", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert "total_files" in body
        assert "total_size_bytes" in body
        assert "total_size_human" in body
        assert "by_type" in body

    def test_stats_empty_room_shows_zero_files(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]
        r = client.get(f"/api/files/stats/{room_id}", headers=h)
        assert r.status_code == 200
        assert r.json()["total_files"] == 0
        assert r.json()["total_size_bytes"] == 0

    def test_stats_non_member_forbidden(self, client):
        h_owner = _register_and_login(client)
        room = _create_room(client, h_owner)
        room_id = room["id"]

        h_other = _register_and_login(client)
        r = client.get(f"/api/files/stats/{room_id}", headers=h_other)
        assert r.status_code in (403, 404)


# ── Distributed Files ─────────────────────────────────────────────────────────

class TestDistributedFiles:

    def test_register_distributed_file_success(self, client):
        h = _register_and_login(client)
        file_hash = secrets.token_hex(32)
        payload = {
            "file_hash": file_hash,
            "filename": "bigfile.bin",
            "total_size": 1024 * 1024,
            "chunk_count": 2,
            "chunks": [
                {
                    "chunk_hash": secrets.token_hex(32),
                    "chunk_index": 0,
                    "size": 524288,
                    "node_ip": "127.0.0.1",
                    "node_port": 9001,
                },
                {
                    "chunk_hash": secrets.token_hex(32),
                    "chunk_index": 1,
                    "size": 524288,
                    "node_ip": "127.0.0.2",
                    "node_port": 9001,
                },
            ],
        }
        r = client.post("/api/files/distributed/register", json=payload, headers=h)
        assert r.status_code == 200
        body = r.json()
        assert body.get("ok") is True
        assert body.get("file_hash") == file_hash

    def test_register_distributed_unauthenticated(self, anon_client):
        r = anon_client.post("/api/files/distributed/register", json={
            "file_hash": secrets.token_hex(32),
            "filename": "x.bin",
            "total_size": 100,
            "chunk_count": 1,
            "chunks": [],
        })
        assert r.status_code in (401, 403)

    def test_get_distributed_file_exists(self, client):
        h = _register_and_login(client)
        file_hash = secrets.token_hex(32)
        client.post("/api/files/distributed/register", json={
            "file_hash": file_hash,
            "filename": "retrieve_me.bin",
            "total_size": 512,
            "chunk_count": 1,
            "chunks": [],
        }, headers=h)
        r = client.get(f"/api/files/distributed/{file_hash}", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert body["filename"] == "retrieve_me.bin"
        assert body["total_size"] == 512

    def test_get_distributed_file_not_found(self, client):
        h = _register_and_login(client)
        r = client.get(f"/api/files/distributed/nonexistenthash123", headers=h)
        assert r.status_code == 404

    def test_list_distributed_files_authenticated(self, client):
        h = _register_and_login(client)
        r = client.get("/api/files/distributed/list", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert "files" in body
        assert isinstance(body["files"], list)

    def test_list_distributed_files_unauthenticated(self, anon_client):
        r = anon_client.get("/api/files/distributed/list")
        assert r.status_code in (401, 403)

    def test_registered_file_appears_in_list(self, client):
        h = _register_and_login(client)
        file_hash = secrets.token_hex(32)
        fname = f"listed_{random_str(6)}.bin"
        client.post("/api/files/distributed/register", json={
            "file_hash": file_hash,
            "filename": fname,
            "total_size": 1024,
            "chunk_count": 1,
            "chunks": [],
        }, headers=h)
        r = client.get("/api/files/distributed/list", headers=h)
        assert r.status_code == 200
        hashes = [f["file_hash"] for f in r.json()["files"]]
        assert file_hash in hashes


# ── Resumable Upload ──────────────────────────────────────────────────────────

class TestResumableUpload:

    def test_upload_init_unauthenticated(self, anon_client):
        r = anon_client.post("/api/files/upload-init", data={
            "room_id": "1",
            "file_name": "test.txt",
            "file_size": "1024",
            "file_hash": _valid_sha256(),
        })
        assert r.status_code in (401, 403)

    def test_upload_init_success(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]

        content = b"hello world test data for upload"
        file_hash = hashlib.sha256(content).hexdigest()

        r = client.post("/api/files/upload-init", data={
            "room_id": str(room_id),
            "file_name": "test.txt",
            "file_size": str(len(content)),
            "file_hash": file_hash,
        }, headers=h)
        assert r.status_code == 200
        body = r.json()
        assert "upload_id" in body
        assert "total_chunks" in body
        assert "chunk_size" in body
        assert "received" in body
        assert body["received"] == []

    def test_upload_init_total_chunks_calculated_correctly(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]

        # 2 MB file with 1 MB chunk size => 2 chunks
        file_size = 2 * 1024 * 1024
        chunk_size = 1 * 1024 * 1024
        file_hash = _valid_sha256()

        r = client.post("/api/files/upload-init", data={
            "room_id": str(room_id),
            "file_name": "bigfile.bin",
            "file_size": str(file_size),
            "file_hash": file_hash,
            "chunk_size": str(chunk_size),
        }, headers=h)
        assert r.status_code == 200
        body = r.json()
        assert body["total_chunks"] == 2

    def test_upload_init_non_member_room_forbidden(self, client):
        h_owner = _register_and_login(client)
        room = _create_room(client, h_owner)
        room_id = room["id"]

        h_other = _register_and_login(client)
        r = client.post("/api/files/upload-init", data={
            "room_id": str(room_id),
            "file_name": "test.txt",
            "file_size": "100",
            "file_hash": _valid_sha256(),
        }, headers=h_other)
        assert r.status_code in (400, 403, 422)

    def test_upload_init_invalid_file_hash_length(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]

        r = client.post("/api/files/upload-init", data={
            "room_id": str(room_id),
            "file_name": "test.txt",
            "file_size": "100",
            "file_hash": "tooshort",
        }, headers=h)
        assert r.status_code in (400, 422)

    def test_upload_status_unauthenticated(self, anon_client):
        r = anon_client.get("/api/files/upload-status/fakeid123")
        assert r.status_code in (401, 403)

    def test_upload_status_nonexistent_session(self, client):
        h = _register_and_login(client)
        r = client.get("/api/files/upload-status/nonexistent_upload_id_xyz", headers=h)
        assert r.status_code == 404

    def test_upload_status_after_init(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]

        content = b"status check content"
        file_hash = hashlib.sha256(content).hexdigest()

        init_r = client.post("/api/files/upload-init", data={
            "room_id": str(room_id),
            "file_name": "status_test.txt",
            "file_size": str(len(content)),
            "file_hash": file_hash,
        }, headers=h)
        assert init_r.status_code == 200
        upload_id = init_r.json()["upload_id"]

        status_r = client.get(f"/api/files/upload-status/{upload_id}", headers=h)
        assert status_r.status_code == 200
        body = status_r.json()
        assert body["upload_id"] == upload_id
        assert body["file_name"] == "status_test.txt"
        assert body["file_size"] == len(content)
        assert isinstance(body["received"], list)
        assert isinstance(body["missing"], list)
        assert "progress" in body
        assert "complete" in body
        assert body["complete"] is False

    def test_upload_cancel_unauthenticated(self, anon_client):
        r = anon_client.delete("/api/files/upload-cancel/fakeid")
        assert r.status_code in (401, 403)

    def test_upload_cancel_nonexistent_session_ok(self, client):
        h = _register_and_login(client)
        r = client.delete("/api/files/upload-cancel/nonexistent_cancel_id", headers=h)
        # Should return ok even for non-existent sessions
        assert r.status_code == 200
        assert r.json().get("ok") is True

    def test_upload_cancel_after_init(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]

        content = b"cancel me please"
        file_hash = hashlib.sha256(content).hexdigest()

        init_r = client.post("/api/files/upload-init", data={
            "room_id": str(room_id),
            "file_name": "cancel_me.txt",
            "file_size": str(len(content)),
            "file_hash": file_hash,
        }, headers=h)
        assert init_r.status_code == 200
        upload_id = init_r.json()["upload_id"]

        cancel_r = client.delete(f"/api/files/upload-cancel/{upload_id}", headers=h)
        assert cancel_r.status_code == 200
        assert cancel_r.json().get("ok") is True

        # Status should now return 404 since session was cancelled
        status_r = client.get(f"/api/files/upload-status/{upload_id}", headers=h)
        assert status_r.status_code == 404

    def test_upload_init_zero_file_size_rejected(self, client):
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]

        r = client.post("/api/files/upload-init", data={
            "room_id": str(room_id),
            "file_name": "empty.txt",
            "file_size": "0",
            "file_hash": _valid_sha256(),
        }, headers=h)
        assert r.status_code in (400, 422)

    def test_upload_complete_missing_chunks_rejected(self, client):
        """Completing upload without uploading chunks should fail."""
        h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]

        content = b"incomplete upload test data that is longer than usual"
        file_hash = hashlib.sha256(content).hexdigest()

        init_r = client.post("/api/files/upload-init", data={
            "room_id": str(room_id),
            "file_name": "incomplete.txt",
            "file_size": str(len(content)),
            "file_hash": file_hash,
        }, headers=h)
        assert init_r.status_code == 200
        upload_id = init_r.json()["upload_id"]

        # Try to complete without uploading any chunks
        complete_r = client.post(f"/api/files/upload-complete/{upload_id}", headers=h)
        assert complete_r.status_code in (400, 422)
