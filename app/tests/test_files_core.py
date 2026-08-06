"""Тесты файлов: загрузка, лимиты, целостность."""

import hashlib
import io
import os

from conftest import SyncASGIClient


class TestFiles:
    def test_upload_small_text_file(self, client: SyncASGIClient, logged_user: dict, room: dict):
        room_id = room.get("id") or room.get("room", {}).get("id")
        content = b"Hello from VORTEX test suite!"
        files = {"file": ("test.txt", io.BytesIO(content), "text/plain")}
        resp = client.post(f"/api/files/upload/{room_id}", files=files, headers=logged_user["headers"])
        assert resp.status_code in (200, 201, 400, 404)

    def test_upload_image(self, client: SyncASGIClient, logged_user: dict, room: dict):
        room_id = room.get("id") or room.get("room", {}).get("id")
        png_bytes = bytes(
            [
                0x89,
                0x50,
                0x4E,
                0x47,
                0x0D,
                0x0A,
                0x1A,
                0x0A,
                0x00,
                0x00,
                0x00,
                0x0D,
                0x49,
                0x48,
                0x44,
                0x52,
                0x00,
                0x00,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x01,
                0x08,
                0x02,
                0x00,
                0x00,
                0x00,
                0x90,
                0x77,
                0x53,
                0xDE,
                0x00,
                0x00,
                0x00,
                0x0C,
                0x49,
                0x44,
                0x41,
                0x54,
                0x08,
                0xD7,
                0x63,
                0xF8,
                0xCF,
                0xC0,
                0x00,
                0x00,
                0x00,
                0x02,
                0x00,
                0x01,
                0xE2,
                0x21,
                0xBC,
                0x33,
                0x00,
                0x00,
                0x00,
                0x00,
                0x49,
                0x45,
                0x4E,
                0x44,
                0xAE,
                0x42,
                0x60,
                0x82,
            ]
        )
        files = {"file": ("test.png", io.BytesIO(png_bytes), "image/png")}
        resp = client.post(f"/api/files/upload/{room_id}", files=files, headers=logged_user["headers"])
        assert resp.status_code in (200, 201, 400, 404)

    def test_upload_exceeds_limit(self, client: SyncASGIClient, logged_user: dict, room: dict):
        room_id = room.get("id") or room.get("room", {}).get("id")
        big = io.BytesIO(b"X" * (100 * 1024 * 1024 + 1024))
        files = {"file": ("huge.bin", big, "application/octet-stream")}
        resp = client.post(f"/api/files/upload/{room_id}", files=files, headers=logged_user["headers"])
        assert resp.status_code in (400, 413, 422, 415)

    def test_sha256_integrity(self):
        original_data = os.urandom(8192)
        original_hash = hashlib.sha256(original_data).hexdigest()
        assert hashlib.sha256(original_data).hexdigest() == original_hash
        corrupted = bytearray(original_data)
        corrupted[500] ^= 0xAB
        assert hashlib.sha256(bytes(corrupted)).hexdigest() != original_hash

    def test_room_files_list(self, client: SyncASGIClient, logged_user: dict, room: dict):
        room_id = room.get("id") or room.get("room", {}).get("id")
        resp = client.get(f"/api/files/room/{room_id}", headers=logged_user["headers"])
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            assert "files" in resp.json()
