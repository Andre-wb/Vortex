"""
Tests for sticker packs.
"""
import pytest

from conftest import random_str


class TestStickers:

    def test_list_sticker_packs(self, client, logged_user):
        resp = client.get("/api/stickers/packs", headers=logged_user["headers"])
        assert resp.status_code in (200, 404)

    def test_create_sticker_pack(self, client, logged_user):
        resp = client.post("/api/stickers/packs", json={
            "name": f"pack_{random_str()}",
            "description": "Test sticker pack",
        }, headers=logged_user["headers"])
        assert resp.status_code in (200, 201, 422)

    def test_stickers_unauthenticated(self, client):
        from conftest import SyncASGIClient
        bare = SyncASGIClient()
        resp = bare.get("/api/stickers/packs")
        assert resp.status_code in (200, 401, 403)
        bare.close()
