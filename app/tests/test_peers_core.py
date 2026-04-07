"""Тесты пиров: список, статус ноды, публичные комнаты."""

from conftest import SyncASGIClient


class TestPeers:

    def test_peers_list_authenticated(self, client: SyncASGIClient, logged_user: dict):
        resp = client.get('/api/peers', headers=logged_user['headers'])
        assert resp.status_code == 200
        data = resp.json()
        assert 'peers' in data or isinstance(data, list)

    def test_node_status_public(self, client: SyncASGIClient):
        resp = client.get('/api/peers/status')
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            assert isinstance(resp.json(), dict)

    def test_public_rooms_from_peers(self, client: SyncASGIClient, logged_user: dict):
        resp = client.get('/api/peers/public-rooms', headers=logged_user['headers'])
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            data = resp.json()
            assert 'rooms' in data or isinstance(data, list)
