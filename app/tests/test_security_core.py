"""Тесты безопасности: SQLi, XSS, CSRF, path traversal, авторизация."""

import os
import secrets

import pytest

from conftest import SyncASGIClient, random_str, random_digits, _phone_prefix


_test_phone_pfx = _phone_prefix


class TestSecurity:

    @pytest.mark.parametrize('payload', [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1 UNION SELECT * FROM users",
        "admin'--",
        "' OR 1=1 --",
    ])
    def test_sqli_blocked_in_login(self, client: SyncASGIClient, payload: str):
        csrf = client.get('/api/authentication/csrf-token').json().get('csrf_token', '')
        resp = client.post('/api/authentication/login', json={
            'phone_or_username': payload,
            'password':          payload,
        }, headers={'X-CSRF-Token': csrf})
        assert resp.status_code != 200, \
            f'SQLi payload прошёл (получен 200): {payload!r}'

    @pytest.mark.parametrize('payload', [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '"><script>document.cookie</script>',
    ])
    def test_xss_in_display_name(self, client: SyncASGIClient, payload: str):
        tag  = random_str()
        resp = client.post('/api/authentication/register', json={
            'username':          f'xss_{tag}',
            'password':          'SafePassAbc99!@',
            'display_name':      payload,
            'phone':             f'+2{int(_test_phone_pfx, 16):04d}{random_digits(7)}',
            'avatar_emoji':      '\U0001f6f8',
            'x25519_public_key': secrets.token_hex(32),
        })
        if resp.status_code in (200, 201):
            assert '<script>' not in resp.text.lower()
        else:
            assert resp.status_code in (400, 403, 422)

    def test_mutation_without_csrf_rejected(self, client: SyncASGIClient, logged_user: dict):
        resp = client.post('/api/rooms', json={
            'room_name':          f'NoCSRF_{random_str()}',
            'is_public':          True,
            'encrypted_room_key': {
                'key': secrets.token_hex(32),
                'iv': secrets.token_hex(16),
                'version': '1'
            },
            'ephemeral_pub':      secrets.token_hex(32),
        })
        assert resp.status_code in (400, 401, 403, 422), \
            f'Запрос без CSRF токена должен быть отклонён, получено {resp.status_code}'

    @pytest.mark.parametrize('evil_path', [
        '../../../etc/passwd',
        '..%2F..%2Fetc%2Fpasswd',
        '/etc/shadow',
        '....//....//etc/hosts',
    ])
    def test_path_traversal_in_file_download(self, client: SyncASGIClient, logged_user: dict, evil_path: str):
        resp = client.get(f'/api/files/download/{evil_path}', headers=logged_user['headers'])
        assert resp.status_code in (400, 403, 404, 422), \
            f'Path traversal не заблокирован: {evil_path!r} \u2192 {resp.status_code}'

    def test_protected_routes_require_auth(self, client: SyncASGIClient):
        bare = SyncASGIClient()
        for method, url in [('GET', '/api/rooms/my'), ('GET', '/api/peers'), ('POST', '/api/rooms')]:
            if method == 'GET':
                r = bare.get(url)
            else:
                r = bare.post(url, json={})
            assert r.status_code in (401, 403, 422), \
                f'{method} {url} должен требовать авторизацию, получено {r.status_code}'

    def test_argon2_hash_not_plaintext(self):
        try:
            from argon2 import PasswordHasher
            ph     = PasswordHasher()
            hashed = ph.hash('my_secret_password')
            assert 'my_secret_password' not in hashed
            assert ph.verify(hashed, 'my_secret_password')
        except ImportError:
            pytest.skip('argon2-cffi не установлен')

    def test_jwt_secret_length(self):
        try:
            from app.config import Config as settings
            secret = getattr(settings, 'JWT_SECRET', '') or os.environ.get('JWT_SECRET', '')
            assert len(secret) >= 32, f'JWT_SECRET слишком короткий: {len(secret)} символов'
        except ImportError:
            pytest.skip('config не импортируется')
