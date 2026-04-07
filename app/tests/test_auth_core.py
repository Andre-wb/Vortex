"""Тесты аутентификации: регистрация, логин, сессии."""

import secrets

from conftest import SyncASGIClient, random_str, random_digits, make_user, login_user, _phone_prefix


_test_phone_pfx = _phone_prefix


class TestRegistration:

    def test_register_success(self, client: SyncASGIClient):
        tag  = random_str()
        resp = client.post('/api/authentication/register', json={
            'username':          f'user_{tag}',
            'password':          'ValidPassAbc99!@',
            'display_name':      f'Test {tag}',
            'phone':             f'+2{int(_test_phone_pfx, 16):04d}{random_digits(7)}',
            'avatar_emoji':      '\U0001f6f8',
            'x25519_public_key': secrets.token_hex(32),
        })
        assert resp.status_code == 201
        body = resp.json()
        assert 'id' in body or 'username' in body

    def test_register_duplicate_username(self, client: SyncASGIClient, fresh_user: dict):
        resp = client.post('/api/authentication/register', json={
            'username':          fresh_user['username'],
            'password':          'AnotherPassAbc1!@',
            'display_name':      'Dup',
            'phone':             f'+2{int(_test_phone_pfx, 16):04d}{random_digits(7)}',
            'avatar_emoji':      '\U0001f30a',
            'x25519_public_key': secrets.token_hex(32),
        })
        assert resp.status_code in (400, 409, 422)

    def test_register_missing_fields(self, client: SyncASGIClient):
        resp = client.post('/api/authentication/register', json={'username': 'nope'})
        assert resp.status_code == 422

    def test_register_weak_password(self, client: SyncASGIClient):
        tag  = random_str()
        resp = client.post('/api/authentication/register', json={
            'username':          f'user_{tag}',
            'password':          '123',
            'display_name':      'Weak',
            'phone':             f'+2{int(_test_phone_pfx, 16):04d}{random_digits(7)}',
            'avatar_emoji':      '\U0001f634',
            'x25519_public_key': secrets.token_hex(32),
        })
        assert resp.status_code in (400, 422)

    def test_register_stores_pubkey(self, client: SyncASGIClient):
        user    = make_user(client)
        headers = login_user(client, user['username'], user['password'])
        me      = client.get('/api/authentication/me', headers=headers)
        assert me.status_code == 200
        data = me.json()
        assert 'x25519_public_key' in data or 'pubkey' in str(data)


class TestLogin:

    def test_login_success(self, client: SyncASGIClient, fresh_user: dict):
        csrf = client.get('/api/authentication/csrf-token').json().get('csrf_token', '')
        resp = client.post('/api/authentication/login', json={
            'phone_or_username': fresh_user['username'],
            'password':          fresh_user['password'],
        }, headers={'X-CSRF-Token': csrf})
        assert resp.status_code == 200

    def test_login_wrong_password(self, client: SyncASGIClient, fresh_user: dict):
        csrf = client.get('/api/authentication/csrf-token').json().get('csrf_token', '')
        resp = client.post('/api/authentication/login', json={
            'phone_or_username': fresh_user['username'],
            'password':          'WrongPassword!@',
        }, headers={'X-CSRF-Token': csrf})
        assert resp.status_code in (400, 401, 403)

    def test_login_nonexistent_user(self, client: SyncASGIClient):
        csrf = client.get('/api/authentication/csrf-token').json().get('csrf_token', '')
        resp = client.post('/api/authentication/login', json={
            'phone_or_username': 'no_such_user_abc123',
            'password':          'PasswordAbc99!@',
        }, headers={'X-CSRF-Token': csrf})
        assert resp.status_code in (400, 401, 403, 404), \
            f'Ожидался 400/401/403/404, получен {resp.status_code}'

    def test_logout(self, client: SyncASGIClient, logged_user: dict):
        resp = client.post('/api/authentication/logout', headers=logged_user['headers'])
        assert resp.status_code in (200, 204)


class TestSession:

    def test_me_authenticated(self, client: SyncASGIClient, logged_user: dict):
        resp = client.get('/api/authentication/me', headers=logged_user['headers'])
        assert resp.status_code == 200
        assert resp.json().get('username') == logged_user['username']

    def test_me_unauthenticated(self, client: SyncASGIClient):
        bare = SyncASGIClient()
        resp = bare.get('/api/authentication/me')
        assert resp.status_code == 401

    def test_csrf_token_endpoint(self, client: SyncASGIClient):
        resp = client.get('/api/authentication/csrf-token')
        assert resp.status_code == 200
        data = resp.json()
        assert 'csrf_token' in data
        assert len(data['csrf_token']) > 10
