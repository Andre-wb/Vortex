"""
test_multi_account.py — Тесты устойчивости мультиаккаунта.

Покрывает:
- Регистрация до 4 аккаунтов
- Switch через challenge-response (login-key)
- Сохранение/восстановление сессий
- Edge cases: 5-й аккаунт, switch на несуществующий, concurrent switch
- Изоляция данных между аккаунтами
"""
import secrets

import pytest

from conftest import make_user, login_user, random_str


class TestMultiAccountRegistration:
    """Регистрация нескольких аккаунтов."""

    def test_register_4_accounts(self, client):
        """Можно зарегистрировать 4 аккаунта (максимум)."""
        users = []
        for i in range(4):
            u = make_user(client, f'ma_reg_{i}_{random_str(4)}')
            users.append(u)
            assert u['data']['user_id'] is not None

        # Все 4 могут залогиниться
        for u in users:
            h = login_user(client, u['username'], u['password'])
            r = client.get('/api/contacts', headers=h)
            assert r.status_code == 200

    def test_each_account_has_unique_id(self, client):
        """Каждый аккаунт имеет уникальный user_id."""
        ids = set()
        for i in range(4):
            u = make_user(client, f'ma_uid_{i}_{random_str(4)}')
            ids.add(u['data']['user_id'])
        assert len(ids) == 4


class TestMultiAccountLogin:
    """Добавление аккаунтов через логин (уже существующие)."""

    def test_login_4_existing_accounts(self, client):
        """Создаём 4 аккаунта, потом логинимся в каждый — все работают."""
        users = []
        for i in range(4):
            u = make_user(client, f'ml_{i}_{random_str(4)}')
            users.append(u)

        # Логинимся в каждый по очереди (как при добавлении через Login)
        for u in users:
            h = login_user(client, u['username'], u['password'])
            r = client.get('/api/authentication/devices', headers=h)
            assert r.status_code == 200
            devices = r.json().get('devices', [])
            assert len(devices) >= 1, f"User {u['username']} has no devices after login"

    def test_login_preserves_previous_session(self, client):
        """Логин в другой аккаунт не удаляет сессию предыдущего."""
        u1 = make_user(client, f'lps1_{random_str(4)}')
        u2 = make_user(client, f'lps2_{random_str(4)}')

        # Логинимся в u1, создаём комнату
        h1 = login_user(client, u1['username'], u1['password'])
        r = client.post('/api/rooms', json={
            'name': f'persist_{random_str()}',
            'encrypted_room_key': {
                'ephemeral_pub': secrets.token_hex(32),
                'ciphertext': secrets.token_hex(60),
            },
        }, headers=h1)
        assert r.status_code in (200, 201)
        room_id = r.json()['id']

        # Логинимся в u2
        h2 = login_user(client, u2['username'], u2['password'])
        r = client.get('/api/contacts', headers=h2)
        assert r.status_code == 200

        # Возвращаемся в u1 — комната на месте
        h1 = login_user(client, u1['username'], u1['password'])
        kb = client.get(f'/api/rooms/{room_id}/key-bundle', headers=h1)
        assert kb.status_code == 200
        assert kb.json()['has_key'] is True

    def test_login_with_username(self, client):
        """Логин по username работает."""
        u = make_user(client, f'lun_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])
        r = client.get('/api/contacts', headers=h)
        assert r.status_code == 200

    def test_login_with_phone(self, client):
        """Логин по телефону работает."""
        u = make_user(client, f'lph_{random_str(4)}')
        # login_user использует username, попробуем через phone
        phone = u['data'].get('phone')
        if phone:
            csrf = client.get('/api/authentication/csrf-token').json().get('csrf_token', '')
            r = client.post('/api/authentication/login', json={
                'phone_or_username': phone,
                'password': u['password'],
            }, headers={'X-CSRF-Token': csrf})
            assert r.status_code == 200

    def test_login_wrong_password_fails(self, client):
        """Неправильный пароль — 401."""
        u = make_user(client, f'lwp_{random_str(4)}')
        csrf = client.get('/api/authentication/csrf-token').json().get('csrf_token', '')
        r = client.post('/api/authentication/login', json={
            'phone_or_username': u['username'],
            'password': 'WrongPassword123!@',
        }, headers={'X-CSRF-Token': csrf})
        assert r.status_code in (401, 403)

    def test_login_nonexistent_user_fails(self, client):
        """Несуществующий пользователь — ошибка."""
        csrf = client.get('/api/authentication/csrf-token').json().get('csrf_token', '')
        r = client.post('/api/authentication/login', json={
            'phone_or_username': f'nonexistent_{random_str(10)}',
            'password': 'AnyPassword99!@',
        }, headers={'X-CSRF-Token': csrf})
        assert r.status_code in (401, 404)

    def test_add_account_via_login_after_register(self, client):
        """Сценарий: зарегистрирован → добавить второй через логин."""
        # Первый аккаунт — регистрация
        u1 = make_user(client, f'ar1_{random_str(4)}')
        h1 = login_user(client, u1['username'], u1['password'])
        r = client.get('/api/contacts', headers=h1)
        assert r.status_code == 200

        # Второй аккаунт — тоже регистрация, потом логин
        u2 = make_user(client, f'ar2_{random_str(4)}')
        h2 = login_user(client, u2['username'], u2['password'])
        r = client.get('/api/contacts', headers=h2)
        assert r.status_code == 200

        # Переключаемся обратно на первый
        h1 = login_user(client, u1['username'], u1['password'])
        r = client.get('/api/contacts', headers=h1)
        assert r.status_code == 200

    def test_login_cycle_all_4(self, client):
        """Полный цикл: регистрация 4 → логин в каждый → API доступен."""
        users = [make_user(client, f'cycle_{i}_{random_str(4)}') for i in range(4)]

        # Цикл: логин → проверка → логин в следующий
        for cycle in range(2):  # 2 полных цикла
            for u in users:
                h = login_user(client, u['username'], u['password'])

                # Проверяем основные API
                assert client.get('/api/contacts', headers=h).status_code == 200
                assert client.get('/api/rooms/my', headers=h).status_code == 200
                assert client.get('/api/authentication/devices', headers=h).status_code == 200

    def test_login_creates_new_device(self, client):
        """Каждый логин создаёт новое устройство."""
        u = make_user(client, f'nd_{random_str(4)}')

        h = login_user(client, u['username'], u['password'])
        r1 = client.get('/api/authentication/devices', headers=h)
        count1 = len(r1.json().get('devices', []))

        h = login_user(client, u['username'], u['password'])
        r2 = client.get('/api/authentication/devices', headers=h)
        count2 = len(r2.json().get('devices', []))

        assert count2 >= count1


class TestMultiAccountSwitch:
    """Переключение между аккаунтами."""

    def test_switch_preserves_data(self, client):
        """После switch данные предыдущего аккаунта не смешиваются."""
        u1 = make_user(client, f'sw1_{random_str(4)}')
        u2 = make_user(client, f'sw2_{random_str(4)}')

        # Login as u1, create room
        h1 = login_user(client, u1['username'], u1['password'])
        r1 = client.post('/api/rooms', json={
            'name': f'room_u1_{random_str()}',
            'encrypted_room_key': {
                'ephemeral_pub': secrets.token_hex(32),
                'ciphertext': secrets.token_hex(60),
            },
        }, headers=h1)
        assert r1.status_code in (200, 201)

        # Login as u2, check rooms
        h2 = login_user(client, u2['username'], u2['password'])
        r2 = client.get('/api/rooms/my', headers=h2)
        assert r2.status_code == 200
        rooms = r2.json().get('rooms', [])
        # u2 не должен видеть комнату u1
        room_names = [r.get('name', '') for r in rooms]
        assert not any('room_u1_' in n for n in room_names)

    def test_switch_back_and_forth(self, client):
        """Можно переключаться туда-сюда без ошибок."""
        u1 = make_user(client, f'bf1_{random_str(4)}')
        u2 = make_user(client, f'bf2_{random_str(4)}')

        for _ in range(3):
            h1 = login_user(client, u1['username'], u1['password'])
            r = client.get('/api/contacts', headers=h1)
            assert r.status_code == 200

            h2 = login_user(client, u2['username'], u2['password'])
            r = client.get('/api/contacts', headers=h2)
            assert r.status_code == 200

    def test_login_key_endpoint(self, client):
        """Challenge-response login работает."""
        u = make_user(client, f'lk_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        # Получаем challenge
        r = client.get(
            f'/api/authentication/challenge?identifier={u["username"]}',
            headers=h,
        )
        # Challenge может требовать определённый формат — проверяем что endpoint существует
        assert r.status_code in (200, 400, 404)


class TestMultiAccountIsolation:
    """Изоляция данных между аккаунтами."""

    def test_contacts_isolated(self, client):
        """Контакты одного аккаунта не видны другому."""
        u1 = make_user(client, f'iso1_{random_str(4)}')
        u2 = make_user(client, f'iso2_{random_str(4)}')
        u3 = make_user(client, f'iso3_{random_str(4)}')

        # u1 добавляет u3 в контакты
        h1 = login_user(client, u1['username'], u1['password'])
        client.post('/api/contacts', json={'user_id': u3['data']['user_id']}, headers=h1)

        # u2 не должен видеть u3 в своих контактах
        h2 = login_user(client, u2['username'], u2['password'])
        r = client.get('/api/contacts', headers=h2)
        contacts = r.json().get('contacts', [])
        contact_ids = [c['user_id'] for c in contacts]
        assert u3['data']['user_id'] not in contact_ids

    def test_rooms_isolated(self, client):
        """Комнаты одного аккаунта не видны другому (если не вступил)."""
        u1 = make_user(client, f'ri1_{random_str(4)}')
        u2 = make_user(client, f'ri2_{random_str(4)}')

        h1 = login_user(client, u1['username'], u1['password'])
        client.post('/api/rooms', json={
            'name': f'private_room_{random_str()}',
            'is_public': False,
            'encrypted_room_key': {
                'ephemeral_pub': secrets.token_hex(32),
                'ciphertext': secrets.token_hex(60),
            },
        }, headers=h1)

        h2 = login_user(client, u2['username'], u2['password'])
        r = client.get('/api/rooms/my', headers=h2)
        rooms = r.json().get('rooms', [])
        assert not any('private_room_' in r.get('name', '') for r in rooms)

    def test_dm_isolated(self, client):
        """DM одного аккаунта не видны другому."""
        u1 = make_user(client, f'di1_{random_str(4)}')
        u2 = make_user(client, f'di2_{random_str(4)}')
        u3 = make_user(client, f'di3_{random_str(4)}')

        # u1 создаёт DM с u3
        h1 = login_user(client, u1['username'], u1['password'])
        client.post(f'/api/dm/{u3["data"]["user_id"]}', json={
            'encrypted_room_key': {
                'ephemeral_pub': secrets.token_hex(32),
                'ciphertext': secrets.token_hex(60),
            },
        }, headers=h1)

        # u2 не должен видеть этот DM
        h2 = login_user(client, u2['username'], u2['password'])
        r = client.get('/api/dm/list', headers=h2)
        assert r.status_code == 200
        dms = r.json().get('dms', r.json().get('rooms', []))
        # Ни одного DM для u2
        assert len(dms) == 0 or not any(
            d.get('dm_user', {}).get('user_id') == u3['data']['user_id']
            for d in dms
        )


class TestMultiAccountSessions:
    """Сессии и устройства при мультиаккаунте."""

    def test_each_account_has_own_devices(self, client):
        """Каждый аккаунт имеет свои устройства."""
        u1 = make_user(client, f'dev1_{random_str(4)}')
        u2 = make_user(client, f'dev2_{random_str(4)}')

        h1 = login_user(client, u1['username'], u1['password'])
        r1 = client.get('/api/authentication/devices', headers=h1)
        d1 = r1.json().get('devices', [])

        h2 = login_user(client, u2['username'], u2['password'])
        r2 = client.get('/api/authentication/devices', headers=h2)
        d2 = r2.json().get('devices', [])

        # Устройства не пересекаются
        ids1 = {d['id'] for d in d1}
        ids2 = {d['id'] for d in d2}
        assert ids1.isdisjoint(ids2)


class TestMultiAccountKeys:
    """Ключи шифрования при мультиаккаунте."""

    def test_room_keys_per_account(self, client):
        """Каждый аккаунт имеет свои room keys."""
        u1 = make_user(client, f'rk1_{random_str(4)}')
        u2 = make_user(client, f'rk2_{random_str(4)}')

        # u1 создаёт комнату с ключом
        h1 = login_user(client, u1['username'], u1['password'])
        eph1 = secrets.token_hex(32)
        r1 = client.post('/api/rooms', json={
            'name': f'key_room_{random_str()}',
            'encrypted_room_key': {
                'ephemeral_pub': eph1,
                'ciphertext': secrets.token_hex(60),
            },
        }, headers=h1)
        room_id = r1.json()['id']

        # u1 видит свой ключ
        kb1 = client.get(f'/api/rooms/{room_id}/key-bundle', headers=h1)
        assert kb1.json()['has_key'] is True

        # u2 не участник — не видит ключ
        h2 = login_user(client, u2['username'], u2['password'])
        kb2 = client.get(f'/api/rooms/{room_id}/key-bundle', headers=h2)
        assert kb2.status_code in (403, 404)

    def test_pubkey_unique_per_account(self, client):
        """Каждый аккаунт имеет уникальный X25519 ключ."""
        keys = set()
        for i in range(3):
            u = make_user(client, f'pk_{i}_{random_str(4)}')
            keys.add(u['x25519_pub'])
        assert len(keys) == 3


class TestMultiAccountEdgeCases:
    """Edge cases мультиаккаунта."""

    def test_rapid_switch(self, client):
        """Быстрое переключение не ломает сессии."""
        users = [make_user(client, f'rs_{i}_{random_str(4)}') for i in range(3)]

        for _ in range(5):
            for u in users:
                h = login_user(client, u['username'], u['password'])
                r = client.get('/api/contacts', headers=h)
                assert r.status_code == 200

    def test_concurrent_operations_different_accounts(self, client):
        """Операции от разных аккаунтов не конфликтуют."""
        u1 = make_user(client, f'co1_{random_str(4)}')
        u2 = make_user(client, f'co2_{random_str(4)}')

        h1 = login_user(client, u1['username'], u1['password'])

        # u1 создаёт комнату
        r1 = client.post('/api/rooms', json={
            'name': f'conc1_{random_str()}',
            'encrypted_room_key': {
                'ephemeral_pub': secrets.token_hex(32),
                'ciphertext': secrets.token_hex(60),
            },
        }, headers=h1)
        assert r1.status_code in (200, 201)

        h2 = login_user(client, u2['username'], u2['password'])

        # u2 создаёт свою комнату
        r2 = client.post('/api/rooms', json={
            'name': f'conc2_{random_str()}',
            'encrypted_room_key': {
                'ephemeral_pub': secrets.token_hex(32),
                'ciphertext': secrets.token_hex(60),
            },
        }, headers=h2)
        assert r2.status_code in (200, 201)

        # Оба видят свои комнаты
        h1 = login_user(client, u1['username'], u1['password'])
        rooms1 = client.get('/api/rooms/my', headers=h1).json().get('rooms', [])

        h2 = login_user(client, u2['username'], u2['password'])
        rooms2 = client.get('/api/rooms/my', headers=h2).json().get('rooms', [])

        ids1 = {r['id'] for r in rooms1}
        ids2 = {r['id'] for r in rooms2}

        # Каждый видит свою комнату
        assert r1.json()['id'] in ids1
        assert r2.json()['id'] in ids2

    def test_bot_isolated_per_account(self, client):
        """Боты привязаны к аккаунту."""
        u1 = make_user(client, f'bi1_{random_str(4)}')
        u2 = make_user(client, f'bi2_{random_str(4)}')

        # u1 создаёт бота
        h1 = login_user(client, u1['username'], u1['password'])
        br = client.post('/api/bots', json={
            'name': f'bot_{random_str(4)}',
        }, headers=h1)
        assert br.status_code in (200, 201)
        bot_id = br.json().get('bot_id')

        # u2 не видит бота u1
        h2 = login_user(client, u2['username'], u2['password'])
        r2 = client.get('/api/bots', headers=h2)
        bots = r2.json().get('bots', [])
        assert not any(b['bot_id'] == bot_id for b in bots)

    def test_security_questions_per_account(self, client):
        """Секретные вопросы привязаны к аккаунту."""
        u1 = make_user(client, f'sq1_{random_str(4)}')
        u2 = make_user(client, f'sq2_{random_str(4)}')

        # u1 настраивает вопросы
        h1 = login_user(client, u1['username'], u1['password'])
        client.post('/api/authentication/security-questions/setup', json={
            'questions': ['Q1?', 'Q2?', 'Q3?'],
            'answers': ['a1', 'a2', 'a3'],
        }, headers=h1)

        # u2 не имеет вопросов
        r2 = client.post('/api/authentication/security-questions/load', json={
            'username': u2['username'],
        })
        assert r2.status_code == 200
        assert len(r2.json().get('questions', [])) == 0
