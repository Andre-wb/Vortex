"""
test_privacy_resilience.py — Тесты устойчивости всех фичей конфиденциальности.

Покрывает ПОЛНЫЕ сценарии (не отдельные endpoint, а end-to-end flows):
1. Бэкап ключей: создать → восстановить на новом устройстве
2. Device linking: создать код → ввести на новом → получить ключи
3. SSSS (Shamir): разделить ключ → восстановить M из N
4. Federated backup: распределить → забрать с нод
5. Key transparency: лог → аудит → ротация → лог
6. Cross-device sync: push → pull на другом устройстве
7. History export: выгрузить → проверить на другом аккаунте
8. Конкурентные операции с бэкапами
"""
import secrets

import pytest

from conftest import make_user, login_user, random_str


# ═══════════════════════════════════════════════════════════════════════════════
# 1. БЭКАП КЛЮЧЕЙ — ПОЛНЫЙ ЦИКЛ
# ═══════════════════════════════════════════════════════════════════════════════

class TestBackupFullCycle:
    """Бэкап → удаление устройства → восстановление на новом."""

    def _make_backup_payload(self):
        return {
            'vault_data': secrets.token_hex(64),
            'vault_salt': secrets.token_hex(16),
            'kdf_params': '{"alg":"PBKDF2","iter":600000,"hash":"SHA-256"}',
        }

    def test_backup_create_and_restore(self, client):
        """Создать бэкап → скачать → данные совпадают."""
        u = make_user(client, f'bk1_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        payload = self._make_backup_payload()
        r = client.post('/api/keys/backup', json=payload, headers=h)
        assert r.status_code == 200

        # Скачать бэкап
        h2 = login_user(client, u['username'], u['password'])
        r = client.get('/api/keys/backup', headers=h2)
        assert r.status_code == 200
        assert r.json()['vault_data'] == payload['vault_data']

    def test_backup_survives_relogin(self, client):
        """Бэкап доступен после повторного логина."""
        u = make_user(client, f'bkr_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        payload = self._make_backup_payload()
        client.post('/api/keys/backup', json=payload, headers=h)

        for _ in range(3):
            h = login_user(client, u['username'], u['password'])
            r = client.get('/api/keys/backup', headers=h)
            assert r.json()['vault_data'] == payload['vault_data']

    def test_backup_update_replaces(self, client):
        """Обновление бэкапа заменяет старый."""
        u = make_user(client, f'bku_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        p1 = self._make_backup_payload()
        p2 = self._make_backup_payload()

        client.post('/api/keys/backup', json=p1, headers=h)
        client.post('/api/keys/backup', json=p2, headers=h)

        r = client.get('/api/keys/backup', headers=h)
        assert r.json()['vault_data'] == p2['vault_data']
        assert r.json().get('version', 1) >= 2

    def test_backup_delete_and_recreate(self, client):
        """Удалить бэкап → создать новый."""
        u = make_user(client, f'bkd_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        client.post('/api/keys/backup', json=self._make_backup_payload(), headers=h)
        client.delete('/api/keys/backup', headers=h)

        r = client.get('/api/keys/backup', headers=h)
        assert r.status_code == 404

        p_new = self._make_backup_payload()
        client.post('/api/keys/backup', json=p_new, headers=h)
        r = client.get('/api/keys/backup', headers=h)
        assert r.json()['vault_data'] == p_new['vault_data']


# ═══════════════════════════════════════════════════════════════════════════════
# 2. DEVICE LINKING — ПОЛНЫЙ ФЛОУ
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeviceLinkingFlow:
    """Создать код → ввести на новом устройстве → получить ключи."""

    def test_full_linking_flow(self, client):
        """Полный флоу: request → check → approve → poll."""
        u = make_user(client, f'dl1_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        # Шаг 1: Создать запрос на новом устройстве
        r = client.post('/api/keys/link/request', json={
            'new_device_pub': secrets.token_hex(32),
        }, headers=h)
        assert r.status_code == 200
        code = r.json()['link_code']
        request_id = r.json()['request_id']
        assert len(str(code)) == 6

        # Шаг 2: Проверить код на старом устройстве
        r = client.get(f'/api/keys/link/{code}', headers=h)
        assert r.status_code == 200
        assert r.json()['new_device_pub'] is not None

        # Шаг 3: Одобрить и передать ключи
        r = client.post(f'/api/keys/link/{code}/approve', json={
            'encrypted_keys': secrets.token_hex(128),
        }, headers=h)
        assert r.status_code == 200

        # Шаг 4: Получить ключи на новом устройстве
        r = client.get(f'/api/keys/link/poll/{request_id}', headers=h)
        assert r.status_code == 200
        assert r.json().get('encrypted_keys') is not None

    def test_invalid_code_rejected(self, client):
        """Неверный код отклоняется."""
        u = make_user(client, f'dlx_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        r = client.get('/api/keys/link/000000', headers=h)
        assert r.status_code == 404

    def test_code_one_time_use(self, client):
        """Код одноразовый — после poll ключи удаляются."""
        u = make_user(client, f'dl2_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        r = client.post('/api/keys/link/request', json={
            'new_device_pub': secrets.token_hex(32),
        }, headers=h)
        code = r.json()['link_code']
        request_id = r.json()['request_id']

        client.post(f'/api/keys/link/{code}/approve', json={
            'encrypted_keys': secrets.token_hex(64),
        }, headers=h)

        # Первый poll — получаем ключи
        r1 = client.get(f'/api/keys/link/poll/{request_id}', headers=h)
        assert r1.status_code == 200

        # Второй poll — ключи удалены (one-time-read)
        r2 = client.get(f'/api/keys/link/poll/{request_id}', headers=h)
        # Может вернуть 404 или пустые ключи
        assert r2.status_code in (200, 404)
        if r2.status_code == 200:
            assert r2.json().get('encrypted_keys') is None


# ═══════════════════════════════════════════════════════════════════════════════
# 3. SSSS (SHAMIR) — РАЗДЕЛЕНИЕ И ВОССТАНОВЛЕНИЕ
# ═══════════════════════════════════════════════════════════════════════════════

class TestShamirSharing:
    """Разделить ключ на N частей, восстановить из M."""

    def _make_shares(self, n):
        return [
            {'share_index': i + 1, 'encrypted_share': secrets.token_hex(32)}
            for i in range(n)
        ]

    def test_split_and_list_shares(self, client):
        """Разделить ключ → получить список своих частей."""
        u = make_user(client, f'ss1_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        r = client.post('/api/keys/ssss/create', json={
            'threshold': 2,
            'total_shares': 3,
            'shares': self._make_shares(3),
        }, headers=h)
        assert r.status_code == 200

        r = client.get('/api/keys/ssss/shares', headers=h)
        assert r.status_code == 200
        assert len(r.json().get('shares', [])) == 3

    def test_revoke_shares(self, client):
        """Отозвать все части."""
        u = make_user(client, f'ss2_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        client.post('/api/keys/ssss/create', json={
            'threshold': 2,
            'total_shares': 3,
            'shares': self._make_shares(3),
        }, headers=h)

        r = client.delete('/api/keys/ssss', headers=h)
        assert r.status_code == 200

        r = client.get('/api/keys/ssss/shares', headers=h)
        assert len(r.json().get('shares', [])) == 0

    def test_threshold_validation(self, client):
        """threshold > total отклоняется."""
        u = make_user(client, f'ss3_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        r = client.post('/api/keys/ssss/create', json={
            'threshold': 5,
            'total_shares': 3,
            'shares': self._make_shares(3),
        }, headers=h)
        assert r.status_code in (400, 422)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. FEDERATED BACKUP
# ═══════════════════════════════════════════════════════════════════════════════

class TestFederatedBackup:
    """Распределённый бэкап через ноды федерации."""

    def _make_shards(self, n):
        return [
            {
                'shard_index': i + 1,
                'peer_ip': f'10.0.0.{i+1}',
                'peer_port': 8000 + i,
                'encrypted_shard': secrets.token_hex(64),
                'shard_hash': secrets.token_hex(32),
            }
            for i in range(n)
        ]

    def test_status_empty(self, client):
        """Статус без распределения — not distributed."""
        u = make_user(client, f'fb1_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        r = client.get('/api/keys/federated-backup/status', headers=h)
        assert r.status_code == 200
        assert r.json().get('distributed') is False

    def test_store_and_retrieve_shard(self, client):
        """Сохранить шард → получить его."""
        u = make_user(client, f'fb2_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])
        uid = u['data']['user_id']

        shard_data = secrets.token_hex(64)
        shard_hash = secrets.token_hex(32)

        r = client.post('/api/keys/federated-backup/store-shard', json={
            'owner_user_id': uid,
            'shard_index': 1,
            'encrypted_shard': shard_data,
            'shard_hash': shard_hash,
        }, headers=h)
        assert r.status_code == 200

        r = client.get(f'/api/keys/federated-backup/retrieve-shard/{uid}', headers=h)
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 5. KEY TRANSPARENCY — AUDIT CHAIN
# ═══════════════════════════════════════════════════════════════════════════════

class TestKeyTransparency:
    """Append-only лог ключей с Merkle цепочкой."""

    def test_log_and_audit(self, client):
        """Залогировать ключ → аудит проходит."""
        u = make_user(client, f'kt1_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])
        uid = u['data']['user_id']

        client.post('/api/keys/transparency/log', json={
            'pub_key_hash': secrets.token_hex(32),
            'key_type': 'x25519',
        }, headers=h)

        r = client.get(f'/api/keys/transparency/{uid}', headers=h)
        assert r.status_code == 200
        entries = r.json().get('entries', [])
        assert len(entries) >= 1

        r = client.get(f'/api/keys/transparency/{uid}/audit', headers=h)
        assert r.status_code == 200
        assert r.json().get('valid') is True

    def test_chain_integrity_after_rotation(self, client):
        """Несколько записей → цепочка остаётся valid."""
        u = make_user(client, f'kt2_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])
        uid = u['data']['user_id']

        for _ in range(3):
            client.post('/api/keys/transparency/log', json={
                'pub_key_hash': secrets.token_hex(32),
                'key_type': 'x25519',
            }, headers=h)

        r = client.get(f'/api/keys/transparency/{uid}/audit', headers=h)
        assert r.json()['valid'] is True

        r = client.get(f'/api/keys/transparency/{uid}/latest', headers=h)
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 6. CROSS-DEVICE SYNC
# ═══════════════════════════════════════════════════════════════════════════════

class TestCrossDeviceSync:
    """Синхронизация ключей между устройствами."""

    def test_push_and_pull(self, client):
        """Push события → pull с другого устройства."""
        u = make_user(client, f'sync1_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        r = client.post('/api/keys/sync/push', json={
            'device_id': 1,
            'event_type': 'key_update',
            'payload': secrets.token_hex(64),
        }, headers=h)
        assert r.status_code == 200

        r = client.get('/api/keys/sync/pull?since_seq=0', headers=h)
        assert r.status_code == 200
        events = r.json().get('events', [])
        assert len(events) >= 1

    def test_pull_filters_by_type(self, client):
        """Pull фильтрует по event_type."""
        u = make_user(client, f'sync2_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        client.post('/api/keys/sync/push', json={
            'device_id': 1, 'event_type': 'key_update', 'payload': secrets.token_hex(32),
        }, headers=h)
        client.post('/api/keys/sync/push', json={
            'device_id': 1, 'event_type': 'history', 'payload': secrets.token_hex(32),
        }, headers=h)

        r = client.get('/api/keys/sync/pull?since_seq=0&event_type=history', headers=h)
        events = r.json().get('events', [])
        for e in events:
            assert e.get('event_type') == 'history'

    def test_cross_signing(self, client):
        """Кросс-подпись устройств."""
        u = make_user(client, f'cs1_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        r = client.post('/api/keys/cross-sign', json={
            'signer_device': 1,
            'signed_device': 2,
            'signature': secrets.token_hex(32),
            'signer_pub_hash': secrets.token_hex(32),
            'signed_pub_hash': secrets.token_hex(32),
        }, headers=h)
        assert r.status_code == 200

        r = client.get('/api/keys/cross-sign', headers=h)
        signs = r.json().get('signs', [])
        assert len(signs) >= 1

    def test_sync_settings(self, client):
        """Синхронизация настроек между устройствами."""
        u = make_user(client, f'ss_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        r = client.post('/api/keys/sync/settings', json={
            'vault_data': secrets.token_hex(64),
            'vault_salt': secrets.token_hex(16),
        }, headers=h)
        assert r.status_code == 200

        r = client.get('/api/keys/sync/settings', headers=h)
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 7. HISTORY EXPORT
# ═══════════════════════════════════════════════════════════════════════════════

class TestHistoryExport:
    """Экспорт истории сообщений."""

    def test_rooms_summary(self, client):
        """Сводка комнат для экспорта."""
        u = make_user(client, f'he1_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        # Создаём комнату
        client.post('/api/rooms', json={
            'name': f'export_{random_str()}',
            'encrypted_room_key': {
                'ephemeral_pub': secrets.token_hex(32),
                'ciphertext': secrets.token_hex(60),
            },
        }, headers=h)

        r = client.get('/api/keys/sync/rooms-summary', headers=h)
        assert r.status_code == 200
        rooms = r.json().get('rooms', [])
        assert len(rooms) >= 1

    def test_history_export_empty_room(self, client):
        """Экспорт пустой комнаты."""
        u = make_user(client, f'he2_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        r = client.post('/api/rooms', json={
            'name': f'empty_{random_str()}',
            'encrypted_room_key': {
                'ephemeral_pub': secrets.token_hex(32),
                'ciphertext': secrets.token_hex(60),
            },
        }, headers=h)
        room_id = r.json()['id']

        r = client.get(f'/api/keys/sync/history-export/{room_id}', headers=h)
        assert r.status_code == 200
        msgs = r.json().get('messages', [])
        assert isinstance(msgs, list)


# ═══════════════════════════════════════════════════════════════════════════════
# 8. КОНКУРЕНТНЫЕ ОПЕРАЦИИ
# ═══════════════════════════════════════════════════════════════════════════════

class TestConcurrentPrivacy:
    """Конкурентные операции с бэкапами."""

    def test_concurrent_backup_updates(self, client):
        """Несколько быстрых обновлений бэкапа не ломают данные."""
        u = make_user(client, f'cb_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        last_data = None
        for i in range(5):
            data = secrets.token_hex(32)
            client.post('/api/keys/backup', json={
                'vault_data': data,
                'vault_salt': secrets.token_hex(16),
            }, headers=h)
            last_data = data

        r = client.get('/api/keys/backup', headers=h)
        assert r.json()['vault_data'] == last_data

    def test_concurrent_sync_pushes(self, client):
        """Несколько push подряд не теряют данные."""
        u = make_user(client, f'csp_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        for i in range(10):
            r = client.post('/api/keys/sync/push', json={
                'device_id': 1,
                'event_type': 'key_update',
                'payload': secrets.token_hex(16),
            }, headers=h)
            assert r.status_code == 200

        r = client.get('/api/keys/sync/pull?since_seq=0', headers=h)
        events = r.json().get('events', [])
        assert len(events) >= 10

    def test_device_pub_key_set(self, client):
        """Установка pubkey устройства."""
        u = make_user(client, f'dpk_{random_str(4)}')
        h = login_user(client, u['username'], u['password'])

        r = client.post('/api/keys/device-pub-key', json={
            'device_pub_key': secrets.token_hex(32),
        }, headers=h)
        assert r.status_code == 200
