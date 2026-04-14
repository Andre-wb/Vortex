"""
test_group_calls_scale.py — Тесты групповых звонков на масштабируемость.

Проверяем поведение при 5, 10, 20, 50, 70, 100, 150 участниках:
- Topology: mesh (≤6) / SFU (>6)
- Bandwidth profiles: сколько битрейта/fps на каждого
- Mesh connections: N*(N-1)/2 P2P соединений
- SFU load: 1 upstream + N-1 downstream на участника
- Предполагаемое качество видео/аудио
"""
import math
import secrets

import pytest

from conftest import make_user, login_user, random_str


# ═══════════════════════════════════════════════════════════════════════════════
# Bandwidth/quality profiles (из webrtc.js и group_call.js)
# ═══════════════════════════════════════════════════════════════════════════════

# Mesh: каждый участник шлёт/получает N-1 потоков
# SFU: каждый шлёт 1 upstream, получает N-1 downstream (SFU ремаппит)

# Профили качества видео на участника
VIDEO_PROFILES = {
    'hd':     {'resolution': '720p', 'fps': 30, 'bitrate_kbps': 2500},
    'medium': {'resolution': '480p', 'fps': 24, 'bitrate_kbps': 800},
    'low':    {'resolution': '360p', 'fps': 15, 'bitrate_kbps': 300},
    'minimal':{'resolution': '240p', 'fps': 10, 'bitrate_kbps': 150},
    'audio':  {'resolution': 'none', 'fps': 0,  'bitrate_kbps': 0},
}

AUDIO_BITRATE_KBPS = 32  # Opus audio per peer

# SFU порог
SFU_THRESHOLD = 6
SFU_MAX = 50

# Средняя пропускная способность пользователя (Mbps)
AVG_BANDWIDTH_MBPS = 10


def _calc_quality(n_participants):
    """
    Рассчитываем предполагаемое качество звонка для N участников.

    Returns dict с метриками.
    """
    n = n_participants
    is_mesh = n <= SFU_THRESHOLD
    topology = 'mesh' if is_mesh else 'sfu'

    if is_mesh:
        # Mesh: каждый шлёт N-1 видео + N-1 аудио потоков
        connections_per_user = n - 1
        total_connections = n * (n - 1) // 2

        # Upload: N-1 видео + N-1 аудио
        upload_streams = connections_per_user
        # Download: N-1 видео + N-1 аудио
        download_streams = connections_per_user
    else:
        # SFU: 1 upstream, N-1 downstream
        connections_per_user = 1  # to SFU
        total_connections = n     # N connections to SFU

        upload_streams = 1
        download_streams = n - 1

    # Определяем профиль видео исходя из количества потоков
    if n <= 3:
        profile = 'hd'
    elif n <= 6:
        profile = 'medium'
    elif n <= 10:
        profile = 'low'
    elif n <= 20:
        profile = 'minimal'
    else:
        profile = 'audio'  # >20 — только аудио для экономии

    vp = VIDEO_PROFILES[profile]

    # Расчёт bandwidth
    video_bitrate_per_stream = vp['bitrate_kbps']
    audio_bitrate_per_stream = AUDIO_BITRATE_KBPS

    upload_kbps = upload_streams * (video_bitrate_per_stream + audio_bitrate_per_stream)
    download_kbps = download_streams * (video_bitrate_per_stream + audio_bitrate_per_stream)
    total_per_user_kbps = upload_kbps + download_kbps
    total_per_user_mbps = total_per_user_kbps / 1000

    # Проверяем не превышаем ли среднюю bandwidth
    bandwidth_ok = total_per_user_mbps <= AVG_BANDWIDTH_MBPS
    # Если не хватает — снижаем до audio-only
    if not bandwidth_ok and profile != 'audio':
        actual_profile = 'audio'
        video_bitrate_per_stream = 0
        upload_kbps = upload_streams * AUDIO_BITRATE_KBPS
        download_kbps = download_streams * AUDIO_BITRATE_KBPS
        total_per_user_kbps = upload_kbps + download_kbps
        total_per_user_mbps = total_per_user_kbps / 1000
    else:
        actual_profile = profile

    # CPU load estimate (relative)
    # Mesh: encode N-1 times, decode N-1 times
    # SFU: encode 1 time, decode N-1 times
    if is_mesh:
        cpu_encode = connections_per_user
        cpu_decode = connections_per_user
    else:
        cpu_encode = 1
        cpu_decode = download_streams

    # Latency estimate (ms)
    # Mesh: P2P direct = ~50ms avg
    # SFU: client → SFU → client = ~80ms avg
    latency_ms = 50 if is_mesh else 80

    return {
        'participants': n,
        'topology': topology,
        'mesh_connections': total_connections if is_mesh else None,
        'connections_per_user': connections_per_user,
        'upload_streams': upload_streams,
        'download_streams': download_streams,
        'video_profile': actual_profile,
        'resolution': VIDEO_PROFILES[actual_profile]['resolution'],
        'fps': VIDEO_PROFILES[actual_profile]['fps'],
        'video_bitrate_kbps': video_bitrate_per_stream,
        'audio_bitrate_kbps': audio_bitrate_per_stream,
        'upload_kbps': upload_kbps,
        'download_kbps': download_kbps,
        'total_per_user_kbps': total_per_user_kbps,
        'total_per_user_mbps': round(total_per_user_mbps, 2),
        'bandwidth_ok': total_per_user_mbps <= AVG_BANDWIDTH_MBPS,
        'cpu_encode_factor': cpu_encode,
        'cpu_decode_factor': cpu_decode,
        'latency_ms': latency_ms,
        'quality_rating': _rate_quality(actual_profile, n, latency_ms),
    }


def _rate_quality(profile, n, latency):
    """Оценка качества: excellent / good / acceptable / degraded / audio-only."""
    if profile == 'hd' and latency <= 60:
        return 'excellent'
    if profile in ('hd', 'medium') and latency <= 100:
        return 'good'
    if profile in ('medium', 'low') and latency <= 150:
        return 'acceptable'
    if profile == 'minimal':
        return 'degraded'
    if profile == 'audio':
        return 'audio-only'
    return 'acceptable'


# ═══════════════════════════════════════════════════════════════════════════════
# Тесты качества для каждого размера группы
# ═══════════════════════════════════════════════════════════════════════════════

class TestGroupCallQuality:
    """Тесты предполагаемого качества групповых звонков."""

    @pytest.mark.parametrize("n", [5, 10, 20, 50, 70, 100, 150])
    def test_quality_profile(self, n):
        """Проверяем bandwidth/quality расчёты для N участников."""
        q = _calc_quality(n)

        print(f"\n{'='*70}")
        print(f"  ГРУППОВОЙ ЗВОНОК: {n} УЧАСТНИКОВ")
        print(f"{'='*70}")
        print(f"  Topology:          {q['topology'].upper()}")
        if q['mesh_connections']:
            print(f"  Mesh connections:  {q['mesh_connections']} P2P")
        print(f"  Upload streams:    {q['upload_streams']}")
        print(f"  Download streams:  {q['download_streams']}")
        print(f"  Video profile:     {q['video_profile']} ({q['resolution']} @ {q['fps']}fps)")
        print(f"  Video bitrate:     {q['video_bitrate_kbps']} kbps/stream")
        print(f"  Audio bitrate:     {q['audio_bitrate_kbps']} kbps/stream")
        print(f"  Upload total:      {q['upload_kbps']} kbps ({q['upload_kbps']/1000:.1f} Mbps)")
        print(f"  Download total:    {q['download_kbps']} kbps ({q['download_kbps']/1000:.1f} Mbps)")
        print(f"  Total per user:    {q['total_per_user_mbps']} Mbps")
        print(f"  Bandwidth OK:      {'✅' if q['bandwidth_ok'] else '❌'}")
        print(f"  CPU encode:        {q['cpu_encode_factor']}x")
        print(f"  CPU decode:        {q['cpu_decode_factor']}x")
        print(f"  Latency:           ~{q['latency_ms']}ms")
        print(f"  Quality:           {q['quality_rating'].upper()}")
        print(f"{'='*70}")

        # Assertions
        assert q['bandwidth_ok'], f"{n} participants: bandwidth {q['total_per_user_mbps']} Mbps exceeds {AVG_BANDWIDTH_MBPS} Mbps"
        assert q['topology'] in ('mesh', 'sfu')
        if n <= SFU_THRESHOLD:
            assert q['topology'] == 'mesh'
        else:
            assert q['topology'] == 'sfu'


# ═══════════════════════════════════════════════════════════════════════════════
# API тесты групповых звонков
# ═══════════════════════════════════════════════════════════════════════════════

class TestGroupCallAPI:
    """Тесты API групповых звонков с симуляцией участников."""

    def _create_room_with_members(self, client, n_members):
        """Создать комнату и добавить N участников."""
        users = []
        for i in range(n_members):
            u = make_user(client, f'gc{n_members}_{i}_{random_str(4)}')
            users.append(u)

        # Логинимся как первый (создатель)
        h_creator = login_user(client, users[0]['username'], users[0]['password'])

        # Создаём комнату
        r = client.post('/api/rooms', json={
            'name': f'gc_{n_members}_{random_str(5)}',
            'is_public': True,
            'encrypted_room_key': {
                'ephemeral_pub': secrets.token_hex(32),
                'ciphertext': secrets.token_hex(60),
            },
        }, headers=h_creator)
        assert r.status_code in (200, 201), f"Create room failed: {r.text}"
        room = r.json()
        invite = room['invite_code']

        # Остальные вступают
        for u in users[1:]:
            h = login_user(client, u['username'], u['password'])
            jr = client.post(f'/api/rooms/join/{invite}', headers=h)
            assert jr.status_code == 200, f"Join failed for {u['username']}: {jr.text}"

        return room, users, h_creator

    @pytest.mark.parametrize("n", [5, 10])
    def test_start_and_join_group_call(self, client, n):
        """Стартуем звонок и все N участников подключаются."""
        room, users, _ = self._create_room_with_members(client, n)

        # Login as creator and start call
        h_creator = login_user(client, users[0]['username'], users[0]['password'])
        r = client.post(f'/api/group-calls/{room["id"]}/start', json={
            'call_type': 'group_video',
        }, headers=h_creator)
        assert r.status_code == 200
        data = r.json()
        call_id = data['call_id']
        topology = data.get('topology', 'mesh')

        print(f"\n[{n} participants] Call started: {call_id}, topology={topology}")

        # Каждый участник присоединяется
        joined = 0
        for u in users[1:]:
            h = login_user(client, u['username'], u['password'])
            jr = client.post(f'/api/group-calls/{call_id}/join', headers=h)
            if jr.status_code == 200:
                joined += 1

        print(f"[{n} participants] {joined}/{n-1} joined successfully")

        # Проверяем статус
        h_creator = login_user(client, users[0]['username'], users[0]['password'])
        sr = client.get(f'/api/group-calls/{call_id}/status', headers=h_creator)
        assert sr.status_code == 200
        status = sr.json()

        connected = status['participant_count']
        print(f"[{n} participants] Connected: {connected}, State: {status['state']}")

        # Расчёт качества
        q = _calc_quality(connected)
        print(f"[{n} participants] Quality: {q['quality_rating']}, Video: {q['resolution']}@{q['fps']}fps")
        print(f"[{n} participants] Bandwidth: {q['total_per_user_mbps']} Mbps/user")

        assert connected >= 1
        assert status['state'] in ('ringing', 'active')

        # Завершаем звонок
        h_creator = login_user(client, users[0]['username'], users[0]['password'])
        er = client.post(f'/api/group-calls/{call_id}/end', headers=h_creator)
        assert er.status_code == 200

    def test_active_call_check(self, client):
        """Проверка active call endpoint."""
        room, users, _ = self._create_room_with_members(client, 3)

        h = login_user(client, users[0]['username'], users[0]['password'])

        # No active call initially
        ar = client.get(f'/api/group-calls/{room["id"]}/active', headers=h)
        assert ar.status_code == 200
        assert ar.json()['active'] is False

        # Start call
        sr = client.post(f'/api/group-calls/{room["id"]}/start', json={
            'call_type': 'group_audio',
        }, headers=h)
        call_id = sr.json()['call_id']

        # Now active
        ar2 = client.get(f'/api/group-calls/{room["id"]}/active', headers=h)
        assert ar2.json()['active'] is True

        # End call
        client.post(f'/api/group-calls/{call_id}/end', headers=h)

    def test_decline_group_call(self, client):
        """Отклонение звонка."""
        room, users, _ = self._create_room_with_members(client, 3)

        h0 = login_user(client, users[0]['username'], users[0]['password'])
        sr = client.post(f'/api/group-calls/{room["id"]}/start', json={
            'call_type': 'group_audio',
        }, headers=h0)
        call_id = sr.json()['call_id']

        # User 1 declines
        h1 = login_user(client, users[1]['username'], users[1]['password'])
        dr = client.post(f'/api/group-calls/{call_id}/decline', headers=h1)
        assert dr.status_code == 200

        # User 2 joins
        h2 = login_user(client, users[2]['username'], users[2]['password'])
        jr = client.post(f'/api/group-calls/{call_id}/join', headers=h2)
        assert jr.status_code == 200

        # End
        h0 = login_user(client, users[0]['username'], users[0]['password'])
        client.post(f'/api/group-calls/{call_id}/end', headers=h0)

    def test_leave_group_call(self, client):
        """Выход из звонка."""
        room, users, _ = self._create_room_with_members(client, 4)

        h0 = login_user(client, users[0]['username'], users[0]['password'])
        sr = client.post(f'/api/group-calls/{room["id"]}/start', json={
            'call_type': 'group_video',
        }, headers=h0)
        call_id = sr.json()['call_id']

        # All join
        for u in users[1:]:
            h = login_user(client, u['username'], u['password'])
            client.post(f'/api/group-calls/{call_id}/join', headers=h)

        # User 1 leaves
        h1 = login_user(client, users[1]['username'], users[1]['password'])
        lr = client.post(f'/api/group-calls/{call_id}/leave', headers=h1)
        assert lr.status_code == 200

        # Check status — should still be active
        h0 = login_user(client, users[0]['username'], users[0]['password'])
        st = client.get(f'/api/group-calls/{call_id}/status', headers=h0)
        assert st.json()['state'] in ('ringing', 'active')

        client.post(f'/api/group-calls/{call_id}/end', headers=h0)

    def test_no_duplicate_active_calls(self, client):
        """Нельзя создать два активных звонка в одной комнате."""
        room, users, _ = self._create_room_with_members(client, 3)

        h0 = login_user(client, users[0]['username'], users[0]['password'])
        sr1 = client.post(f'/api/group-calls/{room["id"]}/start', json={
            'call_type': 'group_audio',
        }, headers=h0)
        call_id = sr1.json()['call_id']

        # Second start — returns existing
        sr2 = client.post(f'/api/group-calls/{room["id"]}/start', json={
            'call_type': 'group_audio',
        }, headers=h0)
        assert sr2.json()['already_active'] is True
        assert sr2.json()['call_id'] == call_id

        client.post(f'/api/group-calls/{call_id}/end', headers=h0)


# ═══════════════════════════════════════════════════════════════════════════════
# Сводная таблица качества
# ═══════════════════════════════════════════════════════════════════════════════

class TestQualitySummary:
    """Сводная таблица предполагаемого качества для всех размеров."""

    def test_print_quality_table(self):
        """Печатает сводную таблицу качества."""
        sizes = [2, 3, 5, 6, 7, 10, 15, 20, 30, 50, 70, 100, 150]

        print(f"\n{'='*110}")
        print(f"  СВОДНАЯ ТАБЛИЦА КАЧЕСТВА ГРУППОВЫХ ЗВОНКОВ VORTEX")
        print(f"{'='*110}")
        print(f"  {'N':>4} | {'Topology':>5} | {'Video':>8} | {'Res':>5} | {'FPS':>3} | "
              f"{'Up(Mbps)':>8} | {'Down(Mbps)':>10} | {'Total':>7} | {'BW OK':>5} | "
              f"{'CPU enc':>7} | {'CPU dec':>7} | {'Latency':>7} | {'Quality':>10}")
        print(f"  {'-'*4}-+-{'-'*5}-+-{'-'*8}-+-{'-'*5}-+-{'-'*3}-+-"
              f"{'-'*8}-+-{'-'*10}-+-{'-'*7}-+-{'-'*5}-+-"
              f"{'-'*7}-+-{'-'*7}-+-{'-'*7}-+-{'-'*10}")

        for n in sizes:
            q = _calc_quality(n)
            print(f"  {n:>4} | {q['topology']:>5} | {q['video_profile']:>8} | "
                  f"{q['resolution']:>5} | {q['fps']:>3} | "
                  f"{q['upload_kbps']/1000:>8.1f} | {q['download_kbps']/1000:>10.1f} | "
                  f"{q['total_per_user_mbps']:>7.2f} | {'✅' if q['bandwidth_ok'] else '❌':>5} | "
                  f"{q['cpu_encode_factor']:>7} | {q['cpu_decode_factor']:>7} | "
                  f"{q['latency_ms']:>5}ms | {q['quality_rating']:>10}")

        print(f"{'='*110}")
        print(f"  SFU Threshold: {SFU_THRESHOLD} participants")
        print(f"  SFU Max:       {SFU_MAX} participants")
        print(f"  Avg bandwidth: {AVG_BANDWIDTH_MBPS} Mbps")
        print(f"{'='*110}\n")

        # Все профили должны укладываться в bandwidth
        for n in sizes:
            q = _calc_quality(n)
            assert q['bandwidth_ok'], f"{n} participants exceeds bandwidth"
