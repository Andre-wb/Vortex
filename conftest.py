"""
conftest.py — глобальные фикстуры и настройки pytest для VORTEX.
Положи в корень проекта рядом с pytest.ini: /Vortex/conftest.py
"""

import asyncio
import contextlib
import os
import secrets
import string
import sys
import tempfile

import httpx
import pytest

# Добавляем корень проекта в sys.path чтобы импорт app.* работал
ROOT = os.path.dirname(__file__)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


# Помечает DB_PATH, который conftest сгенерировал сам. Воркеры pytest-xdist
# наследуют окружение мастера, поэтому без метки они подхватили бы его путь
# и снова оказались бы в одной базе.
_DB_PATH_AUTO = 'VORTEX_TEST_DB_AUTO'


def _isolated_db_path() -> str:
    """Отдельный файл БД для каждого процесса pytest.

    SQLAlchemy разбирает 'file::memory:?cache=shared' как обычный путь и
    создаёт файл 'file::memory:' на диске. Все воркеры писали в него разом:
    телефоны и логины пересекались (409 «identifier unavailable»), параллельные
    записи упирались в блокировки SQLite, а create_all натыкался на
    «table users already exists». К тому же файл переживал прогон и накапливал
    старых пользователей.
    """
    worker = os.environ.get('PYTEST_XDIST_WORKER') or 'main'
    db_dir = os.path.join(tempfile.gettempdir(), 'vortex-pytest')
    os.makedirs(db_dir, exist_ok=True)
    path = os.path.join(db_dir, f'{worker}-{os.getpid()}.db')
    # WAL и SHM удаляем вместе с базой — иначе остатки прошлого прогона
    # подмешиваются к пустой БД.
    for suffix in ('', '-wal', '-shm'):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path + suffix)
    return path


# Устанавливаем переменные окружения ДО импорта приложения
os.environ.setdefault('TESTING',                 'true')
if not os.environ.get('DB_PATH') or os.environ.get(_DB_PATH_AUTO):
    os.environ['DB_PATH'] = _isolated_db_path()
    os.environ[_DB_PATH_AUTO] = '1'
os.environ.setdefault('JWT_SECRET',              'test_secret_key_minimum_32_chars_long_1234')
os.environ.setdefault('CSRF_SECRET',             'test_csrf_secret_minimum_32_chars_1234567')
os.environ.setdefault('NODE_INITIALIZED',        'true')
os.environ.setdefault('DEVICE_NAME',             'TestNode')
os.environ.setdefault('PORT',                    '8001')
os.environ.setdefault('HOST',                    '127.0.0.1')
os.environ.setdefault('UDP_PORT',                '4201')
os.environ.setdefault('MAX_FILE_MB',             '100')
os.environ.setdefault('WAF_RATE_LIMIT_REQUESTS', '9999')
os.environ.setdefault('REGISTRATION_MODE',       'open')
os.environ.setdefault('LOG_FORMAT',               'console')
os.environ.setdefault('LOG_LEVEL',                'WARNING')
os.environ.setdefault('NETWORK_MODE',             'local')   # knock/cover disabled in tests
os.environ.setdefault('OBFUSCATION_ENABLED',      'false')   # no obfuscation in tests
os.environ['STEALTH_MODE'] = 'false'                          # stealth off in tests
os.environ.setdefault('VORTEX_PQ_REQUIRED',       'false')   # allow tests without real PQ lib
os.environ.setdefault('VORTEX_PQ_SIMULATE',        '1')      # enable PQ simulation for tests
os.environ.setdefault('FEDERATION_PSK',            'test-federation-psk-32-chars-long!')
os.environ.setdefault('FEDERATION_GUEST_ENABLED',  '1')
# Иначе /api/ai/* обращается к локальной Qwen/Ollama: результат зависит от того,
# поднята ли модель на машине, а один запрос съедает десятки секунд.
os.environ.setdefault('AI_ENABLED',                'false')


# Тесты не должны ходить в реальный DNS: несуществующие хосты вроде
# node-xxx.example.com резолвятся до 30+ секунд и роняют pytest-timeout.
# Литеральные IP проверяем как раньше (SSRF-тесты), домены считаем публичными.
from app.federation import trusted_nodes as _trusted_nodes  # noqa: E402

# Импорт приложения (после установки env)
from app.main import app  # noqa: E402


def _test_resolve_safe_ips(hostname: str) -> list[str]:
    import ipaddress
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return ['203.0.113.10']
    if _trusted_nodes._ip_is_internal(addr):
        raise ValueError(f"Blocked internal address: {hostname}")
    return [str(addr)]

_trusted_nodes._resolve_safe_ips = _test_resolve_safe_ips


# Обёртка над httpx.AsyncClient + ASGITransport

class SyncASGIClient:
    """
    Синхронная обёртка над httpx.AsyncClient для тестирования ASGI-приложений.

    КРИТИЧНО: startup, все HTTP-запросы и shutdown должны выполняться
    в ОДНОМ event loop. SQLite :memory: создаёт таблицы в соединении,
    привязанном к loop-у startup. Если запросы идут в другом loop-е —
    таблицы не видны ("no such table") или соединение "detached".

    Исправление: loop создаётся ЗДЕСЬ и передаётся в startup/shutdown снаружи
    через фикстуру client, которая использует именно этот loop для всего.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop | None = None):
        self._transport = httpx.ASGITransport(app=app)
        self._base_url  = 'http://testserver'
        self._cookies   = httpx.Cookies()
        self._own_loop  = loop is None
        self._loop      = loop if loop is not None else asyncio.new_event_loop()

    def _send(self, method: str, url: str, **kwargs) -> httpx.Response:
        async def _do() -> httpx.Response:
            async with httpx.AsyncClient(
                    transport=self._transport,
                    base_url=self._base_url,
                    cookies=self._cookies,
                    follow_redirects=True,
            ) as client:
                resp = await getattr(client, method)(url, **kwargs)
                self._cookies.update(resp.cookies)
                return resp
        return self._loop.run_until_complete(_do())

    def get(self, url: str, **kwargs)    -> httpx.Response: return self._send('get',    url, **kwargs)
    def post(self, url: str, **kwargs)   -> httpx.Response: return self._send('post',   url, **kwargs)
    def put(self, url: str, **kwargs)    -> httpx.Response: return self._send('put',    url, **kwargs)
    def delete(self, url: str, **kwargs) -> httpx.Response: return self._send('delete', url, **kwargs)

    def close(self):
        if self._own_loop:
            with contextlib.suppress(Exception):
                self._loop.close()

    def make_anon_client(self) -> 'SyncASGIClient':
        """Return a fresh client sharing this loop but with no stored cookies."""
        return SyncASGIClient(loop=self._loop)

    def __enter__(self): return self
    def __exit__(self, *args): self.close()


# SESSION-SCOPE: один клиент на всю сессию тестов

@pytest.fixture(scope='session', autouse=True)
def db_schema():
    """Создаёт схему до первого теста.

    Часть тестов работает с SessionLocal напрямую, не запрашивая client,
    и раньше полагалась на таблицы, которые оставил в общем файле БД
    другой воркер.
    """
    from app.database import init_db
    init_db()


@pytest.fixture(scope='session')
def client(db_schema) -> SyncASGIClient:
    """
    Единственный SyncASGIClient на всю сессию.

    ВАЖНО: startup() запускается в ТОМ ЖЕ loop, что и все последующие
    HTTP-запросы. SQLite :memory: привязана к конкретному соединению/loop —
    если startup и запросы используют разные loop-ы, таблицы окажутся
    в разных in-memory базах и будут невидимы ("no such table: users").

    Старый баг был здесь:
        loop = asyncio.new_event_loop()
        loop.run_until_complete(app.router.startup())  # loop A — создаёт таблицы
        c = SyncASGIClient()  # loop B (новый!) — таблиц не видит
    """
    loop = asyncio.new_event_loop()
    c = SyncASGIClient(loop=loop)           # ← клиент использует loop
    loop.run_until_complete(app.router._startup())  # ← startup в том же loop

    yield c

    loop.run_until_complete(app.router._shutdown())
    # Cancel all pending tasks (e.g. WAF cleanup loop) so loop closes cleanly
    pending = asyncio.all_tasks(loop)
    for task in pending:
        task.cancel()
    if pending:
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
    c.close()
    loop.close()


# Вспомогательные утилиты (доступны из всех тестов через импорт conftest)

def random_str(n: int = 10) -> str:
    return ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n))


# Atomic counter for unique phone numbers — eliminates collisions
_phone_counter = 0
_phone_lock = __import__('threading').Lock()
_phone_prefix = secrets.token_hex(2)  # unique per test session


def random_digits(n: int = 7) -> str:
    """Уникальная строка из цифр. Без коллизий между запусками."""
    global _phone_counter
    with _phone_lock:
        _phone_counter += 1
        cnt = _phone_counter
    return str(cnt).zfill(n)[-n:]


def _unique_phone() -> str:
    """Generate a guaranteed-unique phone number using counter + session prefix."""
    global _phone_counter
    with _phone_lock:
        _phone_counter += 1
        cnt = _phone_counter
    # Use session-unique prefix to avoid collisions across test runs
    return f'+1{int(_phone_prefix, 16):04d}{cnt:07d}'


def make_user(client: SyncASGIClient, suffix: str | None = None) -> dict:
    """
    Регистрирует пользователя и возвращает его данные + заголовки.
    Телефон уникален через атомный счётчик — нет коллизий.
    """
    tag = suffix or random_str()
    payload = {
        'username':          f'user_{tag}',
        'password':          'StrongPass99x!@',
        'display_name':      f'Test {tag}',
        'phone':             _unique_phone(),
        'avatar_emoji':      '🤖',
        'x25519_public_key': secrets.token_hex(32),
    }
    r = client.post('/api/authentication/register', json=payload)
    assert r.status_code == 201, f'register failed ({r.status_code}): {r.text}'
    csrf = client.get('/api/authentication/csrf-token').json().get('csrf_token', '')
    return {
        'username':   payload['username'],
        'password':   payload['password'],
        'data':       r.json(),
        'headers':    {'X-CSRF-Token': csrf},
        'x25519_pub': payload['x25519_public_key'],
    }


def fed_proof_headers(node_id: str = 'test-peer') -> dict:
    """Заголовки peer proof для федеративных эндпоинтов (code-hash, handshake и т.п.)."""
    from app.federation.trusted_nodes import make_federation_proof
    return {
        'X-Federation-Node':  node_id,
        'X-Federation-Proof': make_federation_proof(node_id),
    }


def login_user(client: SyncASGIClient, username: str, password: str) -> dict:
    """Логинит пользователя, возвращает словарь с заголовками."""
    csrf = client.get('/api/authentication/csrf-token').json().get('csrf_token', '')
    r = client.post('/api/authentication/login', json={
        'phone_or_username': username,
        'password':          password,
    }, headers={'X-CSRF-Token': csrf})
    assert r.status_code == 200, f'login failed ({r.status_code}): {r.text}'
    return {'X-CSRF-Token': csrf}


# FUNCTION-SCOPE фикстуры

@pytest.fixture
def anon_client(client: SyncASGIClient) -> SyncASGIClient:
    """A fresh client with no stored auth cookies — for testing unauthenticated access."""
    return client.make_anon_client()


@pytest.fixture
def fresh_user(client: SyncASGIClient) -> dict:
    """Новый пользователь (только зарегистрирован, не залогинен)."""
    return make_user(client)


@pytest.fixture
def logged_user(client: SyncASGIClient, fresh_user: dict) -> dict:
    """Зарегистрированный и залогиненный пользователь."""
    headers = login_user(client, fresh_user['username'], fresh_user['password'])
    fresh_user['headers'] = headers
    return fresh_user


@pytest.fixture
def room(client: SyncASGIClient, logged_user: dict) -> dict:
    """Тестовая комната, созданная logged_user."""
    r = client.post('/api/rooms', json={
        'name':          f'room_{random_str()}',
        'is_public':     True,
        'encrypted_room_key': {
            'ephemeral_pub': secrets.token_hex(32),
            'ciphertext':    secrets.token_hex(60),
        },
    }, headers=logged_user['headers'])
    assert r.status_code in (200, 201), f'create room failed: {r.text}'
    return r.json()


@pytest.fixture
def two_users(client: SyncASGIClient):
    """Два залогиненных пользователя (для тестов взаимодействия)."""
    u1 = make_user(client, suffix=f'a{random_str(6)}')
    u2 = make_user(client, suffix=f'b{random_str(6)}')
    h1 = login_user(client, u1['username'], u1['password'])
    h2 = login_user(client, u2['username'], u2['password'])
    u1['headers'] = h1
    u2['headers'] = h2
    return u1, u2


# Хук: выводим метрики после тестов

def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Добавляем секцию метрик в финальный отчёт."""
    passed  = len(terminalreporter.stats.get('passed',  []))
    failed  = len(terminalreporter.stats.get('failed',  []))
    skipped = len(terminalreporter.stats.get('skipped', []))
    total   = passed + failed + skipped

    terminalreporter.write_sep('=', 'VORTEX Test Summary')
    terminalreporter.write_line(f'  Total:   {total}')
    terminalreporter.write_line(f'  Passed:  {passed}  ✅')
    if failed:
        terminalreporter.write_line(f'  Failed:  {failed}  ❌')
    if skipped:
        terminalreporter.write_line(f'  Skipped: {skipped}  ⏭')
