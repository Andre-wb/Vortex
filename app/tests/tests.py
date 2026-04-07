"""
app/tests/tests.py — тонкий хаб, ре-экспортирует все тестовые классы.

Раздроблен на отдельные модули:
  test_crypto_core.py      — AES-GCM, SHA-256, X25519
  test_auth_core.py        — регистрация, логин, сессии
  test_rooms_core.py       — комнаты
  test_files_core.py       — файлы
  test_websocket_core.py   — WebSocket
  test_e2e_encryption.py   — E2E шифрование
  test_peers_core.py       — пиры
  test_reliability.py      — надёжность
  test_security_core.py    — безопасность
  test_metrics.py          — метрики
  test_integration.py      — интеграционные сценарии
"""

from app.tests.test_crypto_core import TestAESGCM, TestSHA256Integrity, TestX25519PubkeyFromJWK  # noqa: F401
from app.tests.test_auth_core import TestRegistration, TestLogin, TestSession  # noqa: F401
from app.tests.test_rooms_core import TestRooms  # noqa: F401
from app.tests.test_files_core import TestFiles  # noqa: F401
from app.tests.test_websocket_core import TestWebSocket  # noqa: F401
from app.tests.test_e2e_encryption import TestE2EEncryption  # noqa: F401
from app.tests.test_peers_core import TestPeers  # noqa: F401
from app.tests.test_reliability import TestReliability  # noqa: F401
from app.tests.test_security_core import TestSecurity  # noqa: F401
from app.tests.test_metrics import TestMetrics  # noqa: F401
from app.tests.test_integration import TestIntegrationScenarios  # noqa: F401
