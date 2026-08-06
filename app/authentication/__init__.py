"""
Пакет аутентификации — собирает все sub-модули на общий роутер.

Каждый модуль при импорте регистрирует свои эндпоинты на router из _helpers.
"""
# Общий роутер и хелперы
import app.authentication.key_login
import app.authentication.passkey

# Импортируем sub-модули, чтобы зарегистрировать их @router эндпоинты
import app.authentication.password
import app.authentication.profile
import app.authentication.qr_login
import app.authentication.security_questions
import app.authentication.session
import app.authentication.two_factor  # noqa: F401
from app.authentication._helpers import (  # noqa: F401
    _DUMMY_HASH,
    _auth_rate,
    _Challenge,
    _challenges,
    _challenges_lock,
    _check_auth_rate,
    _cleanup_expired_challenges,
    _set_auth_cookies,
    router,
)
