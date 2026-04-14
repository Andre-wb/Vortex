"""
Пакет аутентификации — собирает все sub-модули на общий роутер.

Каждый модуль при импорте регистрирует свои эндпоинты на router из _helpers.
"""
# Общий роутер и хелперы
from app.authentication._helpers import (  # noqa: F401
    _Challenge, _DUMMY_HASH, _auth_rate, _challenges, _challenges_lock,
    _check_auth_rate, _cleanup_expired_challenges, _set_auth_cookies, router,
)

# Импортируем sub-модули, чтобы зарегистрировать их @router эндпоинты
import app.authentication.password        # noqa: F401
import app.authentication.key_login       # noqa: F401
import app.authentication.qr_login        # noqa: F401
import app.authentication.two_factor      # noqa: F401
import app.authentication.session         # noqa: F401
import app.authentication.profile         # noqa: F401
import app.authentication.passkey         # noqa: F401
import app.authentication.security_questions  # noqa: F401
