"""
Пакет WAF — Web Application Firewall.

Ре-экспортирует все публичные символы для обратной совместимости:
  from app.security.waf import WAFMiddleware, init_waf_engine, waf_router
"""
from app.security.waf.signatures import WAFRule, WAFSignature  # noqa: F401
from app.security.waf.engine import WAFEngine  # noqa: F401
from app.security.waf.captcha import WAFCaptcha  # noqa: F401
from app.security.waf.middleware import WAFMiddleware  # noqa: F401
from app.security.waf.routes import (  # noqa: F401
    WAFManager, init_waf_engine, get_waf_engine, get_waf_manager,
    setup_waf, waf_router,
)
