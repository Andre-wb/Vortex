"""
Пакет WAF — Web Application Firewall.

Движок реализован на Rust (крейт `vortex_waf`), здесь только ASGI-middleware и
HTTP-эндпоинты управления.

  from app.security.waf import WAFMiddleware, init_waf_engine, waf_router
"""
from app.security.waf.backend import (  # noqa: F401
    RULE_COUNT, VERSION, WAFEngine, resolve_client_ip,
)
from app.security.waf.metrics import (  # noqa: F401
    register_waf_metrics, unregister_waf_metrics,
)
from app.security.waf.middleware import WAFMiddleware  # noqa: F401
from app.security.waf.routes import (  # noqa: F401
    WAFManager, init_waf_engine, get_waf_engine, get_waf_manager,
    setup_waf, waf_router,
)

__all__ = [
    "RULE_COUNT",
    "VERSION",
    "WAFEngine",
    "WAFManager",
    "WAFMiddleware",
    "get_waf_engine",
    "get_waf_manager",
    "init_waf_engine",
    "register_waf_metrics",
    "resolve_client_ip",
    "setup_waf",
    "unregister_waf_metrics",
    "waf_router",
]
