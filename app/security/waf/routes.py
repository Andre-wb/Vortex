"""WAF Management API — эндпоинты для управления WAF."""
from __future__ import annotations

import ipaddress
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from app.security.waf.backend import WAFEngine

logger = logging.getLogger(__name__)


class WAFManager:
    """Операции администрирования поверх движка."""

    def __init__(self, waf_engine: WAFEngine):
        self.waf = waf_engine

    def block_ip(self, ip: str, reason: str, duration: int = 3600) -> dict:
        success = self.waf.block_ip(ip, reason, duration)
        return {'success': success, 'ip': ip, 'reason': reason, 'duration': duration}

    def unblock_ip(self, ip: str) -> dict:
        if self.waf.unblock_ip(ip):
            return {'success': True, 'ip': ip, 'message': 'IP unblocked'}
        return {'success': False, 'ip': ip, 'message': 'IP not found'}

    def get_blocked_ips(self) -> list[dict]:
        return self.waf.blocked_ips()

    def add_whitelist_ip(self, ip: str) -> dict:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {'success': False, 'ip': ip, 'message': 'Invalid IP format'}
        self.waf.add_whitelist_ip(ip)
        return {'success': True, 'ip': ip, 'message': 'IP added to whitelist'}

    def remove_whitelist_ip(self, ip: str) -> dict:
        if self.waf.remove_whitelist_ip(ip):
            return {'success': True, 'ip': ip, 'message': 'IP removed from whitelist'}
        return {'success': False, 'ip': ip, 'message': 'IP not found in whitelist'}

    def get_whitelist(self) -> list[str]:
        return self.waf.whitelist()



_waf_engine: Optional[WAFEngine] = None


def init_waf_engine(config: Optional[dict] = None) -> WAFEngine:
    global _waf_engine
    _waf_engine = WAFEngine(config)
    return _waf_engine


def get_waf_engine() -> WAFEngine:
    if _waf_engine is None:
        raise RuntimeError("WAFEngine not initialized. Call init_waf_engine() first.")
    return _waf_engine


def get_waf_manager() -> WAFManager:
    return WAFManager(get_waf_engine())



waf_router = APIRouter(prefix="/waf", tags=["WAF"])


@waf_router.get("/stats")
async def waf_stats(waf: WAFEngine = Depends(get_waf_engine)):
    return JSONResponse(waf.get_stats())


@waf_router.get("/rules")
async def waf_rules(waf: WAFEngine = Depends(get_waf_engine)):
    rules = waf.rules()
    return JSONResponse({'rules': rules, 'total': len(rules)})


@waf_router.get("/blocked-ips")
async def blocked_ips(manager: WAFManager = Depends(get_waf_manager)):
    return JSONResponse({'blocked_ips': manager.get_blocked_ips()})


@waf_router.post("/block-ip")
async def block_ip(ip: str, reason: str = "Manual block", duration: int = 3600,
                   manager: WAFManager = Depends(get_waf_manager)):
    return JSONResponse(manager.block_ip(ip, reason, duration))


@waf_router.post("/unblock-ip")
async def unblock_ip(ip: str, manager: WAFManager = Depends(get_waf_manager)):
    return JSONResponse(manager.unblock_ip(ip))


@waf_router.get("/whitelist")
async def whitelist(manager: WAFManager = Depends(get_waf_manager)):
    return JSONResponse({'whitelist': manager.get_whitelist()})


@waf_router.post("/whitelist/add")
async def whitelist_add(ip: str, manager: WAFManager = Depends(get_waf_manager)):
    return JSONResponse(manager.add_whitelist_ip(ip))


@waf_router.delete("/whitelist/remove")
async def whitelist_remove(ip: str, manager: WAFManager = Depends(get_waf_manager)):
    return JSONResponse(manager.remove_whitelist_ip(ip))


@waf_router.post("/captcha/generate")
async def generate_captcha(request: Request, waf: WAFEngine = Depends(get_waf_engine)):
    client_ip = request.client.host if request.client else 'unknown'
    return JSONResponse({'success': True, 'challenge': waf.generate_captcha(client_ip)})


@waf_router.get("/test")
async def test_waf(request: Request):
    return JSONResponse({
        'status': 'ok',
        'client_ip': request.client.host if request.client else 'unknown',
    })



def setup_waf(app, config: Optional[dict] = None) -> WAFEngine:
    waf_engine = init_waf_engine(config)
    from app.security.waf.middleware import WAFMiddleware
    app.add_middleware(WAFMiddleware, waf_engine=waf_engine)
    app.include_router(waf_router)

    @app.exception_handler(HTTPException)
    async def waf_exception_handler(request: Request, exc: HTTPException):
        if exc.status_code == 403:
            return JSONResponse(
                status_code=403,
                content={'error': 'Access denied', 'message': exc.detail},
                headers={'X-WAF-Protected': 'true'},
            )
        return JSONResponse(status_code=exc.status_code, content={'error': exc.detail})

    logger.info("WAF successfully initialized")
    return waf_engine
