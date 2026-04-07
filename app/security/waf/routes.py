"""WAF Management API — эндпоинты для управления WAF."""
from __future__ import annotations

import ipaddress
import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from app.security.waf.captcha import WAFCaptcha
from app.security.waf.engine import WAFEngine

logger = logging.getLogger(__name__)


# ── WAFManager ────────────────────────────────────────────────────────────

class WAFManager:
    def __init__(self, waf_engine: WAFEngine):
        self.waf = waf_engine

    def block_ip(self, ip: str, reason: str, duration: int = 3600) -> Dict:
        success = self.waf.block_ip(ip, reason, duration)
        return {'success': success, 'ip': ip, 'reason': reason, 'duration': duration}

    def unblock_ip(self, ip: str) -> Dict:
        if ip in self.waf.blocked_ips:
            del self.waf.blocked_ips[ip]
            return {'success': True, 'ip': ip, 'message': 'IP unblocked'}
        return {'success': False, 'ip': ip, 'message': 'IP not found'}

    def get_blocked_ips(self) -> List[Dict]:
        return [
            {
                'ip': ip,
                'blocked_at': info.get('blocked_at').isoformat() if info.get('blocked_at') else None,
                'blocked_until': info.get('until').isoformat() if info.get('until') else None,
                'reason': info.get('reason', 'unknown'),
                'duration': info.get('duration', 0),
            }
            for ip, info in self.waf.blocked_ips.items()
        ]

    def add_whitelist_ip(self, ip: str) -> Dict:
        try:
            ipaddress.ip_address(ip)
            self.waf.ip_whitelist.add(ip)
            return {'success': True, 'ip': ip, 'message': 'IP added to whitelist'}
        except ValueError:
            return {'success': False, 'ip': ip, 'message': 'Invalid IP format'}

    def remove_whitelist_ip(self, ip: str) -> Dict:
        if ip in self.waf.ip_whitelist:
            self.waf.ip_whitelist.remove(ip)
            return {'success': True, 'ip': ip, 'message': 'IP removed from whitelist'}
        return {'success': False, 'ip': ip, 'message': 'IP not found in whitelist'}

    def get_whitelist(self) -> List[str]:
        return list(self.waf.ip_whitelist)


# ── Global singleton ──────────────────────────────────────────────────────

_waf_engine: Optional[WAFEngine] = None


def init_waf_engine(config: Optional[Dict] = None) -> WAFEngine:
    global _waf_engine
    _waf_engine = WAFEngine(config)
    return _waf_engine


def get_waf_engine() -> WAFEngine:
    if _waf_engine is None:
        raise RuntimeError("WAFEngine not initialized. Call init_waf_engine() first.")
    return _waf_engine


def get_waf_manager() -> WAFManager:
    return WAFManager(get_waf_engine())


# ── Router ────────────────────────────────────────────────────────────────

waf_router = APIRouter(prefix="/waf", tags=["WAF"])


@waf_router.get("/stats")
async def waf_stats(waf: WAFEngine = Depends(get_waf_engine)):
    return JSONResponse(waf.get_stats())


@waf_router.get("/rules")
async def waf_rules(waf: WAFEngine = Depends(get_waf_engine)):
    rules = [
        {
            'id': r.rule_id, 'description': r.description,
            'severity': r.severity, 'action': r.action,
            'trigger_count': r.trigger_count,
            'last_triggered': r.last_triggered.isoformat() if r.last_triggered else None,
        }
        for r in waf.rules
    ]
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
async def generate_captcha(request: Request):
    client_ip = request.client.host if request.client else 'unknown'
    captcha = WAFCaptcha()
    challenge = captcha.generate_challenge(client_ip)
    return JSONResponse({'success': True, 'challenge': challenge})


@waf_router.get("/test")
async def test_waf(request: Request):
    return JSONResponse({'status': 'ok', 'client_ip': request.client.host if request.client else 'unknown'})


# ── Setup function ────────────────────────────────────────────────────────

def setup_waf(app, config: Optional[Dict] = None) -> WAFEngine:
    waf_engine = WAFEngine(config)
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
