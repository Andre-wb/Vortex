"""WAFEngine — основной движок анализа запросов."""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from app.security.waf.signatures import WAFSignature

logger = logging.getLogger(__name__)


class WAFEngine:
    def __init__(self, config: Optional[Dict] = None):
        cfg = config or {}
        self.rules = WAFSignature.get_all_rules()
        self.safe_params = set(cfg.get('safe_params', ['csrf_token', '_csrf', 'csrfmiddlewaretoken']))
        self.ip_whitelist: Set[str] = {'127.0.0.1', '::1', 'localhost'}
        self.ip_blacklist: Set[str] = set()
        self.blocked_ips: Dict[str, Dict] = {}
        self.request_history: Dict[str, List[datetime]] = defaultdict(list)

        self.rate_limit_requests = int(cfg.get('rate_limit_requests', 100))
        self.rate_limit_window = int(cfg.get('rate_limit_window', 60))
        self.block_duration = int(cfg.get('block_duration', 3600))
        self.max_content_length = int(cfg.get('max_content_length', 10 * 1024 * 1024))

        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'rules_triggered': defaultdict(int),
            'ip_blocks': 0,
        }

        for ip in cfg.get('whitelist_ips', []):
            self.ip_whitelist.add(ip)

    def is_ip_blocked(self, ip: str) -> bool:
        if ip in self.ip_whitelist:
            return False
        if ip in self.ip_blacklist:
            return True
        if ip in self.blocked_ips:
            if self.blocked_ips[ip].get('until', datetime.min.replace(tzinfo=timezone.utc)) > datetime.now(timezone.utc):
                return True
            del self.blocked_ips[ip]
        return False

    def block_ip(self, ip: str, reason: str, duration: Optional[int] = None) -> bool:
        if ip in self.ip_whitelist:
            logger.warning(f"Attempt to block whitelisted IP: {ip}")
            return False
        dur = duration or self.block_duration
        self.blocked_ips[ip] = {
            'blocked_at': datetime.now(timezone.utc),
            'until': datetime.now(timezone.utc) + timedelta(seconds=dur),
            'reason': reason,
            'duration': dur,
        }
        self.stats['ip_blocks'] += 1
        logger.warning(f"IP blocked: {ip}, reason: {reason}")
        return True

    def check_rate_limit(self, ip: str) -> Tuple[bool, Optional[str]]:
        if ip in self.ip_whitelist:
            return True, None
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=self.rate_limit_window)
        self.request_history[ip] = [ts for ts in self.request_history[ip] if ts > window_start]

        if len(self.request_history[ip]) >= self.rate_limit_requests:
            oldest = min(self.request_history[ip])
            wait = self.rate_limit_window - (now - oldest).total_seconds()
            if len(self.request_history[ip]) >= self.rate_limit_requests * 2:
                self.block_ip(ip, "Rate limit exceeded (double limit)", 1800)
            return False, f"Rate limit exceeded. Try again in {wait:.0f} seconds."

        self.request_history[ip].append(now)
        if len(self.request_history[ip]) > self.rate_limit_requests * 10:
            self.request_history[ip] = self.request_history[ip][-self.rate_limit_requests:]
        return True, None

    def analyze_request(self, request_data: Dict) -> Dict[str, Any]:
        findings = []
        should_block = False
        matched_rules = []

        ip = request_data.get('client_ip', 'unknown')

        if self.is_ip_blocked(ip):
            return {'block': True, 'reason': 'IP blocked', 'findings': [{'rule_id': 'IP-BLOCKED', 'severity': 'critical'}]}

        rate_ok, rate_reason = self.check_rate_limit(ip)
        if not rate_ok:
            return {'block': True, 'reason': rate_reason, 'findings': [{'rule_id': 'RATE-LIMIT', 'severity': 'medium'}]}

        method = request_data.get('method', '').upper()
        if method not in {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}:
            findings.append({'rule_id': 'INVALID-METHOD', 'severity': 'medium', 'description': f'Invalid HTTP method: {method}'})

        url = request_data.get('url', '')
        if len(url) > 2048:
            findings.append({'rule_id': 'LONG-URL', 'severity': 'low', 'description': f'URL too long: {len(url)} characters'})

        headers = request_data.get('headers', {})
        for name, value in headers.items():
            if name.lower() == 'user-agent' and (not value or len(value) < 5):
                findings.append({'rule_id': 'SUSPICIOUS-UA', 'severity': 'low', 'description': 'Suspicious User-Agent'})
            if name.lower() == 'referer' and 'javascript:' in value.lower():
                findings.append({'rule_id': 'XSS-REFERER', 'severity': 'high', 'description': 'XSS in Referer header'})

        params = request_data.get('params', {})
        for name, val in params.items():
            values = val if isinstance(val, list) else [val]
            for v in values:
                findings.extend(self._check_parameter(name, str(v)))

        body = request_data.get('body', '')
        if body:
            if len(body) > self.max_content_length:
                findings.append({'rule_id': 'LARGE-BODY', 'severity': 'medium', 'description': f'Request body too large: {len(body)} bytes'})
            else:
                findings.extend(self._check_request_body(body, request_data.get('content_type', '')))

        path = request_data.get('path', '')
        findings.extend(self._check_path(path))

        for f in findings:
            if f.get('severity') in ('high', 'critical'):
                should_block = True
                matched_rules.append(f['rule_id'])

        self.stats['total_requests'] += 1
        if should_block:
            self.stats['blocked_requests'] += 1
            for rid in matched_rules:
                self.stats['rules_triggered'][rid] += 1

        return {'block': should_block, 'findings': findings, 'matched_rules': matched_rules, 'client_ip': ip}

    def _check_parameter(self, name: str, value: str) -> List[Dict]:
        if name.lower() in self.safe_params:
            return []
        res = []
        for rule in self.rules:
            if rule.match(name) or rule.match(value):
                res.append({
                    'rule_id': rule.rule_id,
                    'description': f'{rule.description} in parameter {name}',
                    'severity': rule.severity,
                    'value': value[:100],
                })
                rule.trigger_count += 1
                rule.last_triggered = datetime.now(timezone.utc)
        return res

    def _check_request_body(self, body: str, content_type: str) -> List[Dict]:
        findings = []
        parsed = False
        if 'multipart/form-data' in content_type:
            import urllib.parse
            decoded_body = urllib.parse.unquote(urllib.parse.unquote(body))
            if '..' in decoded_body or '../' in decoded_body or '..\\' in decoded_body:
                findings.append({
                    'rule_id': 'PATH-TRAVERSAL',
                    'severity': 'high',
                    'description': 'Directory traversal attempt in multipart form data',
                })
            dangerous_extensions = ('.php', '.asp', '.aspx', '.jsp', '.py', '.pl', '.sh', '.exe', '.bat', '.cmd')
            for ext in dangerous_extensions:
                if ext in decoded_body.lower():
                    findings.append({
                        'rule_id': 'DANGEROUS-UPLOAD',
                        'severity': 'high',
                        'description': f'Dangerous file extension {ext} in multipart upload',
                    })
                    break
            return findings

        if 'application/json' in content_type:
            try:
                data = json.loads(body)
                findings.extend(self._check_json_structure(data))
                parsed = True
            except json.JSONDecodeError:
                findings.append({'rule_id': 'INVALID-JSON', 'severity': 'medium', 'description': 'Invalid JSON in request body'})

        elif 'application/x-www-form-urlencoded' in content_type:
            import urllib.parse
            try:
                parsed_data = urllib.parse.parse_qs(body)
                for key, values in parsed_data.items():
                    if key.lower() in self.safe_params:
                        continue
                    for val in values:
                        findings.extend(self._check_parameter(key, val))
                parsed = True
            except Exception:
                pass

        if not parsed:
            for rule in self.rules:
                if rule.match(body):
                    findings.append({
                        'rule_id': rule.rule_id,
                        'description': f'{rule.description} in request body',
                        'severity': rule.severity,
                        'value': body[:100],
                    })
                    rule.trigger_count += 1
        return findings

    def _check_json_structure(self, data: Any, path: str = "") -> List[Dict]:
        findings = []
        if isinstance(data, dict):
            for key, value in data.items():
                cur = f"{path}.{key}" if path else key
                findings.extend(self._check_parameter(cur, key))
                if isinstance(value, (dict, list)):
                    findings.extend(self._check_json_structure(value, cur))
                else:
                    findings.extend(self._check_parameter(cur, str(value)))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                cur = f"{path}[{i}]"
                if isinstance(item, (dict, list)):
                    findings.extend(self._check_json_structure(item, cur))
                else:
                    findings.extend(self._check_parameter(cur, str(item)))
        return findings

    def _check_path(self, path: str) -> List[Dict]:
        findings = []
        import urllib.parse
        decoded = urllib.parse.unquote(urllib.parse.unquote(path))
        if '..' in decoded or '../' in decoded or '..\\' in decoded:
            findings.append({'rule_id': 'PATH-TRAVERSAL', 'severity': 'high', 'description': 'Directory traversal attempt in path'})
        for ext in ('.php', '.asp', '.aspx', '.jsp', '.py', '.pl', '.sh'):
            if path.lower().endswith(ext):
                findings.append({'rule_id': 'DANGEROUS-EXTENSION', 'severity': 'medium', 'description': f'Dangerous file extension: {ext}'})
        if len(path) > 500:
            findings.append({'rule_id': 'LONG-PATH', 'severity': 'low', 'description': f'Path too long: {len(path)} characters'})
        for rule in self.rules:
            if rule.match(path):
                findings.append({
                    'rule_id': rule.rule_id,
                    'description': f'{rule.description} in URL path',
                    'severity': rule.severity,
                })
                rule.trigger_count += 1
        return findings

    def get_stats(self) -> Dict:
        total = self.stats['total_requests']
        return {
            'total_requests': total,
            'blocked_requests': self.stats['blocked_requests'],
            'block_rate': round(self.stats['blocked_requests'] / total * 100, 2) if total else 0,
            'rules_triggered': dict(self.stats['rules_triggered']),
            'ip_blocks': self.stats['ip_blocks'],
            'blocked_ips_count': len(self.blocked_ips),
            'active_rules': len([r for r in self.rules if r.trigger_count > 0]),
        }

    def clear_old_blocks(self):
        now = datetime.now(timezone.utc)
        expired = [ip for ip, info in self.blocked_ips.items() if info.get('until', now) < now]
        for ip in expired:
            del self.blocked_ips[ip]
        if expired:
            logger.info(f"Cleared {len(expired)} expired IP blocks")

        # Evict IPs with no recent requests to bound request_history dict size.
        window_start = now - timedelta(seconds=self.rate_limit_window * 2)
        stale = [
            ip for ip, ts_list in self.request_history.items()
            if not ts_list or max(ts_list) < window_start
        ]
        for ip in stale:
            del self.request_history[ip]
