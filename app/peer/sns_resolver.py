"""Solana Name Service (SNS) resolver for .sol domains.

Clients use this to go from a human-friendly name (e.g. ``vortexx.sol``) to
the underlying controller URL + pubkey. The SNS record is stored on-chain;
we read it through the Bonfida public gateway rather than speaking Solana
directly so there's no wallet dependency.

We look up two SNS record types per domain:
    - ``URL``  — the controller HTTPS URL
    - ``TXT``  — optional extra metadata (e.g. "pubkey=<hex>;mirrors=...")

If Bonfida is unreachable we fall back to:
    - SNS-SDK public RPC (Helius / Ankr)  — future work
    - User-supplied cached result from previous successful lookups

For the MVP only Bonfida is implemented. The interface is narrow enough that
a second provider can be plugged in later.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

BONFIDA_API = "https://sns-api.bonfida.com"
DEFAULT_TIMEOUT = 10.0

# Very permissive domain pattern: subdomains allowed, ends with .sol
_SOL_DOMAIN = re.compile(r"^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*\.sol$", re.I)


@dataclass
class SnsRecord:
    """Parsed SNS lookup result."""
    domain: str
    url: Optional[str] = None           # controller URL from the URL record
    pubkey: Optional[str] = None        # controller ed25519 pubkey (from TXT)
    mirrors: list[str] = None           # extra mirror URLs (from TXT)
    raw_txt: Optional[str] = None       # raw TXT content, for debugging

    def __post_init__(self):
        if self.mirrors is None:
            self.mirrors = []

    @property
    def is_resolved(self) -> bool:
        return bool(self.url)


def is_sol_domain(s: str) -> bool:
    return bool(s and _SOL_DOMAIN.match(s.strip().lower()))


async def resolve(
    domain: str,
    api_url: str = BONFIDA_API,
    timeout: float = DEFAULT_TIMEOUT,
) -> SnsRecord:
    """Resolve ``domain.sol`` via the Bonfida SNS API.

    Raises ``ValueError`` if the name is not a valid ``.sol`` domain.
    On network/record failure returns an SnsRecord with ``is_resolved=False``
    (rather than raising) so callers can fall back to hardcoded URLs.
    """
    domain = domain.strip().lower()
    if not is_sol_domain(domain):
        raise ValueError(f"not a .sol domain: {domain!r}")

    rec = SnsRecord(domain=domain)

    # Two independent record lookups — TXT is optional.
    async with httpx.AsyncClient(timeout=timeout) as http:
        url_task = _fetch_record(http, api_url, domain, "URL")
        txt_task = _fetch_record(http, api_url, domain, "TXT")
        url_val, txt_val = await asyncio.gather(url_task, txt_task)

    if url_val:
        rec.url = _normalize_url(url_val)
    if txt_val:
        rec.raw_txt = txt_val
        _parse_txt(rec, txt_val)

    return rec


async def _fetch_record(
    http: httpx.AsyncClient,
    api_url: str,
    domain: str,
    record: str,
) -> Optional[str]:
    """Query /v2/record/{domain}/{record} and return the value, or None."""
    endpoint = f"{api_url.rstrip('/')}/v2/record/{domain}/{record}"
    try:
        r = await http.get(endpoint)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        data = r.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.debug("SNS %s lookup for %s failed: %s", record, domain, e)
        return None

    # Bonfida response shapes vary by version — handle the common ones:
    #   { "result": { "content": "<value>" } }
    #   { "result": "<value>" }
    #   { "content": "<value>" }
    #   "<value>"
    result = data.get("result", data) if isinstance(data, dict) else data
    if isinstance(result, dict):
        value = result.get("content") or result.get("deserialized") or result.get("value")
    else:
        value = result

    if not isinstance(value, str):
        return None
    return value.strip()


def _normalize_url(value: str) -> str:
    """Ensure we end up with an http(s):// URL."""
    value = value.strip()
    if not value:
        return value
    if value.startswith(("http://", "https://", "wss://", "ws://")):
        return value
    # Plain hostname — assume HTTPS
    return "https://" + value


def _parse_txt(rec: SnsRecord, txt: str) -> None:
    """Parse a simple "k=v;k2=v2" TXT record.

    Recognised keys:
        pubkey   controller Ed25519 pubkey (hex)
        mirror   one mirror URL (may appear multiple times)
        mirrors  comma-separated mirrors
    """
    for part in txt.replace("\n", ";").split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if not val:
            continue
        if key == "pubkey":
            rec.pubkey = val
        elif key == "mirror":
            rec.mirrors.append(val)
        elif key == "mirrors":
            rec.mirrors.extend(m.strip() for m in val.split(",") if m.strip())
