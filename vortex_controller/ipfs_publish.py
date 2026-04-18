"""Publish the controller web bundle to IPFS.

Talks to any IPFS HTTP API endpoint — a local Kubo daemon
(``http://127.0.0.1:5001``), a pinning service like Web3.Storage or Pinata
that implements the same API, or the Blockfrost / Fleek gateway.

Usage:
    # With a local kubo daemon running:
    python -m vortex_controller.ipfs_publish

    # With a remote pinning service:
    IPFS_API=https://api.pinata.cloud \\
    IPFS_AUTH="Bearer <jwt>" \\
    python -m vortex_controller.ipfs_publish

Output: a root CID that you can:
    1. Put in ``MIRROR_URLS`` so clients see it as a mirror:
         MIRROR_URLS="ipfs://bafy...,https://..."
    2. Pin with Pinata / Web3.Storage / Filebase
    3. Point a DNSLink TXT record at (``_dnslink.vortexx.sol``)
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

WEB_DIR = Path(__file__).parent / "web"


def publish_to_ipfs(
    src_dir: Path,
    api_url: str,
    auth_header: Optional[str] = None,
    wrap_with_directory: bool = True,
    timeout: float = 60.0,
) -> dict:
    """Upload ``src_dir`` recursively to an IPFS HTTP API.

    Returns a dict describing what was pinned:
        {
            "root_cid": "bafy...",          # the directory CID
            "files": [
                {"name": "index.html", "cid": "bafy...", "size": 1234},
                ...
            ],
        }

    The IPFS add API returns one line of JSON per file; the last line is the
    root directory. We stream-collect all of them.
    """
    files: list[tuple[str, tuple[str, bytes, str]]] = []
    for p in sorted(src_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(src_dir).as_posix()
        mtype = _mime_for(p.suffix)
        files.append(("file", (rel, p.read_bytes(), mtype)))

    if not files:
        raise RuntimeError(f"no files found under {src_dir}")

    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header

    params = {
        "pin": "true",
        "cid-version": "1",
        "hash": "sha2-256",
        "wrap-with-directory": "true" if wrap_with_directory else "false",
    }

    url = api_url.rstrip("/") + "/api/v0/add"
    logger.info("Uploading %d files to %s", len(files), url)
    with httpx.Client(timeout=timeout, follow_redirects=True) as http:
        r = http.post(url, params=params, files=files, headers=headers)
        r.raise_for_status()

    entries = [json.loads(line) for line in r.text.splitlines() if line.strip()]
    if not entries:
        raise RuntimeError("IPFS returned empty response")

    # The last entry with an empty Name (or matching directory) is the root.
    root = None
    for e in reversed(entries):
        if e.get("Name", "") == "" or e.get("Name") == src_dir.name:
            root = e
            break
    if root is None:
        # Fallback: take the last entry
        root = entries[-1]

    files_out = [
        {"name": e.get("Name"), "cid": e.get("Hash"), "size": int(e.get("Size") or 0)}
        for e in entries
        if e is not root
    ]
    return {"root_cid": root["Hash"], "files": files_out}


def _mime_for(ext: str) -> str:
    return {
        ".html": "text/html",
        ".css":  "text/css",
        ".js":   "application/javascript",
        ".json": "application/json",
        ".svg":  "image/svg+xml",
        ".png":  "image/png",
        ".ico":  "image/x-icon",
    }.get(ext.lower(), "application/octet-stream")


def _format_report(result: dict, api_url: str) -> str:
    root = result["root_cid"]
    lines = [
        f"✅ Published to IPFS via {api_url}",
        "",
        f"Root CID:  {root}",
        f"Files:     {len(result['files'])}",
        "",
        "Gateway URLs (try any):",
        f"  https://ipfs.io/ipfs/{root}/",
        f"  https://{root}.ipfs.dweb.link/",
        f"  https://cf-ipfs.com/ipfs/{root}/",
        "",
        "Add to controller .env / env vars:",
        f'  MIRROR_URLS="ipfs://{root}"',
        "",
        "For a persistent name, set a DNSLink record on your domain:",
        f"  _dnslink.vortexx.sol  TXT  \"dnslink=/ipfs/{root}\"",
    ]
    return "\n".join(lines)


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--api", default=os.getenv("IPFS_API", "http://127.0.0.1:5001"),
        help="IPFS HTTP API endpoint (env: IPFS_API)",
    )
    parser.add_argument(
        "--auth", default=os.getenv("IPFS_AUTH", ""),
        help="Authorization header value, e.g. 'Bearer <jwt>' (env: IPFS_AUTH)",
    )
    parser.add_argument(
        "--src", type=Path, default=WEB_DIR,
        help="Source directory (default: vortex_controller/web)",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON instead of text")
    args = parser.parse_args()

    if not args.src.is_dir():
        print(f"source not found: {args.src}", file=sys.stderr)
        return 1

    try:
        result = publish_to_ipfs(
            src_dir=args.src,
            api_url=args.api,
            auth_header=args.auth or None,
        )
    except Exception as e:
        print(f"upload failed: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(_format_report(result, args.api))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
