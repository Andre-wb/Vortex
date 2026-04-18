"""Build and sign the integrity manifest.

Usage:
    # first time: auto-generates release key at RELEASE_KEY_PATH and signs
    python -m vortex_controller.integrity.sign_tool

    # use an explicit keyfile:
    python -m vortex_controller.integrity.sign_tool --key ~/.config/vortex-release.key

    # only print the pubkey of the current release key:
    python -m vortex_controller.integrity.sign_tool --show-pubkey

Outputs:
    INTEGRITY.sig.json  at the project root

Release pubkey storage:
    The private key lives outside the repo (default: keys/release.key beside
    the controller). The PUBLIC key must be pinned in the Vortex client so
    that users can verify any controller they connect to. Rotate rarely.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import VERSION
from .manifest import build_manifest, canonical_json


DEFAULT_KEY_PATH = Path("keys/release.key")
DEFAULT_OUT = Path("INTEGRITY.sig.json")


def _load_or_create_key(path: Path) -> Ed25519PrivateKey:
    if path.exists():
        return Ed25519PrivateKey.from_private_bytes(path.read_bytes())
    path.parent.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(raw)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return priv


def _pubkey_hex(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _sign(priv: Ed25519PrivateKey, manifest: dict) -> dict:
    data = canonical_json(manifest)
    sig = priv.sign(data).hex()
    return {
        "payload": manifest,
        "signature": sig,
        "signed_by": _pubkey_hex(priv),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--key", type=Path, default=DEFAULT_KEY_PATH,
                    help=f"Ed25519 private key path (default: {DEFAULT_KEY_PATH})")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent,
                    help="Root directory to hash (default: vortex_controller/)")
    ap.add_argument("--out", type=Path, default=None,
                    help=f"Output signed manifest (default: <root>/../{DEFAULT_OUT})")
    ap.add_argument("--version", default=VERSION, help=f"Manifest version (default: {VERSION})")
    ap.add_argument("--show-pubkey", action="store_true",
                    help="Print the release pubkey and exit")
    args = ap.parse_args()

    priv = _load_or_create_key(args.key)
    if args.show_pubkey:
        print(_pubkey_hex(priv))
        return 0

    root = args.root.resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    # Place the signed manifest alongside the project root by default.
    out = args.out or (root.parent / DEFAULT_OUT)

    print(f"Hashing files under {root}…")
    manifest = build_manifest(root=root, version=args.version, built_at=int(time.time()))
    signed = _sign(priv, manifest)
    out.write_text(json.dumps(signed, indent=2), encoding="utf-8")

    print(f"✅ Signed {len(manifest['files'])} files")
    print(f"   Release pubkey: {_pubkey_hex(priv)}")
    print(f"   Written to:     {out}")
    print(f"   Key file:       {args.key}  (keep safe, don't commit)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
