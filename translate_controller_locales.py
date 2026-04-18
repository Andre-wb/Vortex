#!/usr/bin/env python3
"""
Translate all English fallback strings in the Vortex Controller website
locale files to their native languages.

Same design as translate_locales.py (main app), scoped to
``vortex_controller/web/locales/``.

Usage:
    pip install deep-translator
    python translate_controller_locales.py            # translate every file that's still identical to en.json
    python translate_controller_locales.py --force    # re-translate even if file differs from en
    python translate_controller_locales.py --only ru,uk,es

Protection layers (same as main app):
  1. <code>...</code> → entire element becomes a placeholder
  2. <strong>, <em>, <br> tags → tag becomes placeholder, inner text translated
  3. Product/tech terms (Vortex, Cloudflare, IPFS, Tor, ...) → placeholder
  4. {placeholders} in template strings → preserved
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

try:
    from deep_translator import GoogleTranslator
except ImportError:
    print("Install first: pip install deep-translator", file=sys.stderr)
    sys.exit(1)


LOCALE_DIR = Path("vortex_controller/web/locales")
SOURCE_LOCALE = "en"
SEPARATOR = "\n|||SEP|||\n"
BATCH_SIZE = 40
SKIP_VALUES = {"VORTEX", "", " "}

# Map our locale codes to Google Translate codes where they differ
CODE_MAP = {
    "he": "iw",
    "jv": "jw",
    "zh": "zh-CN",
    "zh-TW": "zh-TW",
}

# Terms that should never be translated (product, tech, brand names)
_PROTECTED_TERMS = sorted([
    "Vortex", "vortexx.sol", "vortexx",
    "Controller", "Cloudflare", "Tor", "IPFS", "IPNS", "Solana",
    "SNS", "Bonfida", "DNS", "DNSLink", "HTTPS", "HTTP",
    "WebSocket", "QR", "QR Code", "Ed25519", "X25519",
    "WebAuthn", "FIDO2", "Passkey", "Passkeys",
    "PostgreSQL", "SQLite", "Python", "Rust",
    "Anchor", "Devnet", "Mainnet",
    "Wi-Fi", "GitHub",
    # Network mode labels we expose verbatim in the UI
    "Global", "Custom", "Local",
    # Classification labels appearing in response payloads
    "pubkey", "mirrors",
], key=len, reverse=True)


# ── Placeholder-based translation-safe transformer ────────────────────────


def _protect(text: str) -> tuple[str, dict]:
    """Replace tags and protected terms with opaque placeholders Google won't mangle."""
    slots: dict[str, str] = {}

    def _slot(value: str) -> str:
        key = f"§§{len(slots):03d}§§"
        slots[key] = value
        return key

    # 1. <br>
    text = re.sub(r"<br\s*/?>", lambda m: _slot(m.group(0)), text, flags=re.I)

    # 2. Paired tags <strong>...</strong>, <em>...</em>, <code>...</code>
    for tag in ("code", "strong", "em", "b", "i"):
        pattern = re.compile(rf"<{tag}>(.*?)</{tag}>", re.I | re.S)

        def _replace_paired(m, t=tag):
            inner = m.group(1)
            open_slot = _slot(f"<{t}>")
            close_slot = _slot(f"</{t}>")
            return f"{open_slot}{inner}{close_slot}"

        text = pattern.sub(_replace_paired, text)

    # 3. {placeholders}
    text = re.sub(r"\{[^}]+\}", lambda m: _slot(m.group(0)), text)

    # 4. Protected terms (longest first so "QR Code" wins over "QR")
    for term in _PROTECTED_TERMS:
        pattern = re.compile(r"\b" + re.escape(term) + r"\b")
        text = pattern.sub(lambda m: _slot(m.group(0)), text)

    return text, slots


def _restore(text: str, slots: dict) -> str:
    for key, value in slots.items():
        text = text.replace(key, value)
    return text


# ── JSON walker ───────────────────────────────────────────────────────────


def _walk_strings(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, path + (str(i),))
    elif isinstance(obj, str):
        yield path, obj


def _set_path(obj, path, value):
    cur = obj
    for p in path[:-1]:
        if isinstance(cur, dict):
            cur = cur[p]
        else:
            cur = cur[int(p)]
    last = path[-1]
    if isinstance(cur, dict):
        cur[last] = value
    else:
        cur[int(last)] = value


# ── Main translation loop ─────────────────────────────────────────────────


def translate_file(target_code: str, source_obj: dict, force: bool) -> bool:
    target_path = LOCALE_DIR / f"{target_code}.json"
    if not target_path.exists():
        print(f"  skip: {target_path} does not exist")
        return False

    current = json.loads(target_path.read_text(encoding="utf-8"))
    # Skip if already translated (differs from source) unless --force
    if not force and current != source_obj:
        print(f"  skip {target_code}: already translated (use --force to overwrite)")
        return False

    google_code = CODE_MAP.get(target_code, target_code)
    try:
        translator = GoogleTranslator(source="en", target=google_code)
    except Exception as e:
        print(f"  skip {target_code}: unsupported by GoogleTranslator ({e})")
        return False

    # Collect all translatable strings with their paths
    entries = [(p, v) for p, v in _walk_strings(source_obj) if v not in SKIP_VALUES]
    protected = [(p, *_protect(v)) for p, v in entries]

    # Batch for efficiency
    result = json.loads(json.dumps(source_obj))  # deep copy
    for batch_start in range(0, len(protected), BATCH_SIZE):
        batch = protected[batch_start : batch_start + BATCH_SIZE]
        joined = SEPARATOR.join(text for _, text, _ in batch)
        try:
            translated_joined = translator.translate(joined)
        except Exception as e:
            print(f"    translate error batch {batch_start}: {e}")
            time.sleep(2)
            continue
        if translated_joined is None:
            print(f"    empty response at batch {batch_start}")
            continue

        parts = translated_joined.split(SEPARATOR)
        if len(parts) != len(batch):
            # Google sometimes merges — fall back to per-string translation
            parts = []
            for _, text, _ in batch:
                try:
                    parts.append(translator.translate(text) or text)
                except Exception:
                    parts.append(text)
                time.sleep(0.1)

        for (path, _, slots), translated in zip(batch, parts):
            restored = _restore(translated, slots)
            _set_path(result, path, restored)

        time.sleep(0.5)  # polite rate

    target_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"  ✅ {target_code} written ({len(entries)} strings)")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--force", action="store_true",
                    help="Overwrite files that already differ from en.json")
    ap.add_argument("--only", type=str, default="",
                    help="Comma-separated list of locales to translate (default: all)")
    args = ap.parse_args()

    source_path = LOCALE_DIR / f"{SOURCE_LOCALE}.json"
    if not source_path.exists():
        print(f"Source locale not found: {source_path}", file=sys.stderr)
        return 1
    source_obj = json.loads(source_path.read_text(encoding="utf-8"))

    all_locales = sorted(
        p.stem for p in LOCALE_DIR.glob("*.json") if p.stem != SOURCE_LOCALE
    )
    only = [c.strip() for c in args.only.split(",") if c.strip()]
    todo = only or all_locales

    print(f"Translating {len(todo)} locale(s) from {SOURCE_LOCALE}")
    total_done = 0
    for code in todo:
        print(f"\n[{code}]")
        try:
            if translate_file(code, source_obj, force=args.force):
                total_done += 1
        except KeyboardInterrupt:
            print("\ninterrupted")
            return 130
        except Exception as e:
            print(f"  error: {e}")
    print(f"\nDone. {total_done} file(s) translated, {len(todo) - total_done} skipped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
