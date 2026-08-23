#!/usr/bin/env python3
"""Генератор golden-векторов pre-key бандла Python ↔ Rust.

Повторный запуск даёт байт-в-байт идентичный файл.

Запуск (из корня репозитория):
    python scripts/gen_proto_parity_vectors.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(ROOT, "app", "tests", "vectors", "proto_parity.json")

_spec = importlib.util.spec_from_file_location(
    "proto_parity_reference",
    os.path.join(ROOT, "app", "tests", "proto_parity_reference.py"),
)
_reference = importlib.util.module_from_spec(_spec)
sys.modules["proto_parity_reference"] = _reference
_spec.loader.exec_module(_reference)


def build() -> dict:
    return {fn.name: [{"args": case, "expected": fn.python(case)} for case in fn.cases] for fn in _reference.FUNCTIONS}


def main() -> None:
    payload = build()
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    total = sum(len(v) for v in payload.values())
    print(f"{OUT_PATH}: {len(payload)} функций, {total} векторов")


if __name__ == "__main__":
    main()
