"""JSON encoding shared by the Python SDK and its tests.

Objects are sorted so a Python caller and a TypeScript caller produce the same
bytes for the same value. The signature covers those bytes, not a later rewrite.
"""

from __future__ import annotations

import json
from typing import Any


def encode_json(value: Any) -> bytes:
    _reject_unsupported(value)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return encoded.encode("utf-8")


def _reject_unsupported(value: Any) -> None:
    if value is None or isinstance(value, bool | str):
        return
    if isinstance(value, int):
        return
    if isinstance(value, list):
        for item in value:
            _reject_unsupported(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("object keys must be strings")
            _reject_unsupported(item)
        return
    raise ValueError("value must be a JSON object, array, string, integer, boolean, or null")
