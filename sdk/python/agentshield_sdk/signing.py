"""Ed25519 signatures over the AgentShield v1 signing input.

The private seed stays in the caller process. This module never sends it.
"""

from __future__ import annotations

import base64
import hashlib
import re

NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


def signing_input(timestamp: int, nonce: str, body: bytes) -> str:
    digest = hashlib.sha256(body).hexdigest()
    return f"{timestamp}.{nonce}.{digest}"


def sign(seed: bytes, timestamp: int, nonce: str, body: bytes) -> str:
    if not NONCE_PATTERN.fullmatch(nonce):
        raise ValueError("nonce is invalid")
    signature = _private_key(seed).sign(signing_input(timestamp, nonce, body).encode("ascii"))
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def public_key(seed: bytes) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = _private_key(seed).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _private_key(seed: bytes):
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise RuntimeError("install cryptography before signing") from exc
    return Ed25519PrivateKey.from_private_bytes(seed)
