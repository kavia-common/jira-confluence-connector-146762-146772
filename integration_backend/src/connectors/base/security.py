from __future__ import annotations

import base64
import json
import logging
import os
import secrets
from hashlib import sha256
from typing import Any, Tuple, Optional

logger = logging.getLogger("integration_backend.security")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
except Exception:  # pragma: no cover - optional
    AESGCM = None  # type: ignore


def _derive_key_from_string(key_str: str) -> bytes:
    """
    Derive a 32-byte key from an arbitrary string using SHA-256 (dev-friendly).
    For production-grade KDF, use a salt + PBKDF2/HKDF and rotate keys via KMS.
    """
    return sha256(key_str.encode("utf-8")).digest()


def _load_key() -> Optional[bytes]:
    key_str = os.getenv("ENCRYPTION_KEY", "").strip()
    if not key_str:
        return None
    # try URL-safe base64
    try:
        raw = base64.urlsafe_b64decode(key_str)
        if len(raw) in (16, 24, 32):
            return raw if len(raw) == 32 else sha256(raw).digest()
    except Exception:
        pass
    # try standard base64
    try:
        raw = base64.b64decode(key_str)
        if len(raw) in (16, 24, 32):
            return raw if len(raw) == 32 else sha256(raw).digest()
    except Exception:
        pass
    # fallback: deterministic derivation
    return _derive_key_from_string(key_str)


def is_encryption_active() -> bool:
    return AESGCM is not None and _load_key() is not None


def encrypt_bytes(plaintext: bytes) -> Tuple[str, bool]:
    """
    Encrypt bytes using AES-GCM if available+configured; otherwise return base64 of plaintext.

    Returns:
        (ciphertext_b64, was_encrypted)
    """
    key = _load_key()
    if AESGCM is None or key is None:
        if key is None:
            logger.warning("ENCRYPTION_KEY not set; storing token data in plaintext (dev mode).")
        else:
            logger.warning("cryptography not available; storing token data in plaintext (dev mode).")
        return base64.b64encode(plaintext).decode("utf-8"), False
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    payload = nonce + ct
    return base64.b64encode(payload).decode("utf-8"), True


def decrypt_bytes(ciphertext_b64: str, was_encrypted: bool) -> bytes:
    """
    Decrypt ciphertext previously encrypted by encrypt_bytes().
    If was_encrypted is False, treat ciphertext_b64 as base64-encoded plaintext.
    """
    raw = base64.b64decode(ciphertext_b64.encode("utf-8"))
    if not was_encrypted:
        return raw
    key = _load_key()
    if AESGCM is None or key is None:
        logger.error("Attempting to decrypt but encryption environment is not available.")
        raise RuntimeError("Decryption unavailable")
    aesgcm = AESGCM(key)
    nonce, ct = raw[:12], raw[12:]
    return aesgcm.decrypt(nonce, ct, associated_data=None)


def encrypt_json(obj: Any) -> Tuple[str, bool]:
    """
    Serialize to JSON and encrypt. Returns (ciphertext_b64, was_encrypted).
    """
    data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return encrypt_bytes(data)


def decrypt_json(ciphertext_b64: str, was_encrypted: bool) -> Any:
    """
    Decrypt and deserialize JSON to Python.
    """
    data = decrypt_bytes(ciphertext_b64, was_encrypted)
    return json.loads(data.decode("utf-8"))
