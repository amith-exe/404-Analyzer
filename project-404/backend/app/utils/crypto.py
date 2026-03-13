"""Lightweight encryption helpers for auth config storage."""
import base64
import hashlib
import os

from cryptography.fernet import Fernet

from app.config import settings


def _get_fernet() -> Fernet:
    # Derive a 32-byte key from settings.secret_key
    raw = hashlib.sha256(settings.secret_key.encode()).digest()
    key = base64.urlsafe_b64encode(raw)
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    """Encrypt *plaintext* and return a base64-encoded ciphertext string."""
    f = _get_fernet()
    return f.encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a ciphertext string produced by *encrypt_secret*."""
    f = _get_fernet()
    return f.decrypt(ciphertext.encode()).decode()


def redact_secret(value: str) -> str:
    """Return a redacted representation of *value* for logging/storage."""
    if not value:
        return ""
    if len(value) <= 8:
        return "***"
    return value[:4] + "***" + value[-4:]
