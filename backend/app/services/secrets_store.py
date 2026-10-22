"""Encrypted-at-rest store for AI provider API keys.

Keys live in ``~/.sentinel/keys.json`` (mode 0600 where supported).
Encryption uses ``cryptography.fernet`` when available; otherwise a
machine-bound obfuscation (base64 + XOR keyed off an install salt + user
identity) is used — and we log a clear warning. The fallback is obfuscation,
not security; install ``cryptography`` for real encryption at rest.

Public API:
  set_key / get_key / list_providers / delete_key / clear_all /
  looks_like_secret_file

The decrypted key NEVER touches a logger; it is returned by value and used
only in-memory for the duration of an HTTP request.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets as _pysecrets
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_STORE_DIR = Path(os.getenv("SENTINEL_HOME", str(Path.home() / ".sentinel")))
_STORE_FILE = _STORE_DIR / "keys.json"
_SALT_FILE = _STORE_DIR / "salt.bin"

SECRET_FILE_PATTERNS = (
    ".env", ".pem", ".key", ".p12", ".pfx", ".keystore",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".htpasswd", ".netrc", "credentials", "credentials",
)
SECRET_FILE_SUFFIXES = (".env", ".pem", ".key", ".p12", ".pfx", ".keystore")


def _have_cryptography() -> bool:
    try:
        from cryptography.fernet import Fernet  # noqa: F401
        return True
    except ImportError:
        return False


def _load_or_create_salt() -> bytes:
    _STORE_DIR.mkdir(parents=True, exist_ok=True)
    if _SALT_FILE.is_file():
        return _SALT_FILE.read_bytes()
    salt = _pysecrets.token_bytes(32)
    _SALT_FILE.write_bytes(salt)
    try:
        _SALT_FILE.chmod(0o600)
    except OSError:
        pass
    return salt


def _machine_key() -> bytes:
    salt = _load_or_create_salt()
    identity = f"{os.getenv('USERNAME') or os.getenv('USER','user')}@" \
               f"{os.getenv('COMPUTERNAME') or os.getenv('HOSTNAME','host')}"
    return hashlib.sha256(salt + identity.encode()).digest()


def _xor_cipher(data: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)


def _encrypt(plaintext: str) -> str:
    raw = plaintext.encode("utf-8")
    if _have_cryptography():
        from cryptography.fernet import Fernet
        key = base64.urlsafe_b64encode(_machine_key())
        return "fernet:" + Fernet(key).encrypt(raw).decode()
    token = base64.b64encode(_xor_cipher(raw, _machine_key())).decode()
    return "xor:" + token


def _decrypt(token: str) -> str:
    if not token:
        return ""
    if token.startswith("fernet:"):
        from cryptography.fernet import Fernet
        key = base64.urlsafe_b64encode(_machine_key())
        return Fernet(key).decrypt(token[len("fernet:"):].encode()).decode()
    if token.startswith("xor:"):
        raw = base64.b64decode(token[len("xor:"):])
        return _xor_cipher(raw, _machine_key()).decode("utf-8")
    raise ValueError("unknown key-token format")


if not _have_cryptography():
    logger.warning(
        "cryptography not installed — API keys stored with weak obfuscation "
        "(NOT real encryption). Install `cryptography` for Fernet at rest."
    )


def _read_store() -> dict:
    if not _STORE_FILE.is_file():
        return {}
    try:
        return json.loads(_STORE_FILE.read_text("utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.warning("key store unreadable; treating as empty")
        return {}


def _write_store(data: dict) -> None:
    _STORE_DIR.mkdir(parents=True, exist_ok=True)
    _STORE_FILE.write_text(json.dumps(data, indent=2), "utf-8")
    try:
        _STORE_FILE.chmod(0o600)
    except OSError:
        pass


def set_key(provider: str, api_key: str) -> None:
    if not api_key:
        raise ValueError("api_key must be non-empty")
    store = _read_store()
    store[provider.lower()] = _encrypt(api_key)
    _write_store(store)
    logger.info("stored api key for provider %s (encrypted)", provider)


def get_key(provider: str) -> Optional[str]:
    store = _read_store()
    token = store.get(provider.lower())
    if not token:
        return None
    try:
        return _decrypt(token)
    except Exception:
        logger.warning("decrypt failed for %s; treating as missing", provider)
        return None


def list_providers() -> list[str]:
    return list(_read_store().keys())


def delete_key(provider: str) -> bool:
    store = _read_store()
    removed = store.pop(provider.lower(), None) is not None
    if removed:
        _write_store(store)
    return removed


def clear_all() -> int:
    n = len(_read_store())
    _write_store({})
    return n


def looks_like_secret_file(path: str | Path) -> bool:
    p = Path(path)
    name = p.name.lower()
    if any(pat in name for pat in SECRET_FILE_PATTERNS):
        return True
    return any(name.endswith(suf) for suf in SECRET_FILE_SUFFIXES)
