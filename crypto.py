"""
Thin Fernet wrapper. Only the execution proxy calls decrypt() -- nowhere else.
The key comes from FERNET_KEY env var; the server refuses to start without it
(see startup check in main.py) so there's no silent fallback to plaintext.

To generate a key (run once, store in your .env or secrets manager):
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

import os

from cryptography.fernet import Fernet

_fernet: Fernet | None = None


def init_crypto() -> None:
    """Call at app startup. Raises immediately if FERNET_KEY is missing/invalid."""
    global _fernet
    key = os.environ.get("FERNET_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "FERNET_KEY environment variable is not set.\n"
            "Generate one with:\n"
            "  python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"\n"
            "Then set it: set FERNET_KEY=<key>  (Windows) or export FERNET_KEY=<key>  (Linux/Mac)"
        )
    _fernet = Fernet(key.encode())


def _get() -> Fernet:
    if _fernet is None:
        raise RuntimeError("crypto not initialized -- init_crypto() must run at startup")
    return _fernet


def encrypt(plaintext: str) -> bytes:
    return _get().encrypt(plaintext.encode())


def decrypt(ciphertext: bytes) -> str:
    return _get().decrypt(ciphertext).decode()