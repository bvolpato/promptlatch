from __future__ import annotations

import base64
import os
import secrets
import tempfile
import warnings
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_FILE_MODE = 0o600


def generate_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def load_key(key_file: Path) -> bytes:
    env_key = os.getenv("PROMPTLATCH_CONFIG_KEY")
    if env_key is None and "PROMPTCLOAK_CONFIG_KEY" in os.environ:
        warnings.warn(
            "PROMPTCLOAK_CONFIG_KEY is deprecated; use PROMPTLATCH_CONFIG_KEY",
            FutureWarning,
            stacklevel=2,
        )
        env_key = os.environ["PROMPTCLOAK_CONFIG_KEY"]
    raw = env_key or key_file.read_text(encoding="utf-8").strip()
    return base64.urlsafe_b64decode(raw)


def write_key_file(key_file: Path) -> str:
    key = generate_key()
    write_private_text(key_file, key + "\n")
    return key


def write_private_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            os.fchmod(handle.fileno(), KEY_FILE_MODE)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def encrypt_text(plaintext: str, key: bytes) -> str:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_text(ciphertext: str, key: bytes) -> str:
    payload = base64.urlsafe_b64decode(ciphertext)
    nonce, encrypted = payload[:12], payload[12:]
    return AESGCM(key).decrypt(nonce, encrypted, None).decode("utf-8")
