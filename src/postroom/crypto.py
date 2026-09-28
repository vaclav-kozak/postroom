import base64
import hashlib
import os
import secrets
import string

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_ph = PasswordHasher()


class SecretError(Exception):
    """Secret could not be decrypted (wrong key, wrong AAD or tampered blob)."""


class SecretBox:
    def __init__(self, key_b64: str):
        key = base64.b64decode(key_b64)
        if len(key) != 32:
            raise ValueError("master key must be 32 bytes (base64-encoded)")
        self._aead = AESGCM(key)

    def encrypt(self, plaintext: str, aad: str) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext.encode(), aad.encode())

    def decrypt(self, blob: bytes, aad: str) -> str:
        try:
            return self._aead.decrypt(blob[:12], blob[12:], aad.encode()).decode()
        except (InvalidTag, ValueError) as e:
            raise SecretError("cannot decrypt secret") from e


def generate_key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token(prefix: str = "") -> str:
    return prefix + secrets.token_urlsafe(32)


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(hash_: str, password: str) -> bool:
    if not hash_:
        return False
    try:
        return _ph.verify(hash_, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def random_password(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))
