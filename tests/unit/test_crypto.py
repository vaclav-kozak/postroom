import base64
import hashlib

import pytest

from postroom import crypto


def test_secretbox_roundtrip_and_aad():
    box = crypto.SecretBox(crypto.generate_key())
    blob = box.encrypt("hunter2", aad="account:a@b.example.net")
    assert b"hunter2" not in blob
    assert box.decrypt(blob, aad="account:a@b.example.net") == "hunter2"
    with pytest.raises(crypto.SecretError):
        box.decrypt(blob, aad="account:other@b.example.net")


def test_secretbox_rejects_bad_key():
    with pytest.raises(ValueError):
        crypto.SecretBox(base64.b64encode(b"short").decode())


def test_nonce_is_random():
    box = crypto.SecretBox(crypto.generate_key())
    assert box.encrypt("x", "a") != box.encrypt("x", "a")


def test_hash_token_is_sha256_hex():
    assert crypto.hash_token("abc") == hashlib.sha256(b"abc").hexdigest()


def test_new_token_prefix_and_entropy():
    t = crypto.new_token("prm_")
    assert t.startswith("prm_") and len(t) > 40
    assert crypto.new_token() != crypto.new_token()


def test_password_hash_verify():
    h = crypto.hash_password("correct horse")
    assert h.startswith("$argon2id$")
    assert crypto.verify_password(h, "correct horse")
    assert not crypto.verify_password(h, "wrong")
    assert not crypto.verify_password("", "anything")
    assert not crypto.verify_password("garbage", "anything")


def test_pkce_pair():
    verifier, challenge = crypto.pkce_pair()
    digest = hashlib.sha256(verifier.encode()).digest()
    assert challenge == base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def test_random_password():
    p = crypto.random_password(32)
    assert len(p) == 32 and p.isascii()
