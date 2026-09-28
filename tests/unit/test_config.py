import base64

import pytest
from pydantic import ValidationError

from postroom.config import Settings
from postroom.crypto import hash_password

KEY = base64.b64encode(bytes(range(32))).decode()


def test_derived_urls(settings):
    assert settings.mcp_url == "http://testserver/mcp"
    assert settings.google_redirect_uri == "http://testserver/admin/google/callback"
    assert settings.public_host == "testserver"
    assert settings.secure_cookies is False
    assert settings.google_enabled is True


def test_env_prefix(monkeypatch):
    monkeypatch.setenv("POSTROOM_PUBLIC_URL", "https://imap-mcp.example.com/")
    monkeypatch.setenv("POSTROOM_MASTER_KEY", KEY)
    monkeypatch.setenv("POSTROOM_SESSION_SECRET", "y")
    s = Settings()
    assert s.mcp_url == "https://imap-mcp.example.com/mcp"
    assert s.secure_cookies is True
    assert s.public_host == "imap-mcp.example.com"
    assert s.google_enabled is False


def test_time_zone_defaults_to_utc(settings):
    assert settings.timezone == "UTC" and settings.tz.key == "UTC"


def test_time_zone_from_env(monkeypatch):
    monkeypatch.setenv("POSTROOM_MASTER_KEY", KEY)
    monkeypatch.setenv("POSTROOM_SESSION_SECRET", "y")
    monkeypatch.setenv("POSTROOM_TIMEZONE", " Asia/Tokyo ")
    s = Settings()
    assert s.timezone == "Asia/Tokyo" and s.tz.key == "Asia/Tokyo"


@pytest.mark.parametrize("value", ["Mars/Olympus", "", "../etc/passwd", "/etc/localtime", "Europe"])
def test_invalid_time_zone_is_a_clear_config_error(monkeypatch, value):
    monkeypatch.setenv("POSTROOM_MASTER_KEY", KEY)
    monkeypatch.setenv("POSTROOM_SESSION_SECRET", "y")
    monkeypatch.setenv("POSTROOM_TIMEZONE", value)
    with pytest.raises(ValidationError) as e:
        Settings()
    assert "IANA time zone" in str(e.value)


def _env(monkeypatch, **values):
    monkeypatch.setenv("POSTROOM_MASTER_KEY", KEY)
    monkeypatch.setenv("POSTROOM_SESSION_SECRET", "y")
    for name, value in values.items():
        monkeypatch.setenv(f"POSTROOM_{name.upper()}", value)


@pytest.mark.parametrize(
    "value",
    ["abc", "", "x" * 44, base64.b64encode(bytes(16)).decode(), KEY[:-4], f'"{KEY}"'],
)
def test_malformed_master_key_is_a_config_error(monkeypatch, value):
    _env(monkeypatch, master_key=value)
    with pytest.raises(ValidationError, match="must be 32 random bytes in base64"):
        Settings()


def test_master_key_is_accepted_with_surrounding_space(monkeypatch):
    _env(monkeypatch, master_key=f" {KEY}\n")
    assert Settings().master_key == KEY


def test_admin_hash_accepts_empty_and_a_real_hash(monkeypatch):
    _env(monkeypatch)
    assert Settings().admin_password_hash_b64 == ""
    good = base64.b64encode(hash_password("pw").encode()).decode()
    _env(monkeypatch, admin_password_hash_b64=good)
    assert Settings().admin_password_hash_b64 == good


@pytest.mark.parametrize(
    "make",
    [
        lambda h: h[:20],  # truncated
        lambda h: f"'{h}'",  # quotes left in
        lambda h: base64.b64encode(b"my-plain-password").decode(),  # base64 of the password
        lambda h: base64.b64encode(hash_password("pw").encode()[:40]).decode(),  # cut hash
        lambda h: hash_password("pw"),  # the hash itself, not base64
    ],
)
def test_malformed_admin_hash_is_a_config_error(monkeypatch, make):
    value = make(base64.b64encode(hash_password("pw").encode()).decode())
    _env(monkeypatch, admin_password_hash_b64=value)
    with pytest.raises(ValidationError, match="is not a base64-encoded argon2 hash"):
        Settings()


@pytest.mark.parametrize("value", ["nonsense", "10.0.0.0/8,bogus", "300.1.1.1", "::1/200"])
def test_malformed_trusted_proxies_is_a_config_error(monkeypatch, value):
    _env(monkeypatch, trusted_proxies=value)
    with pytest.raises(ValidationError, match="IP addresses or networks"):
        Settings()


def test_trusted_proxies_accepts_addresses_and_networks(monkeypatch):
    _env(monkeypatch, trusted_proxies=" 172.16.0.0/12, ::1 ,10.1.2.3/8,")
    assert [str(n) for n in Settings().trusted_proxy_networks] == [
        "172.16.0.0/12",
        "::1/128",
        "10.0.0.0/8",
    ]
