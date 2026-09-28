import pytest
from pydantic import ValidationError

from postroom.config import Settings


def test_derived_urls(settings):
    assert settings.mcp_url == "http://testserver/mcp"
    assert settings.google_redirect_uri == "http://testserver/admin/google/callback"
    assert settings.public_host == "testserver"
    assert settings.secure_cookies is False
    assert settings.google_enabled is True


def test_env_prefix(monkeypatch):
    monkeypatch.setenv("POSTROOM_PUBLIC_URL", "https://imap-mcp.example.com/")
    monkeypatch.setenv("POSTROOM_MASTER_KEY", "x")
    monkeypatch.setenv("POSTROOM_SESSION_SECRET", "y")
    s = Settings()
    assert s.mcp_url == "https://imap-mcp.example.com/mcp"
    assert s.secure_cookies is True
    assert s.public_host == "imap-mcp.example.com"
    assert s.google_enabled is False


def test_time_zone_defaults_to_utc(settings):
    assert settings.timezone == "UTC" and settings.tz.key == "UTC"


def test_time_zone_from_env(monkeypatch):
    monkeypatch.setenv("POSTROOM_MASTER_KEY", "x")
    monkeypatch.setenv("POSTROOM_SESSION_SECRET", "y")
    monkeypatch.setenv("POSTROOM_TIMEZONE", " Asia/Tokyo ")
    s = Settings()
    assert s.timezone == "Asia/Tokyo" and s.tz.key == "Asia/Tokyo"


@pytest.mark.parametrize("value", ["Mars/Olympus", "", "../etc/passwd", "/etc/localtime", "Europe"])
def test_invalid_time_zone_is_a_clear_config_error(monkeypatch, value):
    monkeypatch.setenv("POSTROOM_MASTER_KEY", "x")
    monkeypatch.setenv("POSTROOM_SESSION_SECRET", "y")
    monkeypatch.setenv("POSTROOM_TIMEZONE", value)
    with pytest.raises(ValidationError) as e:
        Settings()
    assert "IANA time zone" in str(e.value)
