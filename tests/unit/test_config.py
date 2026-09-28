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
