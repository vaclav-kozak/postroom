from urllib.parse import urlparse

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="POSTROOM_", extra="ignore")

    public_url: str = "http://localhost:8000"
    db_path: str = "./data/postroom.db"
    master_key: str
    session_secret: str
    admin_password_hash_b64: str = ""
    google_client_id: str = ""
    google_client_secret: str = ""
    check_interval_seconds: int = 21600
    # Hosts (exact match, no implicit subdomains) that OAuth clients may register https
    # redirect URIs on.
    # Claude uses https://claude.ai/api/mcp/auth_callback and may move to claude.com.
    oauth_redirect_hosts: str = "claude.ai,claude.com"

    @property
    def redirect_hosts(self) -> tuple[str, ...]:
        hosts = (h.strip().lower() for h in self.oauth_redirect_hosts.split(","))
        return tuple(h for h in hosts if h)

    @property
    def base_url(self) -> str:
        return self.public_url.rstrip("/")

    @property
    def public_host(self) -> str:
        return urlparse(self.base_url).netloc

    @property
    def secure_cookies(self) -> bool:
        return self.base_url.startswith("https://")

    @property
    def mcp_url(self) -> str:
        return f"{self.base_url}/mcp"

    @property
    def google_redirect_uri(self) -> str:
        return f"{self.base_url}/admin/google/callback"

    @property
    def google_enabled(self) -> bool:
        return bool(self.google_client_id and self.google_client_secret)
