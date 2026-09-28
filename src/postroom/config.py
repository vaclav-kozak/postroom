from ipaddress import IPv4Network, IPv6Network, ip_network
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import field_validator
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
    # Per-client-IP limit for /login, /register, /authorize and /token (burst 10); 0 disables.
    auth_rate_limit_per_minute: int = 10
    # Comma-separated IPs/CIDRs of reverse proxies whose X-Forwarded-For / X-Real-IP /
    # X-Forwarded-Proto headers are believed. From any other peer these headers are dropped.
    trusted_proxies: str = "127.0.0.1,::1"
    # Emails one account may send per hour (send_email, forward_email, send_draft); 0 = no limit.
    send_limit_per_hour: int = 60
    # IANA time zone (e.g. Europe/Berlin, America/New_York) for date-times given without a
    # UTC offset, for new calendar events and for the times the admin UI shows.
    timezone: str = "UTC"

    @field_validator("timezone")
    @classmethod
    def _valid_timezone(cls, value: str) -> str:
        value = value.strip()
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            raise ValueError(
                f"must be an IANA time zone name such as UTC, "
                f"Europe/Berlin or America/New_York, got {value[:64]!r}"
            ) from None
        return value

    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    @property
    def redirect_hosts(self) -> tuple[str, ...]:
        hosts = (h.strip().lower() for h in self.oauth_redirect_hosts.split(","))
        return tuple(h for h in hosts if h)

    @property
    def trusted_proxy_networks(self) -> tuple[IPv4Network | IPv6Network, ...]:
        items = (p.strip() for p in self.trusted_proxies.split(","))
        return tuple(ip_network(p, strict=False) for p in items if p)

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
