"""Which CalDAV/CardDAV URLs may be given the mailbox password.

Both backends send the account's IMAP/SOGo password (the full-access mailbox credential)
as HTTP Basic auth, so the URL must be https. Plain http is allowed only for loopback
hosts (local test servers). Same rule as the admin form.
"""

from urllib.parse import urlsplit

from postroom.pim.models import PimError

LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")
INSECURE_URL = "CalDAV/CardDAV URL must use https (http only on localhost)"


def dav_url_ok(url: str | None) -> bool:
    try:
        parts = urlsplit(url or "")
        host = parts.hostname
    except ValueError:
        return False
    if not host:
        return False
    scheme = parts.scheme.lower()
    return scheme == "https" or (scheme == "http" and host in LOOPBACK_HOSTS)


def require_dav_url(url: str) -> str:
    """`url`, or a `PimError` when the password must not be sent to it."""
    if not dav_url_ok(url):
        raise PimError(INSECURE_URL)
    return url
