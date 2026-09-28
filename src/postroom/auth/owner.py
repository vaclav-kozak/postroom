"""Owner (admin) authentication: password check, login lockout, signed session cookie, CSRF.

The owner is the only human user. The session is a signed, timestamped cookie
(`itsdangerous`), valid for 12 h. It also carries the DB's session version: logout bumps that
version, which invalidates every outstanding session cookie (copies included). The cookie
signature is also bound to the current admin password hash, so changing the password (new hash
in .env + restart) ends every existing session. Every state-changing POST carries a CSRF token:
the session's token once logged in, or a token bound to the signed pre-login cookie on /login.
"""

import base64
import binascii
import hashlib
import hmac
import math
import secrets
import time
from collections.abc import Callable

from itsdangerous import BadSignature, URLSafeTimedSerializer
from starlette.requests import HTTPConnection
from starlette.responses import Response

from postroom.config import Settings
from postroom.crypto import verify_password
from postroom.db import Database

SESSION_COOKIE = "postroom_session"
SESSION_MAX_AGE = 12 * 3600
PRE_COOKIE = "postroom_pre"
PRE_MAX_AGE = 3600

IP_MAX_FAILURES = 5
IP_WINDOW = 15 * 60
GLOBAL_MAX_FAILURES = 20
GLOBAL_WINDOW = 60 * 60
ATTEMPT_RETENTION = 86400


class LoginGuard:
    """Login lockout: 5 failures / 15 min per IP, 20 failures / 60 min globally.

    A block lasts until the oldest failure that triggered it leaves the window, i.e. until the
    N-th newest failure + window. A successful login does not erase failures.
    """

    def __init__(self, db: Database, clock: Callable[[], float] = time.time):
        self.db = db
        self._db = db
        self._clock = clock

    def _remaining(self, now: float, window: int, limit: int, ip: str | None) -> int:
        sql = "SELECT at FROM login_attempts WHERE ok = 0 AND at > ?"
        params: list = [now - window]
        if ip is not None:
            sql += " AND ip = ?"
            params.append(ip)
        sql += " ORDER BY at DESC LIMIT 1 OFFSET ?"
        params.append(limit - 1)
        row = self._db.one(sql, params)
        if row is None:
            return 0
        return max(0, math.ceil(row["at"] + window - now))

    def blocked_for(self, ip: str) -> int:
        now = self._clock()
        return max(
            self._remaining(now, IP_WINDOW, IP_MAX_FAILURES, ip),
            self._remaining(now, GLOBAL_WINDOW, GLOBAL_MAX_FAILURES, None),
        )

    def record(self, ip: str, ok: bool) -> None:
        now = self._clock()
        with self._db.transaction():
            self._db.execute(
                "DELETE FROM login_attempts WHERE at < ?", (int(now) - ATTEMPT_RETENTION,)
            )
            self._db.execute(
                "INSERT INTO login_attempts(ip, at, ok) VALUES (?, ?, ?)",
                (ip, int(now), int(ok)),
            )


def client_ip(request) -> str:
    """The client's IP: `X-Real-IP` (set by nginx; the container is reachable only through it),
    else the socket peer, else "unknown". Truncated so it is safe as a DB key / log field."""
    ip = request.headers.get("x-real-ip")
    if not ip and request.client is not None:
        ip = request.client.host
    ip = (ip or "").strip()[:64]
    return ip if ip and ip.isprintable() else "unknown"


def safe_next(value: str | None) -> str:
    """Only same-origin absolute paths are allowed as post-login targets."""
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return "/admin"


class OwnerAuth:
    def __init__(self, settings: Settings, guard: LoginGuard, db: Database | None = None):
        self.settings = settings
        self.guard = guard
        self._db = db if db is not None else guard.db
        self._password_hash = self._decode_hash(settings.admin_password_hash_b64)
        # The session signature depends on the password hash: a new password ends all sessions.
        fingerprint = hashlib.sha256(self._password_hash.encode()).hexdigest()[:32]
        self._session = URLSafeTimedSerializer(
            settings.session_secret, salt=f"postroom-session:{fingerprint}"
        )
        self._pre = URLSafeTimedSerializer(settings.session_secret, salt="postroom-pre")

    @staticmethod
    def _decode_hash(value: str) -> str:
        if not value:
            return ""
        try:
            return base64.b64decode(value, validate=True).decode()
        except (binascii.Error, ValueError):
            return ""

    # ----- password ---------------------------------------------------------------------------

    def check_password(self, password: str) -> bool:
        if not self._password_hash:
            return False
        return verify_password(self._password_hash, password)

    # ----- session ----------------------------------------------------------------------------

    def session(self, request: HTTPConnection) -> dict | None:
        raw = request.cookies.get(SESSION_COOKIE)
        if not raw:
            return None
        try:
            data = self._session.loads(raw, max_age=SESSION_MAX_AGE)
        except BadSignature:  # includes SignatureExpired
            return None
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("sid"), str)
            or not isinstance(data.get("csrf"), str)
            or not data["csrf"]
            or data.get("v") != self.session_version()
        ):
            return None
        return data

    def session_version(self) -> int:
        row = self._db.one("SELECT session_version FROM owner_state WHERE id=1")
        return row[0] if row is not None else 0

    def revoke_sessions(self) -> None:
        """Server-side logout: every session cookie issued so far stops working."""
        self._db.execute("UPDATE owner_state SET session_version = session_version + 1 WHERE id=1")

    def is_owner(self, request: HTTPConnection) -> bool:
        return self.session(request) is not None

    def _set_cookie(self, response: Response, key: str, value: str, max_age: int) -> None:
        response.set_cookie(
            key,
            value,
            max_age=max_age,
            path="/",
            secure=self.settings.secure_cookies,
            httponly=True,
            samesite="lax",
        )

    def start_session(self, response: Response) -> None:
        payload = {
            "sid": secrets.token_urlsafe(16),
            "csrf": secrets.token_urlsafe(32),
            "v": self.session_version(),
        }
        self._set_cookie(response, SESSION_COOKIE, self._session.dumps(payload), SESSION_MAX_AGE)

    def end_session(self, response: Response) -> None:
        response.delete_cookie(
            SESSION_COOKIE,
            path="/",
            secure=self.settings.secure_cookies,
            httponly=True,
            samesite="lax",
        )

    # ----- CSRF -------------------------------------------------------------------------------

    def _pre_token(self, request: HTTPConnection) -> str:
        raw = request.cookies.get(PRE_COOKIE)
        if not raw:
            return ""
        try:
            token = self._pre.loads(raw, max_age=PRE_MAX_AGE)
        except BadSignature:
            return ""
        return token if isinstance(token, str) else ""

    def ensure_pre_token(self, request: HTTPConnection, response: Response) -> str:
        token = self._pre_token(request)
        if not token:
            token = secrets.token_urlsafe(32)
        # (Re)issue on every login page view so the cookie's max-age restarts with the form.
        self._set_cookie(response, PRE_COOKIE, self._pre.dumps(token), PRE_MAX_AGE)
        return token

    def clear_pre_token(self, response: Response) -> None:
        response.delete_cookie(
            PRE_COOKIE,
            path="/",
            secure=self.settings.secure_cookies,
            httponly=True,
            samesite="lax",
        )

    def csrf_token(self, request: HTTPConnection) -> str:
        session = self.session(request)
        if session is not None:
            return session["csrf"]
        return self._pre_token(request)

    def check_csrf(self, request: HTTPConnection, form_value: str | None) -> bool:
        expected = self.csrf_token(request)
        if not expected or not isinstance(form_value, str) or not form_value:
            return False
        return hmac.compare_digest(expected.encode(), form_value.encode())
