"""Google OAuth client: consent URL, authorization-code exchange, token refresh, revoke.

The Google refresh token is stored as the account's encrypted secret (`AccountRepo`).
Access tokens live only in memory, cached per account until 60 s before they expire.

Secrets hygiene: no method here logs, stores in an exception message, or otherwise
exposes the client secret, a refresh token or an access token. Error messages carry
only Google's `error` code and the HTTP status, never request or response bodies.
"""

import base64
import binascii
import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from postroom.accounts import AccountRepo, AccountStatus
from postroom.config import Settings
from postroom.mail.imap import AuthFailed

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"

GMAIL_SCOPE = "https://mail.google.com/"
GOOGLE_SCOPES: list[str] = [
    "openid",
    "email",
    GMAIL_SCOPE,
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/tasks",
    "https://www.googleapis.com/auth/contacts.readonly",
    "https://www.googleapis.com/auth/contacts.other.readonly",
]

# Refresh this many seconds before Google's stated expiry.
EXPIRY_MARGIN_SECONDS = 60

REVOKED_MESSAGE = "Google access revoked or expired — reconnect"


@dataclass
class GoogleGrant:
    email: str
    refresh_token: str
    scopes: list[str]


class GoogleOAuthError(Exception):
    """A Google OAuth call failed. The message is safe to show to the owner (no secrets)."""


def _error_code(resp: httpx.Response) -> str:
    """Google's short `error` code from a token-endpoint error response (never the body)."""
    try:
        code = resp.json().get("error")
    except (ValueError, AttributeError):
        return ""
    return code[:64] if isinstance(code, str) else ""


def _decode_id_token(id_token: str) -> dict:
    """Decode the payload of a JWT without verifying its signature.

    Safe here only because the token came straight from Google's token endpoint over
    TLS in response to our own authenticated request; it is never accepted from a client.
    """
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError, binascii.Error) as e:
        raise GoogleOAuthError("Google returned a malformed id_token") from e
    if not isinstance(claims, dict):
        raise GoogleOAuthError("Google returned a malformed id_token")
    return claims


class GoogleOAuth:
    def __init__(
        self,
        settings: Settings,
        repo: AccountRepo,
        http: httpx.Client | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self._settings = settings
        self._repo = repo
        self._http = http or httpx.Client(timeout=20)
        self._clock = clock
        # email -> (access_token, expires_at). Guarded by `_lock`.
        self._cache: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()
        # Per-account refresh locks: concurrent callers for the same account wait for a
        # single refresh instead of each hitting Google; other accounts are not blocked.
        self._refresh_locks: dict[str, threading.Lock] = {}

    # -- consent ----------------------------------------------------------------

    def authorization_url(
        self, state: str, code_challenge: str, login_hint: str | None = None
    ) -> str:
        params = {
            "client_id": self._settings.google_client_id,
            "redirect_uri": self._settings.google_redirect_uri,
            "response_type": "code",
            "scope": " ".join(GOOGLE_SCOPES),
            "access_type": "offline",
            "prompt": "consent",
            "include_granted_scopes": "true",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if login_hint:
            params["login_hint"] = login_hint
        return f"{AUTH_URL}?{urlencode(params)}"

    def _post_token(self, data: dict, what: str) -> httpx.Response:
        try:
            return self._http.post(TOKEN_URL, data=data)
        except httpx.HTTPError as e:
            raise GoogleOAuthError(
                f"Google {what} failed: token endpoint unreachable ({type(e).__name__})"
            ) from e

    def exchange_code(self, code: str, code_verifier: str) -> GoogleGrant:
        resp = self._post_token(
            {
                "code": code,
                "client_id": self._settings.google_client_id,
                "client_secret": self._settings.google_client_secret,
                "redirect_uri": self._settings.google_redirect_uri,
                "grant_type": "authorization_code",
                "code_verifier": code_verifier,
            },
            "code exchange",
        )
        if resp.status_code != 200:
            code_str = _error_code(resp)
            detail = f" ({code_str})" if code_str else ""
            raise GoogleOAuthError(f"Google code exchange failed: HTTP {resp.status_code}{detail}")
        try:
            body = resp.json()
        except ValueError as e:
            raise GoogleOAuthError("Google code exchange returned a non-JSON response") from e
        if not isinstance(body, dict):
            raise GoogleOAuthError("Google code exchange returned an invalid response")

        refresh_token = body.get("refresh_token")
        id_token = body.get("id_token")
        if not refresh_token:
            raise GoogleOAuthError(
                "Google did not return a refresh token — remove the app's access in your "
                "Google account settings and connect again"
            )
        if not id_token:
            raise GoogleOAuthError("Google did not return an id_token")

        claims = _decode_id_token(id_token)
        email = claims.get("email")
        verified = claims.get("email_verified")
        if not isinstance(email, str) or not email.strip():
            raise GoogleOAuthError("Google id_token has no email address")
        if verified is not True and str(verified).lower() != "true":
            raise GoogleOAuthError("Google account email address is not verified")

        scopes = str(body.get("scope") or "").split()
        if GMAIL_SCOPE not in scopes:
            raise GoogleOAuthError(
                "Gmail access was not granted — connect again and allow access to Gmail "
                "on Google's consent screen"
            )

        return GoogleGrant(email=email.strip().lower(), refresh_token=refresh_token, scopes=scopes)

    # -- access tokens -------------------------------------------------------

    def _refresh_lock(self, email: str) -> threading.Lock:
        with self._lock:
            lock = self._refresh_locks.get(email)
            if lock is None:
                lock = self._refresh_locks[email] = threading.Lock()
            return lock

    def _cached(self, email: str) -> str | None:
        with self._lock:
            entry = self._cache.get(email)
        if entry is not None and self._clock() < entry[1] - EXPIRY_MARGIN_SECONDS:
            return entry[0]
        return None

    def access_token(self, email: str) -> str:
        """Return a valid access token for `email`, refreshing it when needed.

        Raises `AuthFailed` when the account must be reconnected (no stored refresh
        token, or Google answered `invalid_grant`), and `GoogleOAuthError` for any
        other failure (network, 5xx, misconfigured client).
        """
        email = email.strip().lower()
        token = self._cached(email)
        if token is not None:
            return token

        with self._refresh_lock(email):
            token = self._cached(email)  # another thread may have refreshed meanwhile
            if token is not None:
                return token

            refresh_token = self._repo.get_secret(email)
            if not refresh_token:
                raise AuthFailed("no Google refresh token stored — connect the account")

            requested_at = self._clock()
            resp = self._post_token(
                {
                    "client_id": self._settings.google_client_id,
                    "client_secret": self._settings.google_client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                },
                "token refresh",
            )

            if resp.status_code != 200:
                code_str = _error_code(resp)
                if resp.status_code == 400 and code_str == "invalid_grant":
                    self.invalidate(email)
                    self._repo.set_status(email, AccountStatus.NEEDS_RECONNECT, REVOKED_MESSAGE)
                    raise AuthFailed(REVOKED_MESSAGE)
                detail = f" ({code_str})" if code_str else ""
                raise GoogleOAuthError(
                    f"Google token refresh failed: HTTP {resp.status_code}{detail}"
                )

            try:
                body = resp.json()
                access = body["access_token"]
                expires_in = float(body.get("expires_in", 3600))
            except (ValueError, KeyError, TypeError) as e:
                raise GoogleOAuthError("Google token refresh returned an invalid response") from e
            if not isinstance(access, str) or not access:
                raise GoogleOAuthError("Google token refresh returned an invalid response")

            # Google may rotate the refresh token; keep the newest one.
            new_refresh = body.get("refresh_token")
            if isinstance(new_refresh, str) and new_refresh and new_refresh != refresh_token:
                self._repo.set_secret(email, new_refresh)

            with self._lock:
                self._cache[email] = (access, requested_at + expires_in)
            return access

    def invalidate(self, email: str) -> None:
        with self._lock:
            self._cache.pop(email.strip().lower(), None)

    def revoke(self, refresh_token: str) -> None:
        """Best-effort revoke of a refresh token at Google. Never raises."""
        try:
            self._http.post(REVOKE_URL, data={"token": refresh_token})
        except Exception:  # noqa: BLE001, S110 -- best effort; the grant is dropped locally anyway
            pass
