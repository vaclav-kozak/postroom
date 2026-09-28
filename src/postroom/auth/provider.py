"""OAuth 2.1 authorization server for the MCP endpoint, plus owner-issued API keys.

This is the lock on the owner's mailboxes. Invariants:
- Codes, access/refresh tokens and API keys are stored only as SHA-256 hashes; plaintext is
  returned exactly once and never logged.
- Every load enforces expiry; codes are single-use (atomic delete), and presenting a used code
  again revokes the token family it produced; refresh tokens rotate and replaying a rotated one
  revokes its whole family.
- Clients may register https redirect URIs only on the allowed hosts (`POSTROOM_OAUTH_REDIRECT_HOSTS`,
  exact match) or http ones on loopback; the client table is bounded (never-tokened clients are
  evicted).
- Everything a stranger can store (DCR metadata, pending /authorize requests) is size-bounded:
  only the client fields this server uses are kept, and oversized values are rejected.
- Access tokens are accepted only for this server's own resource (RFC 8707 audience).
- Nothing is granted without the owner approving it on /consent (`approve`).
"""

import hmac
import json
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlparse

from fastmcp.server.auth.auth import ClientRegistrationOptions, OAuthProvider, RevocationOptions
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.transport_security import RequestBodyLimitMiddleware
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.routing import Route

from postroom.config import Settings
from postroom.crypto import hash_token, new_token
from postroom.db import Database

log = logging.getLogger(__name__)

ACCESS_TTL = 3600
REFRESH_TTL = 30 * 86400
CODE_TTL = 300
PENDING_TTL = 600
MAX_CLIENTS = 500
# /authorize is unauthenticated: bound its storage per client (oldest pending rows are evicted).
MAX_PENDING_PER_CLIENT = 20
STALE_CLIENT_SECONDS = 30 * 86400
# A registered client that never obtained a token is dropped after a day.
UNUSED_CLIENT_SECONDS = 86400
SCOPE = "mcp"
API_KEY_PREFIX = "prm_"
SUBJECT = "owner"
TOUCH_INTERVAL = 60  # last_used_at is written at most once a minute
EXPIRED_GRACE = 86400  # purge keeps expired tokens a day (reuse detection / diagnostics)

# Bounds on what the unauthenticated /register and /authorize endpoints can make us store.
OAUTH_MAX_BODY = 16 * 1024  # request body of /register, /authorize, /token, /revoke
MAX_CLIENT_NAME = 200
MAX_REDIRECT_URIS = 5
MAX_REDIRECT_URI_LEN = 2000
MAX_STATE_LEN = 1000
_BODY_LIMITED_PATHS = frozenset({"/register", "/authorize", "/token", "/revoke"})
_GRANT_TYPES = ("authorization_code", "refresh_token")
# RFC 7636 §4.2: an S256 challenge is BASE64URL(SHA-256(verifier)) without padding.
_S256_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")
# DCR metadata this server never uses; dropped before storing (RFC 7591 §3.2.1 lets the
# server omit or replace requested values).
_UNUSED_CLIENT_FIELDS = (
    "client_uri",
    "logo_uri",
    "contacts",
    "tos_uri",
    "policy_uri",
    "jwks_uri",
    "jwks",
    "software_id",
    "software_version",
    "issuer",
)

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass
class ClientRow:
    client_id: str
    client_name: str | None
    redirect_hosts: list[str]
    created_at: int
    last_used_at: int | None
    active_tokens: int


@dataclass
class ApiKeyRow:
    id: int
    name: str
    prefix: str
    created_at: int
    last_used_at: int | None
    revoked: bool


def _redirect_uri_allowed(uri: str, allowed_hosts: tuple[str, ...]) -> bool:
    """https to exactly an allowed host (no implicit subdomains), or plain http only to a
    loopback host (RFC 8252 §7.3, e.g. Claude Code); never a fragment."""
    try:
        parts = urlparse(uri)
        host = parts.hostname
    except ValueError:
        return False
    if not host or parts.fragment:
        return False
    if parts.scheme == "https":
        return host in allowed_hosts
    return parts.scheme == "http" and host in _LOOPBACK_HOSTS


def _clamp_client_metadata(info: OAuthClientInformationFull) -> None:
    """Bound a DCR request before it is stored: reject oversized values, drop unused fields and
    normalise the list fields to what this server supports. Mutates `info` in place, so the
    registration response echoes exactly what was stored."""
    uris = info.redirect_uris or []
    if info.client_name is not None and len(info.client_name) > MAX_CLIENT_NAME:
        raise RegistrationError(
            "invalid_client_metadata", f"client_name is longer than {MAX_CLIENT_NAME} characters"
        )
    if len(uris) > MAX_REDIRECT_URIS:
        raise RegistrationError(
            "invalid_client_metadata", f"at most {MAX_REDIRECT_URIS} redirect URIs are allowed"
        )
    if any(len(str(uri)) > MAX_REDIRECT_URI_LEN for uri in uris):
        raise RegistrationError(
            "invalid_client_metadata",
            f"redirect URIs must be at most {MAX_REDIRECT_URI_LEN} characters",
        )
    for field in _UNUSED_CLIENT_FIELDS:
        setattr(info, field, None)
    # The SDK already checked that the scope is a subset of ours and that the lists contain
    # "authorization_code" and "code"; only their (unbounded) repetitions and extras remain.
    info.scope = SCOPE
    info.grant_types = [g for g in _GRANT_TYPES if g in info.grant_types]
    info.response_types = ["code"]


def _new_oauth_token() -> str:
    # load_access_token routes on the API-key prefix, so an OAuth token must never carry it.
    while (token := new_token()).startswith(API_KEY_PREFIX):
        continue
    return token


def _hash_matches(stored: str, computed: str) -> bool:
    return hmac.compare_digest(stored.encode(), computed.encode())


def _split_scopes(value: str) -> list[str]:
    return value.split()


class PostroomOAuthProvider(OAuthProvider):
    def __init__(self, settings: Settings, db: Database, clock: Callable[[], float] = time.time):
        super().__init__(
            base_url=settings.base_url,
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]
            ),
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=None,
        )
        self._settings = settings
        self._db = db
        self._clock = clock
        self._resources = frozenset(
            {
                settings.mcp_url,
                settings.mcp_url + "/",
                settings.base_url,
                settings.base_url + "/",
            }
        )

    def _now(self) -> int:
        return int(self._clock())

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        # The SDK caps these unauthenticated endpoints at 4 MiB; their legitimate bodies are a
        # few hundred bytes, so cap them far lower (413) before anything is parsed.
        routes = super().get_routes(mcp_path)
        for route in routes:
            if isinstance(route, Route) and route.path in _BODY_LIMITED_PATHS:
                route.app = RequestBodyLimitMiddleware(route.app, OAUTH_MAX_BODY)
        return routes

    # ----- clients ---------------------------------------------------------------------------

    def _client_info(self, client_id: str) -> OAuthClientInformationFull | None:
        row = self._db.one("SELECT info_json FROM oauth_clients WHERE client_id=?", (client_id,))
        return OAuthClientInformationFull.model_validate_json(row[0]) if row else None

    def _client_count(self) -> int:
        return self._db.one("SELECT count(*) FROM oauth_clients")[0]

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        now = self._now()
        self._db.execute(
            "UPDATE oauth_clients SET last_used_at=? WHERE client_id=?"
            " AND (last_used_at IS NULL OR last_used_at < ?)",
            (now, client_id, now - TOUCH_INTERVAL),
        )
        return self._client_info(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        uris = client_info.redirect_uris or []
        if not uris:
            raise RegistrationError("invalid_redirect_uri", "at least one redirect URI is required")
        _clamp_client_metadata(client_info)
        hosts = self._settings.redirect_hosts
        for uri in uris:
            if not _redirect_uri_allowed(str(uri), hosts):
                raise RegistrationError(
                    "invalid_redirect_uri",
                    "redirect URIs must use https on an allowed host ("
                    + ", ".join(hosts)
                    + "), or http on a loopback host (RFC 8252)",
                )
        # NB: the SDK's error types are frozen dataclasses; contextlib cannot re-raise them
        # through `db.transaction()` (it assigns __traceback__), so they are raised outside.
        with self._db.transaction():
            if self._client_count() >= MAX_CLIENTS:
                self.purge()
            excess = self._client_count() - MAX_CLIENTS + 1
            if excess > 0:
                self._evict_never_tokened(excess)
            full = self._client_count() >= MAX_CLIENTS
            if not full:
                self._db.execute(
                    "INSERT INTO oauth_clients(client_id, info_json, created_at) VALUES (?, ?, ?)",
                    (client_info.client_id, client_info.model_dump_json(), self._now()),
                )
        if full:
            raise RegistrationError("invalid_client_metadata", "too many registered clients")

    def _delete_clients(self, where: str, params) -> None:
        """Delete clients matching `where` and their codes/pending requests (caller holds a
        transaction). Only for clients without live tokens."""
        ids = [
            r[0]
            for r in self._db.query(f"SELECT client_id FROM oauth_clients WHERE {where}", params)
        ]
        for client_id in ids:
            self._db.execute("DELETE FROM oauth_codes WHERE client_id=?", (client_id,))
            self._db.execute("DELETE FROM oauth_pending WHERE client_id=?", (client_id,))
            self._db.execute("DELETE FROM oauth_clients WHERE client_id=?", (client_id,))

    def _evict_never_tokened(self, count: int) -> None:
        """Make room in a full client table: drop the `count` oldest clients that never
        obtained a token (typically abandoned or junk registrations)."""
        self._delete_clients(
            "client_id IN (SELECT client_id FROM oauth_clients WHERE token_issued_at IS NULL"
            " ORDER BY created_at, rowid LIMIT ?)",
            (count,),
        )

    # ----- authorization + consent ----------------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        if params.resource is not None and params.resource not in self._resources:
            raise AuthorizeError("invalid_request", "unknown resource")
        if params.state is not None and len(params.state) > MAX_STATE_LEN:
            raise AuthorizeError(
                "invalid_request", f"state is longer than {MAX_STATE_LEN} characters"
            )
        if not _S256_CHALLENGE.fullmatch(params.code_challenge):
            raise AuthorizeError("invalid_request", "code_challenge is not an S256 challenge")
        now = self._now()
        txn_id = new_token()
        with self._db.transaction():
            self._db.execute("DELETE FROM oauth_pending WHERE created_at < ?", (now - PENDING_TTL,))
            self._db.execute(
                "INSERT INTO oauth_pending(txn_id, client_id, params_json, created_at)"
                " VALUES (?, ?, ?, ?)",
                (txn_id, client.client_id, params.model_dump_json(), now),
            )
            self._db.execute(
                "DELETE FROM oauth_pending WHERE client_id=? AND txn_id NOT IN"
                " (SELECT txn_id FROM oauth_pending WHERE client_id=?"
                " ORDER BY created_at DESC, rowid DESC LIMIT ?)",
                (client.client_id, client.client_id, MAX_PENDING_PER_CLIENT),
            )
        return f"{self._settings.base_url}/consent?txn={txn_id}"

    def _pending_from_row(
        self, row, now: int
    ) -> tuple[OAuthClientInformationFull, AuthorizationParams] | None:
        if row is None or row["created_at"] < now - PENDING_TTL:
            return None
        client = self._client_info(row["client_id"])
        if client is None:
            return None
        return client, AuthorizationParams.model_validate_json(row["params_json"])

    def get_pending(
        self, txn_id: str
    ) -> tuple[OAuthClientInformationFull, AuthorizationParams] | None:
        row = self._db.one(
            "SELECT client_id, params_json, created_at FROM oauth_pending WHERE txn_id=?",
            (txn_id,),
        )
        return self._pending_from_row(row, self._now())

    def _take_pending(
        self, txn_id: str, now: int
    ) -> tuple[OAuthClientInformationFull, AuthorizationParams] | None:
        """Load and delete a pending request (caller holds a transaction). Expired rows are
        consumed too, so a txn can never be used twice."""
        row = self._db.one(
            "SELECT client_id, params_json, created_at FROM oauth_pending WHERE txn_id=?",
            (txn_id,),
        )
        if row is None:
            return None
        self._db.execute("DELETE FROM oauth_pending WHERE txn_id=?", (txn_id,))
        return self._pending_from_row(row, now)

    def approve(self, txn_id: str) -> str:
        now = self._now()
        code = new_token()
        with self._db.transaction():
            pending = self._take_pending(txn_id, now)
            if pending is not None:
                client, params = pending
                data = {
                    "scopes": params.scopes or [SCOPE],
                    "code_challenge": params.code_challenge,
                    "redirect_uri": str(params.redirect_uri),
                    "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
                    "resource": params.resource,
                    "subject": SUBJECT,
                }
                self._db.execute(
                    "INSERT INTO oauth_codes(code_hash, client_id, data_json, expires_at)"
                    " VALUES (?, ?, ?, ?)",
                    (hash_token(code), client.client_id, json.dumps(data), now + CODE_TTL),
                )
        if pending is None:
            raise LookupError("unknown or expired authorization request")
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    def deny(self, txn_id: str) -> str:
        with self._db.transaction():
            pending = self._take_pending(txn_id, self._now())
        if pending is None:
            raise LookupError("unknown or expired authorization request")
        _, params = pending
        return construct_redirect_uri(
            str(params.redirect_uri),
            error="access_denied",
            error_description="the owner denied the request",
            state=params.state,
        )

    # ----- codes + tokens -------------------------------------------------------------------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code_hash = hash_token(authorization_code)
        row = self._db.one(
            "SELECT code_hash, client_id, data_json, expires_at FROM oauth_codes"
            " WHERE code_hash=? AND client_id=? AND expires_at > ?",
            (code_hash, client.client_id, self._now()),
        )
        if row is None or not _hash_matches(row["code_hash"], code_hash):
            self._revoke_if_replayed(code_hash, client.client_id)
            return None
        return AuthorizationCode(
            code=authorization_code,
            client_id=row["client_id"],
            expires_at=row["expires_at"],
            **json.loads(row["data_json"]),
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        now = self._now()
        code_hash = hash_token(authorization_code.code)
        tokens = None
        with self._db.transaction():
            # The DELETE is the single-use gate; the stored grant (not the passed object) is
            # what gets issued.
            rows = self._db.query(
                "DELETE FROM oauth_codes WHERE code_hash=? AND client_id=? AND expires_at > ?"
                " RETURNING data_json",
                (code_hash, client.client_id, now),
            )
            if rows:
                data = json.loads(rows[0]["data_json"])
                family_id = new_token()
                tokens = self._issue_pair(
                    client.client_id, family_id, data["scopes"], data["resource"], now
                )
                # Tombstone: a later presentation of this code revokes what it produced.
                self._db.execute(
                    "INSERT OR REPLACE INTO oauth_used_codes(code_hash, family_id, expires_at)"
                    " VALUES (?, ?, ?)",
                    (code_hash, family_id, now + CODE_TTL),
                )
        if tokens is None:
            self._revoke_if_replayed(code_hash, client.client_id)
            raise TokenError("invalid_grant", "authorization code already used")
        return tokens

    def _revoke_if_replayed(self, code_hash: str, client_id: str) -> None:
        """RFC 6749 §4.1.2: a code used twice has leaked; revoke the tokens it produced."""
        row = self._db.one(
            "SELECT family_id FROM oauth_used_codes WHERE code_hash=? AND expires_at > ?",
            (code_hash, self._now()),
        )
        if row is None:
            return
        self._revoke_family(row["family_id"])
        log.warning(
            "authorization code reuse detected (client %s); revoked the tokens it issued",
            client_id,
        )

    def _issue_pair(
        self,
        client_id: str,
        family_id: str,
        scopes: list[str],
        resource: str | None,
        now: int,
    ) -> OAuthToken:
        """Insert a fresh access + refresh token (caller holds a transaction)."""
        self._db.execute(
            "UPDATE oauth_clients SET token_issued_at=? WHERE client_id=? AND token_issued_at IS NULL",
            (now, client_id),
        )
        access, refresh = _new_oauth_token(), _new_oauth_token()
        scope = " ".join(scopes)
        for token, kind, ttl in ((access, "access", ACCESS_TTL), (refresh, "refresh", REFRESH_TTL)):
            self._db.execute(
                "INSERT INTO oauth_tokens(token_hash, kind, client_id, family_id, scopes,"
                " resource, expires_at, state, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)",
                (hash_token(token), kind, client_id, family_id, scope, resource, now + ttl, now),
            )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=ACCESS_TTL,
            refresh_token=refresh,
            scope=scope,
        )

    def _revoke_family(self, family_id: str) -> None:
        with self._db.transaction():
            self._db.execute(
                "UPDATE oauth_tokens SET state='revoked' WHERE family_id=?", (family_id,)
            )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        token_hash = hash_token(refresh_token)
        row = self._db.one(
            "SELECT token_hash, family_id, scopes, resource, expires_at, state FROM oauth_tokens"
            " WHERE token_hash=? AND kind='refresh' AND client_id=?",
            (token_hash, client.client_id),
        )
        if row is None or not _hash_matches(row["token_hash"], token_hash):
            return None
        if row["state"] == "rotated":
            self._revoke_family(row["family_id"])
            log.warning(
                "refresh token reuse detected for client %s; revoked its token family",
                client.client_id,
            )
            return None
        if row["state"] != "active" or row["expires_at"] <= self._now():
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=_split_scopes(row["scopes"]),
            expires_at=row["expires_at"],
            resource=row["resource"],
            subject=SUBJECT,
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        now = self._now()
        token_hash = hash_token(refresh_token.token)
        tokens = None
        with self._db.transaction():
            row = self._db.one(
                "SELECT family_id, scopes, resource FROM oauth_tokens WHERE token_hash=?"
                " AND kind='refresh' AND client_id=? AND state='active' AND expires_at > ?",
                (token_hash, client.client_id, now),
            )
            rotated = row is not None and self._db.execute(
                "UPDATE oauth_tokens SET state='rotated' WHERE token_hash=? AND state='active'",
                (token_hash,),
            )
            if rotated:
                self._db.execute(
                    "UPDATE oauth_tokens SET state='revoked'"
                    " WHERE family_id=? AND kind='access' AND state='active'",
                    (row["family_id"],),
                )
                original = _split_scopes(row["scopes"])
                granted = scopes if scopes and set(scopes) <= set(original) else original
                tokens = self._issue_pair(
                    client.client_id, row["family_id"], granted, row["resource"], now
                )
        if tokens is None:
            raise TokenError("invalid_grant", "refresh token is invalid or already used")
        return tokens

    async def load_access_token(self, token: str) -> AccessToken | None:
        now = self._now()
        token_hash = hash_token(token)
        if token.startswith(API_KEY_PREFIX):
            return self._load_api_key(token, token_hash, now)
        row = self._db.one(
            "SELECT token_hash, client_id, scopes, resource, expires_at FROM oauth_tokens"
            " WHERE token_hash=? AND kind='access' AND state='active' AND expires_at > ?",
            (token_hash, now),
        )
        if row is None or not _hash_matches(row["token_hash"], token_hash):
            return None
        if row["resource"] is not None and row["resource"] not in self._resources:
            return None
        self._db.execute(
            "UPDATE oauth_tokens SET last_used_at=? WHERE token_hash=?"
            " AND (last_used_at IS NULL OR last_used_at < ?)",
            (now, token_hash, now - TOUCH_INTERVAL),
        )
        return AccessToken(
            token=token,
            client_id=row["client_id"],
            scopes=_split_scopes(row["scopes"]),
            expires_at=row["expires_at"],
            resource=self._settings.mcp_url if row["resource"] else None,
            subject=SUBJECT,
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        row = self._db.one(
            "SELECT family_id FROM oauth_tokens WHERE token_hash=?", (hash_token(token.token),)
        )
        if row is not None:
            self._revoke_family(row["family_id"])

    # ----- API keys -------------------------------------------------------------------------

    def _load_api_key(self, key: str, key_hash: str, now: int) -> AccessToken | None:
        row = self._db.one(
            "SELECT id, key_hash FROM api_keys WHERE key_hash=? AND revoked=0", (key_hash,)
        )
        if row is None or not _hash_matches(row["key_hash"], key_hash):
            return None
        self._db.execute(
            "UPDATE api_keys SET last_used_at=? WHERE id=?"
            " AND (last_used_at IS NULL OR last_used_at < ?)",
            (now, row["id"], now - TOUCH_INTERVAL),
        )
        return AccessToken(
            token=key,
            client_id=f"apikey:{row['id']}",
            scopes=[SCOPE],
            expires_at=None,
            subject=SUBJECT,
        )

    def create_api_key(self, name: str) -> str:
        name = name.strip()
        if not name:
            raise ValueError("API key name must not be empty")
        key = new_token(API_KEY_PREFIX)
        self._db.insert(
            "INSERT INTO api_keys(name, key_hash, prefix, created_at) VALUES (?, ?, ?, ?)",
            (name, hash_token(key), key[:8], self._now()),
        )
        return key

    def list_api_keys(self) -> list[ApiKeyRow]:
        rows = self._db.query(
            "SELECT id, name, prefix, created_at, last_used_at, revoked FROM api_keys ORDER BY id"
        )
        return [
            ApiKeyRow(
                id=r["id"],
                name=r["name"],
                prefix=r["prefix"],
                created_at=r["created_at"],
                last_used_at=r["last_used_at"],
                revoked=bool(r["revoked"]),
            )
            for r in rows
        ]

    def revoke_api_key(self, key_id: int) -> None:
        self._db.execute("UPDATE api_keys SET revoked=1 WHERE id=?", (key_id,))

    # ----- admin + maintenance --------------------------------------------------------------

    def list_clients(self) -> list[ClientRow]:
        # Only the bounded pieces of the metadata are extracted (in SQLite, row by row), so
        # rows stored before the DCR bounds existed cannot blow up the admin page's memory.
        rows = self._db.query(
            "SELECT c.client_id, c.created_at, c.last_used_at,"
            " substr(json_extract(c.info_json, '$.client_name'), 1, ?) AS client_name,"
            " (SELECT json_group_array(substr(u.value, 1, ?)) FROM"
            "  (SELECT value FROM json_each(c.info_json, '$.redirect_uris') LIMIT ?) u)"
            "  AS redirect_uris,"
            " (SELECT count(*) FROM oauth_tokens t WHERE t.client_id = c.client_id"
            "  AND t.state='active' AND t.expires_at > ?) AS active_tokens"
            " FROM oauth_clients c ORDER BY COALESCE(c.last_used_at, c.created_at) DESC",
            (MAX_CLIENT_NAME, MAX_REDIRECT_URI_LEN, MAX_REDIRECT_URIS, self._now()),
        )
        result = []
        for r in rows:
            hosts: list[str] = []
            for uri in json.loads(r["redirect_uris"] or "[]"):
                try:
                    host = urlparse(str(uri)).hostname or ""
                except ValueError:
                    host = ""
                if host not in hosts:
                    hosts.append(host)
            name = r["client_name"]
            result.append(
                ClientRow(
                    client_id=r["client_id"],
                    client_name=name if isinstance(name, str) else None,
                    redirect_hosts=hosts,
                    created_at=r["created_at"],
                    last_used_at=r["last_used_at"],
                    active_tokens=r["active_tokens"],
                )
            )
        return result

    def revoke_client(self, client_id: str) -> None:
        with self._db.transaction():
            self._db.execute(
                "UPDATE oauth_tokens SET state='revoked' WHERE client_id=?", (client_id,)
            )
            self._db.execute("DELETE FROM oauth_codes WHERE client_id=?", (client_id,))
            self._db.execute("DELETE FROM oauth_pending WHERE client_id=?", (client_id,))
            self._db.execute("DELETE FROM oauth_clients WHERE client_id=?", (client_id,))

    def purge(self) -> None:
        now = self._now()
        with self._db.transaction():
            self._db.execute("DELETE FROM oauth_codes WHERE expires_at <= ?", (now,))
            self._db.execute("DELETE FROM oauth_used_codes WHERE expires_at <= ?", (now,))
            self._db.execute("DELETE FROM oauth_pending WHERE created_at < ?", (now - PENDING_TTL,))
            self._db.execute(
                "DELETE FROM oauth_tokens WHERE expires_at < ?"
                " OR (state != 'active' AND created_at < ?)",
                (now - EXPIRED_GRACE, now - REFRESH_TTL),
            )
            self._db.execute(
                "DELETE FROM oauth_clients WHERE COALESCE(last_used_at, created_at) < ?"
                " AND NOT EXISTS (SELECT 1 FROM oauth_tokens t"
                "  WHERE t.client_id = oauth_clients.client_id"
                "  AND t.state='active' AND t.expires_at > ?)",
                (now - STALE_CLIENT_SECONDS, now),
            )
            self._delete_clients(
                "token_issued_at IS NULL AND created_at < ?", (now - UNUSED_CLIENT_SECONDS,)
            )
