import contextlib
import os
import sqlite3
import threading

SCHEMA_VERSION = 3

MIGRATIONS: dict[int, str] = {
    1: """
    CREATE TABLE accounts (
        id INTEGER PRIMARY KEY,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        display_name TEXT,
        provider TEXT NOT NULL CHECK (provider IN ('imap','google')),
        imap_host TEXT, imap_port INTEGER,
        imap_security TEXT CHECK (imap_security IN ('ssl','starttls')),
        imap_username TEXT,
        caldav_url TEXT, carddav_url TEXT,
        secret_enc BLOB,
        enabled INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'pending',
        last_error TEXT, last_ok_at INTEGER, last_check_at INTEGER,
        created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
    );
    CREATE TABLE oauth_clients (
        client_id TEXT PRIMARY KEY, info_json TEXT NOT NULL,
        created_at INTEGER NOT NULL, last_used_at INTEGER
    );
    CREATE TABLE oauth_pending (
        txn_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, params_json TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE oauth_codes (
        code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, data_json TEXT NOT NULL,
        expires_at REAL NOT NULL
    );
    CREATE TABLE oauth_tokens (
        token_hash TEXT PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('access','refresh')),
        client_id TEXT NOT NULL, family_id TEXT NOT NULL,
        scopes TEXT NOT NULL DEFAULT '', resource TEXT,
        expires_at INTEGER, state TEXT NOT NULL DEFAULT 'active'
            CHECK (state IN ('active','rotated','revoked')),
        created_at INTEGER NOT NULL, last_used_at INTEGER
    );
    CREATE INDEX oauth_tokens_family ON oauth_tokens(family_id);
    CREATE INDEX oauth_tokens_client ON oauth_tokens(client_id);
    CREATE TABLE api_keys (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE,
        prefix TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER,
        revoked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE login_attempts (ip TEXT NOT NULL, at INTEGER NOT NULL, ok INTEGER NOT NULL);
    CREATE INDEX login_attempts_at ON login_attempts(at);
    """,
    2: """
    -- Server-side logout: every owner session carries this version; logout bumps it.
    CREATE TABLE owner_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        session_version INTEGER NOT NULL
    );
    INSERT INTO owner_state(id, session_version) VALUES (1, 1);
    -- DCR table fill: a client that never received a token may be evicted.
    ALTER TABLE oauth_clients ADD COLUMN token_issued_at INTEGER;
    UPDATE oauth_clients SET token_issued_at = (
        SELECT min(t.created_at) FROM oauth_tokens t WHERE t.client_id = oauth_clients.client_id
    );
    -- Auth-code replay: a used code's hash -> the token family it produced.
    CREATE TABLE oauth_used_codes (
        code_hash TEXT PRIMARY KEY, family_id TEXT NOT NULL, expires_at INTEGER NOT NULL
    );
    """,
    3: """
    -- Per-account mail access level: read (read + drafts), organize (+ flags, move, trash,
    -- create folders), full (+ sending). Existing accounts get 'full': MCP clients ask the
    -- user to approve every non-read-only tool call; the owner can lower it per account.
    ALTER TABLE accounts ADD COLUMN mail_access TEXT NOT NULL DEFAULT 'full'
        CHECK (mail_access IN ('read','organize','full'));
    """,
}


class Database:
    def __init__(self, path: str):
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._depth = 0
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._migrate()

    def _migrate(self) -> None:
        current = self._conn.execute("PRAGMA user_version").fetchone()[0]
        for version in sorted(v for v in MIGRATIONS if v > current):
            self._conn.executescript(
                "BEGIN;" + MIGRATIONS[version] + f"; PRAGMA user_version={version}; COMMIT;"
            )

    @contextlib.contextmanager
    def transaction(self):
        with self._lock:
            outer = self._depth == 0
            if outer:
                self._conn.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield self
            except BaseException:
                self._depth -= 1
                if outer:
                    self._conn.execute("ROLLBACK")
                raise
            else:
                self._depth -= 1
                if outer:
                    self._conn.execute("COMMIT")

    def execute(self, sql: str, params=()) -> int:
        with self._lock:
            return self._conn.execute(sql, params).rowcount

    def insert(self, sql: str, params=()) -> int:
        with self._lock:
            return self._conn.execute(sql, params).lastrowid

    def query(self, sql: str, params=()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def one(self, sql: str, params=()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()
