import threading

from postroom.db import SCHEMA_VERSION, Database


def test_schema_created(tmp_path):
    db = Database(str(tmp_path / "sub" / "x.db"))
    tables = {r["name"] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {
        "accounts",
        "oauth_clients",
        "oauth_pending",
        "oauth_codes",
        "oauth_tokens",
        "api_keys",
        "login_attempts",
    } <= tables
    assert db.one("PRAGMA user_version")[0] == SCHEMA_VERSION


def test_reopen_is_idempotent(tmp_path):
    p = str(tmp_path / "x.db")
    Database(p).insert(
        "INSERT INTO api_keys(name,key_hash,prefix,created_at) VALUES('a','h','p',1)"
    )
    db2 = Database(p)
    assert db2.one("SELECT count(*) FROM api_keys")[0] == 1


def test_threaded_writes(tmp_path):
    db = Database(str(tmp_path / "x.db"))

    def work(i):
        db.insert("INSERT INTO login_attempts(ip, at, ok) VALUES(?,?,0)", (f"ip{i}", i))

    ts = [threading.Thread(target=work, args=(i,)) for i in range(20)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert db.one("SELECT count(*) FROM login_attempts")[0] == 20


def test_transaction_rolls_back(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        with db.transaction():
            db.insert("INSERT INTO login_attempts(ip, at, ok) VALUES('a',1,0)")
            raise RuntimeError
    except RuntimeError:
        pass
    assert db.one("SELECT count(*) FROM login_attempts")[0] == 0


def test_migration_2_upgrades_a_v1_database(tmp_path):
    import sqlite3

    from postroom.db import MIGRATIONS

    p = str(tmp_path / "v1.db")
    conn = sqlite3.connect(p, isolation_level=None)
    conn.executescript("BEGIN;" + MIGRATIONS[1] + "; PRAGMA user_version=1; COMMIT;")
    conn.execute("INSERT INTO oauth_clients(client_id, info_json, created_at) VALUES('a','{}',1)")
    conn.execute("INSERT INTO oauth_clients(client_id, info_json, created_at) VALUES('b','{}',1)")
    conn.execute(
        "INSERT INTO oauth_tokens(token_hash, kind, client_id, family_id, created_at)"
        " VALUES('h', 'access', 'a', 'f', 42)"
    )
    conn.close()
    db = Database(p)
    assert db.one("PRAGMA user_version")[0] == SCHEMA_VERSION == 2
    issued = {r[0]: r[1] for r in db.query("SELECT client_id, token_issued_at FROM oauth_clients")}
    assert issued == {"a": 42, "b": None}
    assert db.one("SELECT session_version FROM owner_state WHERE id=1")[0] == 1
    assert db.one("SELECT count(*) FROM oauth_used_codes")[0] == 0
