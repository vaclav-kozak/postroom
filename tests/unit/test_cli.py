import base64
import io
import os
import stat

import pytest

from postroom import cli
from postroom.crypto import verify_password
from tests.unit.test_emclient import PASS, XML


def _env(monkeypatch, settings):
    monkeypatch.setenv("POSTROOM_DB_PATH", settings.db_path)
    monkeypatch.setenv("POSTROOM_MASTER_KEY", settings.master_key)
    monkeypatch.setenv("POSTROOM_SESSION_SECRET", "s")


def test_import_first_line_passphrase(monkeypatch, settings, capsys):
    _env(monkeypatch, settings)
    data = PASS.encode() + b"\n" + XML
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(data)))
    assert cli.main(["import-emclient", "-", "--passphrase-first-line"]) == 0
    out = capsys.readouterr().out
    assert "a@example.com" in out and "created" in out
    assert "pässword1" not in out and "refresh" not in out


def test_import_dry_run_writes_nothing(monkeypatch, settings, tmp_path, capsys):
    _env(monkeypatch, settings)
    x = tmp_path / "e.xml"
    x.write_bytes(XML)
    p = tmp_path / "p.txt"
    p.write_text(PASS + "\n")
    assert cli.main(["import-emclient", str(x), "--passphrase-file", str(p), "--dry-run"]) == 0
    assert cli.main(["list-accounts"]) == 0
    assert "a@example.com" not in capsys.readouterr().out.split("dry-run")[-1]


def test_gen_secrets(tmp_path, capsys):
    env_out, pw_out = tmp_path / "env", tmp_path / "pw"
    assert cli.main(["gen-secrets", "--env-out", str(env_out), "--password-out", str(pw_out)]) == 0
    for f in (env_out, pw_out):
        assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
    env = dict(line.split("=", 1) for line in env_out.read_text().splitlines() if "=" in line)
    pw = pw_out.read_text().strip()
    assert len(pw) >= 32
    h = base64.b64decode(env["POSTROOM_ADMIN_PASSWORD_HASH_B64"]).decode()
    assert verify_password(h, pw)
    assert len(base64.b64decode(env["POSTROOM_MASTER_KEY"])) == 32
    printed = capsys.readouterr().out
    assert pw not in printed and env["POSTROOM_MASTER_KEY"] not in printed


def test_set_password_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("new-password-123\n"))
    assert cli.main(["set-password", "--stdin"]) == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("POSTROOM_ADMIN_PASSWORD_HASH_B64=")
    h = base64.b64decode(out.split("=", 1)[1]).decode()
    assert verify_password(h, "new-password-123") and "new-password-123" not in out


def test_check_accounts_cli(monkeypatch, settings, capsys):
    _env(monkeypatch, settings)
    from postroom.accounts import AccountRepo, Provider
    from postroom.crypto import SecretBox
    from postroom.db import Database

    repo = AccountRepo(Database(settings.db_path), SecretBox(settings.master_key))
    repo.upsert(
        email="x@x.cz",
        provider=Provider.IMAP,
        imap_host="127.0.0.1",
        imap_port=1,
        imap_security="ssl",
        secret="p",
    )
    assert cli.main(["check-accounts"]) == 0
    assert "x@x.cz\terror" in capsys.readouterr().out


def test_set_password_mismatch(monkeypatch, capsys):
    answers = iter(["one-password", "other-password"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert cli.main(["set-password"]) == 1
    captured = capsys.readouterr()
    assert "POSTROOM_ADMIN_PASSWORD_HASH_B64" not in captured.out
    assert "one-password" not in captured.out + captured.err


def test_set_password_empty_rejected(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("\n"))
    assert cli.main(["set-password", "--stdin"]) == 1
    assert capsys.readouterr().out == ""


def test_check_accounts_cli_filters_and_skips_locked(monkeypatch, settings, capsys):
    _env(monkeypatch, settings)
    from postroom.accounts import AccountRepo, AccountStatus, Provider
    from postroom.crypto import SecretBox
    from postroom.db import Database
    from postroom.mail.imap import ImapConnector

    repo = AccountRepo(Database(settings.db_path), SecretBox(settings.master_key))
    for email, status in [("a@x.cz", None), ("b@x.cz", AccountStatus.NEEDS_RECONNECT)]:
        repo.upsert(
            email=email,
            provider=Provider.IMAP,
            imap_host="127.0.0.1",
            imap_port=1,
            imap_security="ssl",
            secret="p",
            status=status,
        )
    connects = []
    monkeypatch.setattr(
        ImapConnector,
        "connect",
        lambda self, acc, s: (
            connects.append(acc.email) or (_ for _ in ()).throw(OSError("refused"))
        ),
    )
    assert cli.main(["check-accounts", "--email", "B@x.cz", "nobody@x.cz"]) == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("b@x.cz\tneeds_reconnect\t")
    assert "a@x.cz" not in captured.out and "unknown account: nobody@x.cz" in captured.err
    assert connects == []  # the breaker holds: no login attempt for needs_reconnect


def test_api_key_cli(monkeypatch, settings, capsys):
    _env(monkeypatch, settings)
    assert cli.main(["create-api-key", "smoke"]) == 0
    key = capsys.readouterr().out.strip()
    assert key.startswith("prm_") and "\n" not in key
    assert cli.main(["list-api-keys"]) == 0
    out = capsys.readouterr().out
    assert "smoke" in out and key not in out
    key_id = out.split()[0]
    assert cli.main(["revoke-api-key", key_id]) == 0
    assert cli.main(["list-api-keys"]) == 0
    assert "revoked" in capsys.readouterr().out


def test_api_key_cli_edge_cases(monkeypatch, settings, capsys):
    _env(monkeypatch, settings)
    assert cli.main(["create-api-key", "   "]) == 2
    assert cli.main(["create-api-key", "x" * 61]) == 2
    assert cli.main(["revoke-api-key", "999"]) == 1
    assert cli.main(["create-api-key", "laptop"]) == 0
    key = capsys.readouterr().out.strip()
    assert cli.main(["list-api-keys"]) == 0
    fields = capsys.readouterr().out.strip().split("\t")
    assert fields[1:3] == ["laptop", key[:8]] and fields[4] == "-" and fields[5] == "active"


def test_set_access(monkeypatch, settings, capsys):
    _env(monkeypatch, settings)
    from postroom.accounts import AccountRepo, MailAccess, Provider
    from postroom.crypto import SecretBox
    from postroom.db import Database

    repo = AccountRepo(Database(settings.db_path), SecretBox(settings.master_key))
    repo.upsert(email="user@example.com", provider=Provider.IMAP)
    # Sending is opt-in: a new account starts at organize.
    assert repo.get("user@example.com").mail_access == MailAccess.ORGANIZE

    assert cli.main(["set-access", "User@Example.com", "read"]) == 0
    assert capsys.readouterr().out == "user@example.com\tread\n"
    assert repo.get("user@example.com").mail_access == MailAccess.READ

    assert cli.main(["list-accounts"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split("\t")[4] == "mail_access" and lines[1].split("\t")[4] == "read"

    assert cli.main(["set-access", "user@example.com", "organize"]) == 0
    assert repo.get("user@example.com").mail_access == MailAccess.ORGANIZE

    assert cli.main(["set-access", "nobody@example.com", "full"]) == 1
    assert "unknown account: nobody@example.com" in capsys.readouterr().err

    assert cli.main(["set-access", "user@example.com", "admin"]) == 2
    assert "unknown access level 'admin'" in capsys.readouterr().err
    assert repo.get("user@example.com").mail_access == MailAccess.ORGANIZE


def test_set_access_all(monkeypatch, settings, capsys):
    _env(monkeypatch, settings)
    from postroom.accounts import AccountRepo, MailAccess, Provider
    from postroom.crypto import SecretBox
    from postroom.db import Database

    repo = AccountRepo(Database(settings.db_path), SecretBox(settings.master_key))
    repo.upsert(email="a@example.com", provider=Provider.IMAP)
    repo.upsert(email="b@example.com", provider=Provider.GOOGLE, mail_access=MailAccess.READ)

    assert cli.main(["set-access", "--all", "full"]) == 0
    assert capsys.readouterr().out == "2 accounts\tfull\n"
    assert {a.mail_access for a in repo.list()} == {MailAccess.FULL}

    # --all takes only the level; the per-account form needs both.
    assert cli.main(["set-access", "--all", "a@example.com", "read"]) == 2
    assert cli.main(["set-access", "read"]) == 2
    assert cli.main(["set-access", "--all", "admin"]) == 2
    assert {a.mail_access for a in repo.list()} == {MailAccess.FULL}


def test_invalid_setting_is_a_short_config_error(monkeypatch, settings, capsys):
    _env(monkeypatch, settings)
    monkeypatch.setenv("POSTROOM_TIMEZONE", "Mars/Olympus")
    assert cli.main(["list-accounts"]) == 2
    err = capsys.readouterr().err
    assert "configuration error: POSTROOM_TIMEZONE: must be an IANA time zone" in err
    assert "Traceback" not in err


def test_config_error_never_prints_values(monkeypatch, capsys):
    monkeypatch.delenv("POSTROOM_MASTER_KEY", raising=False)
    monkeypatch.setenv("POSTROOM_SESSION_SECRET", "s3cr3t-value")
    monkeypatch.setenv("POSTROOM_CHECK_INTERVAL_SECONDS", "not-a-number-s3cr3t")
    assert cli.main(["list-accounts"]) == 2
    err = capsys.readouterr().err
    assert "POSTROOM_MASTER_KEY: Field required" in err
    assert "POSTROOM_CHECK_INTERVAL_SECONDS" in err
    assert "s3cr3t" not in err


@pytest.mark.parametrize(
    ("name", "value", "text"),
    [
        ("MASTER_KEY", "abc-s3cr3t", "must be 32 random bytes in base64"),
        ("ADMIN_PASSWORD_HASH_B64", "'s3cr3t'", "is not a base64-encoded argon2 hash"),
        ("TRUSTED_PROXIES", "nonsense", "must be comma-separated IP addresses or networks"),
    ],
)
def test_serve_with_a_malformed_setting_is_one_config_line(
    monkeypatch, settings, capsys, name, value, text
):
    import uvicorn

    _env(monkeypatch, settings)
    monkeypatch.setenv(f"POSTROOM_{name}", value)
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: pytest.fail("the server started"))
    assert cli.main(["serve"]) == 2
    err = capsys.readouterr().err
    assert err.startswith(f"postroom: configuration error: POSTROOM_{name}: {text}")
    assert len(err.strip().splitlines()) == 1
    assert "Traceback" not in err and "s3cr3t" not in err
