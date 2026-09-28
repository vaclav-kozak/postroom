import pytest

from postroom.accounts import AccountStatus
from postroom.mail.imap import AuthFailed, ImapConnector, ImapPool
from tests.integration.conftest import insecure_ctx

pytestmark = pytest.mark.integration


def test_login_and_list(repo, gm_account):
    pool = ImapPool(repo, ImapConnector(ssl_context=insecure_ctx()))
    with pool.session(gm_account) as c:
        names = [f[2] for f in c.list_folders()]
    assert "INBOX" in names
    assert repo.get(gm_account).status == AccountStatus.CONNECTED
    pool.close_all()


def test_bad_password_trips_breaker(repo, gm_account):
    repo.set_secret(gm_account, "wrong")
    pool = ImapPool(repo, ImapConnector(ssl_context=insecure_ctx()))
    with pytest.raises(AuthFailed), pool.session(gm_account):
        pass
    assert repo.get(gm_account).status == AccountStatus.NEEDS_RECONNECT
