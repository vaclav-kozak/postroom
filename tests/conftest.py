import base64
import os

import pytest

from postroom.accounts import AccountRepo
from postroom.config import Settings
from postroom.crypto import SecretBox
from postroom.db import Database


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        public_url="http://testserver",
        db_path=str(tmp_path / "postroom.db"),
        master_key=base64.b64encode(os.urandom(32)).decode(),
        session_secret="test-session-secret",
        admin_password_hash_b64="",
        check_interval_seconds=0,
        google_client_id="gid",
        google_client_secret="gsecret",
    )


@pytest.fixture
def db(settings) -> Database:
    return Database(settings.db_path)


@pytest.fixture
def box(settings) -> SecretBox:
    return SecretBox(settings.master_key)


@pytest.fixture
def repo(db, box) -> AccountRepo:
    return AccountRepo(db, box)
