import socket
import ssl
import subprocess
import sys
import time

import httpx
import pytest
from imapclient import IMAPClient
from testcontainers.core.container import DockerContainer
from testcontainers.core.waiting_utils import wait_for_logs

from postroom.accounts import Provider

USER, PASSWORD = "alice@example.com", "secret"


def insecure_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


@pytest.fixture(scope="session")
def greenmail_container():
    c = (
        DockerContainer("greenmail/standalone:2.1.3")
        .with_env(
            "GREENMAIL_OPTS",
            "-Dgreenmail.setup.test.all -Dgreenmail.hostname=0.0.0.0 "
            f"-Dgreenmail.users={USER.split('@')[0]}:{PASSWORD}@example.com "
            "-Dgreenmail.users.login=email -Dgreenmail.verbose",
        )
        .with_exposed_ports(3993, 3465)
    )
    c.start()
    wait_for_logs(c, "Starting GreenMail standalone", timeout=60)
    time.sleep(1)
    yield c
    c.stop()


@pytest.fixture(scope="session")
def greenmail(greenmail_container):
    """(host, port) of GreenMail's IMAPS server."""
    c = greenmail_container
    return c.get_container_host_ip(), int(c.get_exposed_port(3993))


@pytest.fixture(scope="session")
def greenmail_smtps(greenmail_container):
    """(host, port) of GreenMail's SMTPS server (implicit TLS, self-signed)."""
    c = greenmail_container
    return c.get_container_host_ip(), int(c.get_exposed_port(3465))


@pytest.fixture
def raw_imap(greenmail):
    host, port = greenmail
    cl = IMAPClient(host, port, ssl=True, ssl_context=insecure_ctx())
    cl.login(USER, PASSWORD)
    yield cl
    cl.logout()


@pytest.fixture
def gm_account(repo, greenmail):
    host, port = greenmail
    repo.upsert(
        email=USER,
        provider=Provider.IMAP,
        imap_host=host,
        imap_port=port,
        imap_security="ssl",
        secret=PASSWORD,
    )
    return USER


DAV_USER, DAV_PASS = "alice", "secret"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="session")
def radicale(tmp_path_factory):
    d = tmp_path_factory.mktemp("radicale")
    port = _free_port()
    (d / "users").write_text(f"{DAV_USER}:{DAV_PASS}\n")
    (d / "config").write_text(
        f"[server]\nhosts = 127.0.0.1:{port}\n"
        f"[auth]\ntype = htpasswd\nhtpasswd_filename = {d / 'users'}\nhtpasswd_encryption = plain\n"
        f"[storage]\nfilesystem_folder = {d / 'collections'}\n"
        "[rights]\ntype = owner_only\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-m", "radicale", "--config", str(d / "config")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            httpx.get(base, timeout=0.5)
            break
        except httpx.HTTPError:
            time.sleep(0.1)
    import caldav

    principal = caldav.DAVClient(
        url=f"{base}/{DAV_USER}/", username=DAV_USER, password=DAV_PASS
    ).principal()
    principal.make_calendar(
        name="Personal", cal_id="personal", supported_calendar_component_set=["VEVENT", "VTODO"]
    )
    body = (
        '<?xml version="1.0"?><D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">'
        "<D:set><D:prop><D:resourcetype><D:collection/><C:addressbook/></D:resourcetype>"
        "<D:displayname>Contacts</D:displayname></D:prop></D:set></D:mkcol>"
    )
    auth = (DAV_USER, DAV_PASS)
    httpx.request(
        "MKCOL", f"{base}/{DAV_USER}/contacts/", content=body, auth=auth
    ).raise_for_status()
    httpx.put(
        f"{base}/{DAV_USER}/contacts/jan.vcf",
        auth=auth,
        headers={"Content-Type": "text/vcard"},
        content="BEGIN:VCARD\r\nVERSION:3.0\r\nUID:jan\r\nFN:Jan Novák\r\nN:Novák;Jan;;;\r\n"
        "EMAIL:jan@example.com\r\nEND:VCARD\r\n",
    ).raise_for_status()
    yield f"{base}/{DAV_USER}/"
    proc.terminate()
    proc.wait(10)
