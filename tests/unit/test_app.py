from fastmcp import Client

from postroom.accounts import AccountStatus, Provider
from postroom.app import SERVER_INSTRUCTIONS, build_mcp, build_services
from postroom.google.oauth import GoogleOAuth

READ_TOOLS = {
    "list_accounts",
    "list_folders",
    "search_emails",
    "get_email",
    "get_thread",
    "get_attachment",
}
PIM_TOOLS = {
    "list_calendars",
    "list_events",
    "create_event",
    "update_event",
    "delete_event",
    "list_task_lists",
    "list_tasks",
    "create_task",
    "update_task",
    "delete_task",
    "search_contacts",
}


def test_build_services_wires_google_token_source(settings):
    s = build_services(settings)
    assert isinstance(s.google, GoogleOAuth)
    assert s.pool.connector.google_token == s.google.access_token
    assert s.mail.pool is s.pool and s.pool.repo is s.repo and s.mail.repo is s.repo


def test_build_services_without_google(settings):
    settings.google_client_secret = ""
    s = build_services(settings)
    assert s.google is None and s.pool.connector.google_token is None


async def test_build_mcp_registers_annotated_mail_tools(settings):
    mcp = build_mcp(build_services(settings))
    assert mcp.name == "postroom" and mcp.instructions == SERVER_INSTRUCTIONS
    async with Client(mcp) as c:
        tools = {t.name: t for t in await c.list_tools()}
    assert set(tools) == READ_TOOLS | {"create_draft"} | PIM_TOOLS
    for name in READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True
        assert tools[name].annotations.open_world_hint is True
    assert tools["create_draft"].annotations.read_only_hint is False
    assert tools["create_draft"].annotations.destructive_hint is False


async def test_unknown_account_is_clean_tool_error(settings):
    mcp = build_mcp(build_services(settings))
    async with Client(mcp) as c:
        res = await c.call_tool("list_folders", {"account": "nobody@x.cz"}, raise_on_error=False)
    assert res.is_error and res.content[0].text == "unknown account: nobody@x.cz"


async def test_blocked_account_is_not_contacted(settings):
    services = build_services(settings)
    services.repo.upsert(
        email="a@x.cz",
        provider=Provider.IMAP,
        imap_host="127.0.0.1",
        imap_port=1,
        imap_security="ssl",
        secret="pw",
        status=AccountStatus.NEEDS_RECONNECT,
    )
    mcp = build_mcp(services)
    async with Client(mcp) as c:
        res = await c.call_tool(
            "get_email", {"account": "a@x.cz", "folder": "inbox", "uid": 1}, raise_on_error=False
        )
    assert res.is_error and "needs reconnect" in res.content[0].text
    assert "pw" not in res.content[0].text


def test_build_services_wires_pim(settings):
    s = build_services(settings)
    assert s.pim.repo is s.repo and s.pim.google is s.google
    assert "they never invite attendees" in SERVER_INSTRUCTIONS


async def test_blocked_account_pim_call_is_not_contacted(settings):
    services = build_services(settings)
    services.repo.upsert(
        email="a@x.cz",
        provider=Provider.IMAP,
        imap_host="127.0.0.1",
        imap_port=1,
        imap_security="ssl",
        caldav_url="http://127.0.0.1:1/dav/",
        secret="pw",
        status=AccountStatus.NEEDS_RECONNECT,
    )
    built = []
    services.pim.backend_factory = lambda account, capability: built.append(account)
    mcp = build_mcp(services)
    async with Client(mcp) as c:
        res = await c.call_tool("list_calendars", {"account": "a@x.cz"}, raise_on_error=False)
    assert res.is_error and res.content[0].text == "account unavailable: needs_reconnect"
    assert built == []
