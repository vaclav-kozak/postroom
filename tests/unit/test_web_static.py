"""Static assets (CSS, JS, fonts, favicon) and the CSP-compatibility of the admin templates."""

import importlib.resources
import re

import httpx
import pytest

from postroom.app import build_services, create_app
from postroom.web.pages import ASSET_VERSION, STATIC


@pytest.fixture
async def http(settings):
    settings.public_url = "http://localhost"
    app = create_app(settings, build_services(settings))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as c:
            yield c


@pytest.mark.parametrize(
    ("path", "content_type"),
    [
        ("app.css", "text/css"),
        ("app.js", "text/javascript"),
        ("favicon.svg", "image/svg+xml"),
        ("fonts/zilla-slab-latin-600-normal.woff2", "font/woff2"),
        ("fonts/atkinson-hyperlegible-next-latin-400-normal.woff2", "font/woff2"),
        ("fonts/atkinson-hyperlegible-mono-latin-400-normal.woff2", "font/woff2"),
    ],
)
async def test_static_assets_served_with_type_and_cache(http, path, content_type):
    r = await http.get(f"/static/{path}", params={"v": ASSET_VERSION})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith(content_type)
    assert r.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.content == STATIC[path].body


async def test_unversioned_asset_gets_short_cache(http):
    r = await http.get("/static/app.css")
    assert r.status_code == 200 and r.headers["cache-control"] == "public, max-age=3600"
    r = await http.get("/static/app.css", params={"v": "stale"})
    assert r.headers["cache-control"] == "public, max-age=3600"


@pytest.mark.parametrize(
    "path",
    [
        "/static/nope.css",
        "/static/../pages.py",
        "/static/%2e%2e/pages.py",
        "/static/..%2fpages.py",
        "/static/fonts",
        "/static/",
        "/static/templates/base.html",
    ],
)
async def test_static_serves_only_known_files(http, path):
    r = await http.get(path)
    assert r.status_code == 404


def test_static_map_holds_only_whitelisted_types():
    assert STATIC, "static assets missing from the package"
    for name in STATIC:
        assert re.fullmatch(r"[A-Za-z0-9./-]+\.(css|js|svg|woff2|txt|png)", name), name
        assert ".." not in name


async def test_favicon_redirects_to_svg(http):
    r = await http.get("/favicon.ico")
    assert r.status_code == 301
    assert r.headers["location"] == f"/static/favicon.svg?v={ASSET_VERSION}"


async def test_pages_link_versioned_assets(http):
    page = await http.get("/login")
    assert f'href="/static/app.css?v={ASSET_VERSION}"' in page.text
    assert f'src="/static/app.js?v={ASSET_VERSION}"' in page.text
    assert f'href="/static/favicon.svg?v={ASSET_VERSION}"' in page.text


def test_templates_have_no_inline_script_or_style():
    """CSP is `default-src 'self'`: inline <script>, <style>, style="" and on*="" are blocked."""
    root = importlib.resources.files("postroom.web") / "templates"
    files = [f for f in root.iterdir() if f.name.endswith(".html")]
    files += [f for f in (root / "partials").iterdir() if f.name.endswith(".html")]
    assert files
    for f in files:
        html = f.read_text("utf-8")
        assert "<style" not in html, f.name
        assert not re.search(r"\sstyle=", html), f.name
        assert not re.search(r"\son[a-z]+=", html), f.name
        for tag in re.findall(r"<script\b[^>]*>", html):
            assert re.search(r'\ssrc="/static/', tag), (f.name, tag)


def test_font_licenses_ship_with_fonts():
    fonts = {n for n in STATIC if n.startswith("fonts/") and n.endswith(".woff2")}
    licenses = {n for n in STATIC if n.startswith("fonts/LICENSE-")}
    for family in ("zilla-slab", "atkinson-hyperlegible-next", "atkinson-hyperlegible-mono"):
        assert any(f.startswith(f"fonts/{family}-") for f in fonts), family
        assert f"fonts/LICENSE-{family}.txt" in licenses, family
    assert sum(len(STATIC[n].body) for n in fonts) < 300_000
