"""Final fix round: memory bounds on HTML conversion and message parsing."""

import threading

import pytest

from postroom.mail import heavy, parse
from postroom.mail.heavy import ServerBusy, heavy_work


class CountingSoup:
    """Wraps BeautifulSoup to count how many times HTML is parsed into a tree."""

    def __init__(self, monkeypatch):
        self.calls = 0
        real = parse.BeautifulSoup

        def soup(*args, **kwargs):
            self.calls += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(parse, "BeautifulSoup", soup)


def test_html_is_parsed_into_a_tree_only_once(monkeypatch):
    soup = CountingSoup(monkeypatch)
    text = parse.html_to_text("<h1>Title</h1><p>Hello <b>world</b></p>")
    assert text == "# Title\n\nHello **world**"
    assert soup.calls == 1


def test_tag_dense_html_skips_the_tree_converter(monkeypatch):
    soup = CountingSoup(monkeypatch)
    html = "<b>x</b>" * (parse._MAX_RICH_HTML_TAGS // 2 + 1)
    text = parse.html_to_text(html)
    assert soup.calls == 0
    assert text.replace("\n", "").startswith("xxx")


def test_html_just_under_the_tag_cap_is_still_converted(monkeypatch):
    soup = CountingSoup(monkeypatch)
    html = "<b>x</b>" * (parse._MAX_RICH_HTML_TAGS // 2)
    assert parse.html_to_text(html).startswith("**x**")
    assert soup.calls == 1


def test_script_and_style_do_not_count_towards_the_tag_cap(monkeypatch):
    soup = CountingSoup(monkeypatch)
    script = "<script>" + "if (a<b) {}" * parse._MAX_RICH_HTML_TAGS + "</script>"
    text = parse.html_to_text(script + "<h2>Report</h2><style>p<x{}</style>")
    assert text == "## Report"
    assert soup.calls == 1


def test_html_conversion_waits_for_the_heavy_work_gate(monkeypatch):
    monkeypatch.setattr(heavy, "HEAVY_WAIT_SECONDS", 0.05)
    holding = threading.Event()
    release = threading.Event()

    def holder():
        with heavy_work():
            holding.set()
            release.wait(5)

    t = threading.Thread(target=holder)
    t.start()
    holding.wait(5)
    try:
        with pytest.raises(ServerBusy):
            parse.html_to_text("<p>hi</p>")
    finally:
        release.set()
        t.join()


# -- header cap ------------------------------------------------------------------------


def test_header_bomb_is_capped_before_parsing():
    import tracemalloc

    raw = (
        b"From: a@b.example.net\r\nSubject: hello\r\n"
        + b"X-Junk: a\r\n" * 600_000  # ~6.6 MiB of header lines: +145 MiB to parse whole
        + b"Content-Type: text/html\r\n\r\n<p>the body text survives the header cap</p>\r\n"
    )
    tracemalloc.start()
    msg = parse.parse_message(raw)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert msg.subject == "hello" and msg.from_ == "a@b.example.net"
    assert "the body text survives" in msg.body_text
    assert peak < 40 * 2**20


def test_normal_headers_are_untouched():
    raw = b"Subject: s\r\nX-A: " + b"b" * 1000 + b"\r\n\r\n" + b"body " * 100_000
    assert parse._cap_header(raw) is raw
