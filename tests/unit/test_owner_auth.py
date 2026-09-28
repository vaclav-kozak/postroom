from postroom.auth.owner import LoginGuard, safe_next


def test_ip_lockout(db):
    now = [10_000.0]
    g = LoginGuard(db, clock=lambda: now[0])
    for _ in range(4):
        g.record("1.1.1.1", False)
    assert g.blocked_for("1.1.1.1") == 0
    g.record("1.1.1.1", False)
    assert 890 <= g.blocked_for("1.1.1.1") <= 900
    assert g.blocked_for("2.2.2.2") == 0
    now[0] += 901
    assert g.blocked_for("1.1.1.1") == 0


def test_global_lockout(db):
    now = [10_000.0]
    g = LoginGuard(db, clock=lambda: now[0])
    for i in range(20):
        g.record(f"10.0.0.{i}", False)
    assert g.blocked_for("9.9.9.9") > 3000


def test_safe_next():
    assert safe_next("/consent?txn=abc") == "/consent?txn=abc"
    for bad in (
        None,
        "",
        "https://evil.example",
        "//evil.example",
        "/\\evil.example",
        "javascript:x",
    ):
        assert safe_next(bad) == "/admin"
