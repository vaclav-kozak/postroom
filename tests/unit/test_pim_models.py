from datetime import UTC, date, datetime, timedelta

import pytest

from postroom.pim.models import TZ, iso, parse_when, rescheduled, validate_range


def test_parse_when():
    assert parse_when("2026-09-25") == date(2026, 9, 25)
    d = parse_when("2026-09-25T10:00:00")
    assert d.tzinfo == TZ and d.hour == 10
    d = parse_when("2026-09-25T10:00:00+00:00")
    assert d.utcoffset() == timedelta(0)
    with pytest.raises(ValueError):
        parse_when("tomorrow")


def test_validate_range():
    validate_range(date(2026, 9, 25), date(2026, 9, 26))
    with pytest.raises(ValueError):
        validate_range(date(2026, 9, 26), date(2026, 9, 25))
    with pytest.raises(ValueError):
        validate_range(date(2026, 9, 25), datetime(2026, 9, 26, tzinfo=UTC))


def test_iso():
    assert iso(date(2026, 9, 25)) == "2026-09-25"
    assert iso(None) is None


def test_rescheduled_keeps_duration_when_only_start_moves():
    s, e = datetime(2026, 10, 1, 9, tzinfo=TZ), datetime(2026, 10, 1, 10, tzinfo=TZ)
    assert rescheduled(s, e, s + timedelta(hours=2), None) == (
        s + timedelta(hours=2),
        e + timedelta(hours=2),
    )
    assert rescheduled(date(2026, 10, 5), date(2026, 10, 7), date(2026, 10, 9), None) == (
        date(2026, 10, 9),
        date(2026, 10, 11),
    )
    assert rescheduled(s, e, None, e + timedelta(hours=1)) == (s, e + timedelta(hours=1))
    with pytest.raises(ValueError):
        rescheduled(s, e, date(2026, 10, 1), None)
    with pytest.raises(ValueError):
        rescheduled(s, e, None, s)
