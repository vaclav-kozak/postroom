from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from postroom.pim.models import iso, parse_when, rescheduled, validate_range

# Any zone with a UTC offset and DST works; the server default is UTC.
TZ = ZoneInfo("Europe/Berlin")


def test_parse_when():
    assert parse_when("2026-09-25", TZ) == date(2026, 9, 25)
    d = parse_when("2026-09-25T10:00:00", TZ)
    assert d.tzinfo == TZ and d.hour == 10
    d = parse_when("2026-09-25T10:00:00+00:00", TZ)
    assert d.utcoffset() == timedelta(0)
    with pytest.raises(ValueError):
        parse_when("tomorrow", TZ)


def test_validate_range():
    validate_range(date(2026, 9, 25), date(2026, 9, 26), TZ)
    with pytest.raises(ValueError):
        validate_range(date(2026, 9, 26), date(2026, 9, 25), TZ)
    with pytest.raises(ValueError):
        validate_range(date(2026, 9, 25), datetime(2026, 9, 26, tzinfo=UTC), TZ)


def test_iso():
    assert iso(date(2026, 9, 25)) == "2026-09-25"
    assert iso(None) is None


def test_rescheduled_keeps_duration_when_only_start_moves():
    s, e = datetime(2026, 10, 1, 9, tzinfo=TZ), datetime(2026, 10, 1, 10, tzinfo=TZ)
    assert rescheduled(s, e, s + timedelta(hours=2), None, TZ) == (
        s + timedelta(hours=2),
        e + timedelta(hours=2),
    )
    assert rescheduled(date(2026, 10, 5), date(2026, 10, 7), date(2026, 10, 9), None, TZ) == (
        date(2026, 10, 9),
        date(2026, 10, 11),
    )
    assert rescheduled(s, e, None, e + timedelta(hours=1), TZ) == (s, e + timedelta(hours=1))
    with pytest.raises(ValueError):
        rescheduled(s, e, date(2026, 10, 1), None, TZ)
    with pytest.raises(ValueError):
        rescheduled(s, e, None, s, TZ)


def test_naive_times_follow_the_given_zone():
    utc = ZoneInfo("UTC")
    assert parse_when("2026-09-25T10:00:00", utc).utcoffset() == timedelta(0)
    assert parse_when("2026-09-25T10:00:00", TZ).utcoffset() == timedelta(hours=2)
    # A naive end compared with an aware start: read in the zone passed in.
    start = datetime(2026, 9, 25, 9, 30, tzinfo=UTC)
    naive_end = datetime(2026, 9, 25, 10, 0)  # noqa: DTZ001 -- naive on purpose
    validate_range(start, naive_end, utc)
    with pytest.raises(ValueError):
        validate_range(start, naive_end, TZ)  # 08:00 UTC
