"""The cutoff of `hal expire`: what LiteLLM keeps goes after 90 UTC days without use."""

from datetime import UTC, date, datetime, timedelta, timezone

import pytest

from hal import litellm_expiry

NOON = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)
BEFORE_MIDNIGHT = datetime(2026, 11, 3, 23, 59, 59, tzinfo=UTC)
AFTER_MIDNIGHT = datetime(2026, 11, 4, 0, 0, 0, tzinfo=UTC)
# 00:30 on 4 November in UTC+01:00 is still 3 November in UTC.
BERLIN_AFTER_LOCAL_MIDNIGHT = datetime(2026, 11, 4, 0, 30, tzinfo=timezone(timedelta(hours=1)))


@pytest.mark.parametrize(
    ("now", "row_day", "goes"),
    [
        (NOON, date(2026, 8, 6), False),
        (NOON, date(2026, 8, 5), False),
        (NOON, date(2026, 8, 4), True),
        (BEFORE_MIDNIGHT, date(2026, 8, 5), False),
        (BEFORE_MIDNIGHT, date(2026, 8, 4), True),
        (AFTER_MIDNIGHT, date(2026, 8, 6), False),
        (AFTER_MIDNIGHT, date(2026, 8, 5), True),
        (BERLIN_AFTER_LOCAL_MIDNIGHT, date(2026, 8, 5), False),
        (BERLIN_AFTER_LOCAL_MIDNIGHT, date(2026, 8, 4), True),
    ],
    ids=[
        "89-days-back-stays",
        "90-days-back-stays",
        "91-days-back-goes",
        "before-utc-midnight-90-stays",
        "before-utc-midnight-91-goes",
        "after-utc-midnight-89-stays",
        "after-utc-midnight-91-goes",
        "other-zone-counts-the-utc-day-90-stays",
        "other-zone-counts-the-utc-day-91-goes",
    ],
)
def test_a_daily_row_goes_only_when_its_utc_day_lies_more_than_90_days_back(
    now: datetime, row_day: date, goes: bool
) -> None:
    assert (row_day < litellm_expiry.cutoff(now).day) is goes


@pytest.mark.parametrize(
    ("last_used", "goes"),
    [
        (NOON - timedelta(days=89), False),
        (NOON - timedelta(days=90), False),
        (NOON - timedelta(days=90, seconds=1), True),
        (NOON - timedelta(days=91), True),
    ],
    ids=["89-days-stays", "exactly-90-days-stays", "just-over-90-days-goes", "91-days-goes"],
)
@pytest.mark.parametrize(
    "now", [NOON, NOON.astimezone(timezone(timedelta(hours=-7)))], ids=["utc", "other-zone"]
)
def test_a_tool_goes_only_when_unused_for_more_than_90_days(
    now: datetime, last_used: datetime, goes: bool
) -> None:
    moment = litellm_expiry.cutoff(now).moment

    assert moment.utcoffset() == timedelta(0)
    assert (last_used < moment) is goes
