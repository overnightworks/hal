"""The admin budget's plan rows (#965): its budget, its customer rows as counts, and the rows held
or not read; never a fingerprint."""

import pytest
from support.stack_plan_rows import groups_of, plan_of

from hal.output import Glyph, Row
from hal.stack import core
from hal.stack.litellm_keys import (
    ADMIN_BUDGET_ID,
    AdminHeld,
    Change,
    FieldChange,
    KeysPlan,
    RowChange,
    Target,
)
from hal.stack.plan_rows import KeysEvent, PlanGroup, changes_in
from hal.stack.realm.reconcile import MembersNotRead

PRINTS = tuple(f"fp-{digit * 64}" for digit in "0123")
NEW_ADMIN = Change(
    Target.BUDGET, ADMIN_BUDGET_ID, True, (FieldChange("budget_duration", None, "1mo"),)
)


def linked(fingerprint: str, new: bool = False) -> RowChange:
    return RowChange(fingerprint, ADMIN_BUDGET_ID, True, new)


def unlinked(fingerprint: str) -> RowChange:
    return RowChange(fingerprint, ADMIN_BUDGET_ID, False, False)


def litellm_rows(keys: KeysPlan) -> tuple[Row, ...]:
    group = groups_of(keys=keys)[3]
    assert group.heading is PlanGroup.LITELLM
    return group.rows


@pytest.mark.parametrize(
    ("keys", "expected"),
    [
        pytest.param(
            KeysPlan((NEW_ADMIN, unlinked(PRINTS[0]), linked(PRINTS[1], True), linked(PRINTS[2]))),
            (
                Row(Glyph.ADD, ADMIN_BUDGET_ID, KeysEvent.NEW_BUDGET, "1mo"),
                Row(
                    Glyph.CHANGE, ADMIN_BUDGET_ID, KeysEvent.CUSTOMER_ROWS, "2 linked · 1 unlinked"
                ),
            ),
            id="a new admin budget and its rows as counts",
        ),
        pytest.param(
            KeysPlan((linked(PRINTS[0]),)),
            (Row(Glyph.CHANGE, ADMIN_BUDGET_ID, KeysEvent.CUSTOMER_ROWS, "1 linked"),),
            id="a count of none is left out",
        ),
        pytest.param(
            KeysPlan(
                (
                    Change(
                        Target.BUDGET,
                        ADMIN_BUDGET_ID,
                        False,
                        (FieldChange("max_budget", 5.0, None),),
                    ),
                )
            ),
            (Row(Glyph.CHANGE, ADMIN_BUDGET_ID, KeysEvent.BUDGET_CHANGED, "budget 5 → none"),),
            id="a limit set by hand is cleared",
        ),
        pytest.param(
            KeysPlan(admin=AdminHeld(core.Gate.OFF)),
            (Row(Glyph.UNCHANGED, ADMIN_BUDGET_ID, KeysEvent.ROWS_HELD, "Keycloak is off"),),
            id="held while Keycloak is held",
        ),
        pytest.param(
            KeysPlan(admin=MembersNotRead("realm-observer exited 1: no\x1b")),
            (
                Row(
                    Glyph.NEEDS_YOU,
                    ADMIN_BUDGET_ID,
                    KeysEvent.MEMBERS_NOT_READ,
                    "realm-observer exited 1: no\\x1b",
                ),
            ),
            id="members not read, the cause escaped",
        ),
    ],
)
def test_the_admin_budget_is_its_budget_row_one_counted_row_of_customer_rows_or_why_not(
    keys: KeysPlan, expected: tuple[Row, ...]
) -> None:
    assert litellm_rows(keys) == expected


def test_the_admin_budgets_rows_follow_the_keys_and_come_before_a_taken_name() -> None:
    hopin = Change(Target.KEY, "hopin", True, (FieldChange("max_parallel_requests", None, 5),))
    keys = KeysPlan((hopin, NEW_ADMIN, linked(PRINTS[0])), ("songmaker",))

    assert [(row.subject, row.event) for row in litellm_rows(keys)] == [
        ("hopin", KeysEvent.NEW_KEY),
        (ADMIN_BUDGET_ID, KeysEvent.NEW_BUDGET),
        (ADMIN_BUDGET_ID, KeysEvent.CUSTOMER_ROWS),
        ("songmaker", KeysEvent.NAME_TAKEN),
    ]


def test_no_planned_row_names_a_fingerprint() -> None:
    keys = KeysPlan((NEW_ADMIN, *map(unlinked, PRINTS[:2]), *map(linked, PRINTS[2:])))

    printed = " ".join(f"{row.subject} {row.event} {row.fact}" for row in litellm_rows(keys))
    assert not any(fingerprint in printed for fingerprint in PRINTS)


def test_the_rows_row_counts_once_toward_the_changes_the_yes_counts() -> None:
    assert changes_in(plan_of(keys=KeysPlan(tuple(map(linked, PRINTS))))) == 1
