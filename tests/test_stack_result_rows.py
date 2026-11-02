"""The rows of a finished step: what a typed result prints as, with no step run."""

import pytest
from support.stack_plan_rows import APP, NEW, app_plan

from hal.output import Glyph
from hal.stack import realm as realm_lines
from hal.stack.apps import AppFailed, AppHeldOff, AppKind, AppOn, OffPlan
from hal.stack.realm.reconcile import (
    Leftovers,
    NotRecorded,
    OnlyInKeycloak,
    RealmApplied,
    RealmFailed,
    RealmSkipped,
    Stage,
)
from hal.stack.result_rows import app_partial, app_row, partial_error, result_rows, waiting_row

SNAPSHOT = "37c2a56056d17297895e58c1ff98493754064280352422f136596266498fe056"
REMOVAL = realm_lines.Change("hallucinai", realm_lines.Kind.REMOVAL, "group", "/console", members=0)
ADDITION = realm_lines.Change("hallucinai", realm_lines.Kind.ADDITION, "group", "/ops", members=2)
UNREAD = ("workflows", "defaultGroups", "userProfile")


def applied(
    *changes: realm_lines.Change, leftovers: Leftovers | NotRecorded, seconds: float = 11.4
) -> RealmApplied:
    return RealmApplied(SNAPSHOT, seconds, changes, leftovers)


NOT_RECORDED = NotRecorded("cannot write applied.json (Permission denied)")


def test_the_result_is_one_row_with_the_short_snapshot_the_count_and_the_time() -> None:
    leftovers = Leftovers((), (), True, UNREAD)

    (row,) = result_rows(applied(ADDITION, REMOVAL, leftovers=leftovers, seconds=71.9))

    assert (row.glyph, row.subject, str(row.event)) == (Glyph.DONE, "keycloak", "realm applied")
    assert row.fact == "2 changes · snapshot 37c2a560 proven · 1m11s"


def test_a_removal_is_reset_to_the_file_with_the_short_snapshot_under_the_row() -> None:
    (row,) = result_rows(applied(ADDITION, REMOVAL, leftovers=NOT_RECORDED))

    assert row.details == (
        "hallucinai: addition group /ops (2 members)",
        "hallucinai: removal group /console (0 members): reset to the file, "
        "pre-apply snapshot 37c2a560",
    )


@pytest.mark.parametrize(
    ("leftovers", "details"),
    [
        pytest.param(NOT_RECORDED, (), id="record not written: nothing listed"),
        pytest.param(
            Leftovers((), (), True, UNREAD),
            ("only in Keycloak: nothing · 3 kinds not read",),
            id="nothing",
        ),
        pytest.param(
            Leftovers(
                (OnlyInKeycloak("hallucinai", "group", "/console"),), ("elsewhere",), True, ("x",)
            ),
            (
                "only in Keycloak: hallucinai group /console",
                "only in Keycloak: elsewhere not listed, it was not observed",
                "only in Keycloak: 1 found · 1 realm not observed · 1 kind not read",
            ),
            id="found and absent",
        ),
        pytest.param(
            Leftovers((), ("elsewhere",), True, UNREAD),
            (
                "only in Keycloak: elsewhere not listed, it was not observed",
                "only in Keycloak: nothing · 1 realm not observed · 3 kinds not read",
            ),
            id="absent only",
        ),
        pytest.param(
            Leftovers((), (), False, UNREAD),
            ("only in Keycloak: not listed, the realm files could not be read",),
            id="files unreadable",
        ),
        pytest.param(
            Leftovers((OnlyInKeycloak("hallucinai", "group", "/a\x1b[31m\nb"),), (), True, ()),
            (
                "only in Keycloak: hallucinai group /a\\x1b[31m\\nb",
                "only in Keycloak: 1 found · 0 kinds not read",
            ),
            id="escaped name",
        ),
    ],
)
def test_what_is_only_in_keycloak_is_one_detail_each_then_one_summary(leftovers, details) -> None:
    (row,) = result_rows(applied(leftovers=leftovers))

    assert row.details == details


def test_no_changes_is_said_as_such() -> None:
    (row,) = result_rows(applied(leftovers=NOT_RECORDED))

    assert row.fact.startswith("no changes · ")


def test_a_skipped_realm_is_one_needs_you_row_with_the_reason_and_no_detail() -> None:
    (row,) = result_rows(RealmSkipped("the realm observer failed"))

    assert (row.glyph, row.subject, str(row.event)) == (
        Glyph.NEEDS_YOU,
        "keycloak",
        "realm skipped",
    )
    assert (row.fact, row.details) == ("the realm observer failed", ())


def test_a_settled_step_has_no_row() -> None:
    assert result_rows(None) == ()


WAY_BACK = 'way back: docs/backup.md "Restore Keycloak" · the next apply repeats the step'


@pytest.mark.parametrize(
    ("failed", "state", "details"),
    [
        pytest.param(
            RealmFailed("backup broke", Stage.BEFORE, None, False),
            "nothing applied",
            (),
            id="before any snapshot: no detail",
        ),
        pytest.param(
            RealmFailed("restore test broke", Stage.BEFORE, SNAPSHOT, False),
            "nothing applied",
            ("pre-apply snapshot 37c2a560 · unproven",),
            id="before config-cli, unproven",
        ),
        pytest.param(
            RealmFailed("observe broke", Stage.BEFORE, SNAPSHOT, True),
            "nothing applied",
            ("pre-apply snapshot 37c2a560 · proven",),
            id="before config-cli, proven",
        ),
        pytest.param(
            RealmFailed("docker compose run exited 1", Stage.APPLYING, SNAPSHOT, True),
            "may be partly applied",
            ("pre-apply snapshot 37c2a560 · proven", WAY_BACK),
            id="config-cli started",
        ),
        pytest.param(
            RealmFailed("checksums broke", Stage.APPLIED, SNAPSHOT, True),
            "applied, not observed",
            ("pre-apply snapshot 37c2a560 · proven", WAY_BACK),
            id="applied, not observed",
        ),
    ],
)
def test_a_failed_step_is_one_red_row_with_its_snapshot_and_way_back_under_it(
    failed: RealmFailed, state: str, details: tuple[str, ...]
) -> None:
    (row,) = result_rows(failed)

    assert (row.glyph, row.subject, str(row.event)) == (Glyph.FAILED, "keycloak", "realm failed")
    assert row.fact == f"{failed.cause} · {state}"
    assert row.details == details


def test_the_cause_of_a_failed_step_is_escaped_in_the_row() -> None:
    (row,) = result_rows(RealmFailed("a\x1b[31m\nb", Stage.BEFORE, None, False))

    assert row.fact == "a\\x1b[31m\\nb · nothing applied"


def test_a_record_that_cannot_be_written_keeps_its_applied_row_and_its_changes() -> None:
    (row,) = result_rows(applied(ADDITION, leftovers=NOT_RECORDED))

    assert (row.glyph, str(row.event)) == (Glyph.DONE, "realm applied")
    assert row.details == ("hallucinai: addition group /ops (2 members)",)


@pytest.mark.parametrize(
    ("result", "error"),
    [
        pytest.param(None, None, id="settled"),
        pytest.param(applied(leftovers=Leftovers((), (), True, ())), None, id="applied"),
        pytest.param(
            RealmSkipped("the realm observer failed"), "keycloak realm skipped", id="skip"
        ),
        pytest.param(
            RealmFailed("backup broke", Stage.BEFORE, None, False),
            "keycloak realm failed",
            id="failed",
        ),
        pytest.param(
            applied(leftovers=NOT_RECORDED),
            "realm: applied and observed, but the record could not be written "
            "(cannot write applied.json (Permission denied)); the next run repeats the step",
            id="record not written",
        ),
    ],
)
def test_the_run_ends_partial_with_the_words_of_its_step(result, error: str | None) -> None:
    assert partial_error(result) == error


def test_the_waiting_line_is_a_live_row_with_the_grace() -> None:
    row = waiting_row(120)

    assert (row.glyph, row.subject, str(row.event)) == (Glyph.ANNOUNCE, "keycloak", "waiting")
    assert row.fact == "up to 2m00s for hal to clean up"


@pytest.mark.parametrize(
    ("kind", "event"),
    [
        (AppKind.ON, "switched on"),
        (AppKind.START_AGAIN, "started again"),
        (AppKind.UPDATE, "updated"),
    ],
)
def test_an_app_that_is_on_is_a_done_row_with_its_tag_the_state_and_the_time(
    kind: AppKind, event: str
) -> None:
    row = app_row(AppOn(app_plan(kind), 102))

    assert (row.glyph, row.subject, str(row.event)) == (Glyph.DONE, "hopin", event)
    assert row.fact == f"{NEW} · running · 1m42s"


@pytest.mark.parametrize(
    ("result", "event", "next_command"),
    [
        (AppFailed(app_plan(AppKind.ON), "x"), "failed", "hal apply"),
        (AppFailed(OffPlan(APP), "x"), "switch off failed", "hal apply"),
        (AppHeldOff(app_plan(AppKind.ON), "x"), "switched off meanwhile", "hal start hopin"),
    ],
)
def test_a_failed_app_is_a_red_row_and_ends_partial_with_the_command_that_ends_it(
    result: AppFailed | AppHeldOff, event: str, next_command: str
) -> None:
    row = app_row(result)

    assert (row.glyph, row.subject, str(row.event)) == (Glyph.FAILED, "hopin", event)
    assert app_partial(result) == (f"partial, hopin {event}", next_command)


def test_the_cause_of_a_failed_app_is_escaped_in_the_row() -> None:
    row = app_row(AppFailed(app_plan(AppKind.ON), "a\x1b[31m\nb"))

    assert row.fact == "a\\x1b[31m\\nb"
