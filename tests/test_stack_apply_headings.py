"""After the yes `hal apply --local` prints each result row under its plan group's heading, on the
scripted boundaries of `tests/support/stack_apply.py`."""

import re
import stat
from collections.abc import Callable

import pytest
from support.stack_apply import (
    DISABLED,
    ENABLED,
    LITELLM_ON,
    PROBE_ENABLED,
    applied_core,  # noqa: F401 the fixture, requested by name below
    at_terminal,  # noqa: F401 the fixture, requested by name below
    core_files,  # noqa: F401 the fixture, requested by name below
    edit_traefik_yml,
    home,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    litellm_running,
    realm_backup,  # noqa: F401 the fixture, requested by name below
    realm_unit,  # noqa: F401 the fixture, requested by name below
    repository,  # noqa: F401 the fixture, requested by name below
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    secret_files,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    step_ca_applied,  # noqa: F401 the fixture, requested by name below
    switch,  # noqa: F401 the fixture, requested by name below
    write_fleet,
)
from support.stack_apply_apps import (
    RELEASE,
    app_world,  # noqa: F401 the fixture, requested by name below
)
from support.stack_litellm_found import APPS, BUDGET_ID
from support.stack_plan_rows import plain

import hal.output
from hal.output import Glyph
from hal.stack import compose, litellm_keys
from hal.stack.litellm_keys import ADMIN_BUDGET_ID
from hal.stack.plan_rows import PlanGroup
from hal.stack.realm.reconcile import REALM_UNIT

VERDICT = "✓ applied"
DETAIL_PREFIX = "    "
ROW = re.compile(r"^  (\S) (\S+)")


def done(subject: str) -> str:
    return f"{Glyph.DONE.value} {subject}"


def failed(subject: str) -> str:
    return f"{Glyph.FAILED.value} {subject}"


def key_rows(*extra: str) -> list[str]:
    """The person budget and one key per app, each made."""
    return [done(BUDGET_ID), *(done(app) for app in APPS), *extra]


def outline(out: str) -> list[str]:
    """What stands after the yes: each heading as its text, each row as `glyph subject`."""
    after_the_yes = plain(out).partition("Type yes")[2].splitlines()[1:]
    entries = []
    for line in after_the_yes:
        if line.startswith((VERDICT, DETAIL_PREFIX)):
            continue
        row = ROW.match(line)
        entries.append(f"{row[1]} {row[2]}" if row else line)
    return entries


def headings_of(entries: list[str]) -> list[str]:
    return [entry for entry in entries if entry[1:2] != " "]


@pytest.fixture
def keys(repository, scripted, secret_files):  # noqa: F811
    """The unit `litellm` on beside a disabled step-ca, with no key and no budget made yet."""
    write_fleet(repository, DISABLED + LITELLM_ON)
    running = litellm_running(repository, scripted, secret_files)
    running.rows = dict.fromkeys(APPS)
    running.budget = None
    return running


@pytest.fixture
def headed_from_one_row(monkeypatch: pytest.MonkeyPatch) -> None:
    """Plans of a few rows print their headings, for cases that route rare rows."""
    monkeypatch.setattr(hal.output, "HEADING_THRESHOLD", 1)


def test_a_headed_plan_prints_core_units_and_litellm_each_with_its_first_result_row(
    applied_core,  # noqa: F811
    keys,
    switch,  # noqa: F811
    repository,  # noqa: F811
):
    edit_traefik_yml(repository)
    write_fleet(repository, PROBE_ENABLED + LITELLM_ON)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert outline(out) == [
        PlanGroup.CORE,
        done("traefik"),
        PlanGroup.UNITS,
        done("step-ca"),
        done("probe"),
        PlanGroup.LITELLM,
        *key_rows(),
    ]


def test_a_headed_plan_prints_apps_after_litellm_with_the_first_app_row(
    keys,
    app_world,  # noqa: F811
):
    with (app_world.repository / "fleet.yaml").open("a") as fleet:
        fleet.write(LITELLM_ON)
    app_world.origin.release(RELEASE)
    keys.admin_budget = None

    exit_code, out, _ = app_world.apply()

    assert exit_code == 0
    assert outline(out) == [
        PlanGroup.LITELLM,
        *key_rows(done(ADMIN_BUDGET_ID)),
        PlanGroup.APPS,
        done("hopin"),
    ]


def test_a_group_with_no_result_row_prints_no_heading(
    applied_core,  # noqa: F811
    keys,
    switch,  # noqa: F811
    repository,  # noqa: F811
):
    edit_traefik_yml(repository)
    keys.admin_budget = None

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert headings_of(outline(out)) == [PlanGroup.CORE, PlanGroup.LITELLM]


def test_a_plan_below_six_rows_prints_its_results_flat(keys, switch, repository):  # noqa: F811
    write_fleet(repository, ENABLED + LITELLM_ON)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert outline(out) == [done("step-ca"), *key_rows()]
    assert headings_of(outline(out)) == []


@pytest.mark.parametrize("headed", [True, False], ids=["headed", "flat"])
@pytest.mark.parametrize(
    ("crashing", "order"),
    [
        ("step-ca", [failed("step-ca"), done("probe")]),
        ("hello", [done("step-ca"), failed("hello")]),
    ],
    ids=["failure first", "failure last"],
)
def test_failed_and_switched_units_print_in_switch_order_before_the_key_rows_each_failure_once(
    headed,
    crashing,
    order,
    keys,
    switch,  # noqa: F811
    scripted,  # noqa: F811
    repository,  # noqa: F811
):
    write_fleet(repository, PROBE_ENABLED + (LITELLM_ON if headed else ""))
    scripted.crash_loops = {crashing}

    exit_code, out, err = switch()

    assert exit_code == 1
    expected = [PlanGroup.UNITS, *order, PlanGroup.LITELLM, *key_rows()]
    assert outline(out) == (expected if headed else order)
    assert err.count("error: partial,") == 1


def test_a_raise_in_a_later_step_leaves_the_failed_unit_rows_already_printed(
    keys,
    switch,  # noqa: F811
    scripted,  # noqa: F811
    repository,  # noqa: F811
    monkeypatch,
):
    write_fleet(repository, PROBE_ENABLED + LITELLM_ON)
    scripted.crash_loops = {"step-ca"}

    def refuse(*_: object) -> None:
        raise compose.ComposeError("the key step could not run")

    monkeypatch.setattr(litellm_keys, "run_keys", refuse)

    exit_code, out, err = switch()

    assert exit_code == 1
    assert outline(out)[:3] == [PlanGroup.UNITS, failed("step-ca"), done("probe")]
    assert err.count("error: partial, step-ca") == 1


@pytest.mark.usefixtures("headed_from_one_row")
@pytest.mark.parametrize(
    ("arrange", "expected"),
    [
        pytest.param(
            lambda keys: setattr(keys, "read_fails", True),
            [f"{Glyph.NEEDS_YOU.value} litellm"],
            id="skipped",
        ),
        pytest.param(
            lambda keys: (setattr(keys, "fail_at", 1), setattr(keys, "cause", "name taken")),
            [
                done(BUDGET_ID),
                failed(APPS[0]),
                *(f"{Glyph.UNCHANGED.value} {app}" for app in APPS[1:]),
            ],
            id="failed",
        ),
    ],
)
def test_the_key_step_rows_stand_under_litellm_the_skipped_and_failed_ones_too(
    arrange: Callable[[object], object],
    expected: list[str],
    keys,
    switch,  # noqa: F811
    repository,  # noqa: F811
):
    write_fleet(repository, ENABLED + LITELLM_ON)
    arrange(keys)

    _, out, _ = switch()

    shown = outline(out)
    assert shown[shown.index(PlanGroup.LITELLM) + 1 :] == expected
    assert shown.count(PlanGroup.LITELLM) == 1


RECREATES = [
    pytest.param(PlanGroup.CORE, "traefik", id="core"),
    pytest.param(PlanGroup.UNITS, "step-ca", id="unit service"),
]


def drift(group: PlanGroup, tree, compose_script) -> None:
    """The service of `group` that a recreate changes."""
    if group is PlanGroup.CORE:
        edit_traefik_yml(tree)
    else:
        compose_script.change_definition("step-ca")


@pytest.mark.usefixtures("headed_from_one_row")
@pytest.mark.parametrize(("group", "subject"), RECREATES)
def test_a_failed_recreate_stands_under_the_heading_of_the_step_that_failed(
    group,
    subject,
    step_ca_applied,  # noqa: F811
    switch,  # noqa: F811
    scripted,  # noqa: F811
    repository,  # noqa: F811
):
    drift(group, repository, scripted)
    scripted.crash_loops = {subject}

    exit_code, out, _ = switch()

    assert exit_code == 1
    assert outline(out) == [group, failed(subject)]


@pytest.mark.usefixtures("headed_from_one_row", "realm_unit")
def test_the_waiting_row_of_a_stopped_hal_is_the_first_row_under_units(
    switch,  # noqa: F811
    repository,  # noqa: F811
    monkeypatch,
):
    monkeypatch.setattr("hal.stack.pre_apply.BACKUP_SECONDS", 1)
    monkeypatch.setattr("hal.stack.pre_apply.STOP_GRACE_SECONDS", 0.2)
    hal = repository / ".venv/bin/hal"
    hal.parent.mkdir(parents=True)
    hal.write_text("#!/bin/sh\nexec sleep 30\n")
    hal.chmod(hal.stat().st_mode | stat.S_IXUSR)

    _, out, _ = switch(installed_backup=True)

    assert outline(out)[:2] == [PlanGroup.UNITS, f"{Glyph.ANNOUNCE.value} {REALM_UNIT}"]


def ctrl_c(*_arguments: object) -> None:
    raise KeyboardInterrupt


@pytest.mark.usefixtures("headed_from_one_row")
@pytest.mark.parametrize(("group", "subject"), RECREATES)
def test_a_ctrl_c_row_ends_the_open_line_then_stands_under_the_heading_of_its_step(
    group,
    subject,
    step_ca_applied,  # noqa: F811
    switch,  # noqa: F811
    scripted,  # noqa: F811
    repository,  # noqa: F811
):
    drift(group, repository, scripted)
    scripted.verb_up = ctrl_c

    exit_code, out, _ = switch()

    assert exit_code == 1
    assert outline(out) == ["", group, failed(subject)]
