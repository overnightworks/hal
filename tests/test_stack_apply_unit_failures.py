"""A failure of the unit switch after the yes is a red row with the way on, never a bare
sentence, on the scripted boundaries of `tests/support/stack_apply.py`."""

from support.stack_apply import (
    DISABLED,
    STEP_CA_SERVICES,
    SWITCHED_OFF_AT,
    at_terminal,  # noqa: F401 the fixture, requested by name below
    home,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    realm_backup,  # noqa: F401 the fixture, requested by name below
    repository,  # noqa: F401 the fixture, requested by name below
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    switch,  # noqa: F401 the fixture, requested by name below
    switch_off,
    write_fleet,
)
from support.stack_apply_fakes import container_name
from support.stack_plan_rows import find_row, plain

from hal.output.command import Verb, command
from hal.stack.result_rows import ResultEvent
from hal.stack.switches import describe_since

LOGS = "docker logs --tail 50"


def partial_pair(subject: str, event: ResultEvent, next_step: str) -> str:
    return f"error: partial, {subject} {event}\nnext: {next_step}"


def row_line(out: str, subject: str, event: ResultEvent) -> str:
    return next(line for line in plain(out).splitlines() if find_row(line, subject, event))


def test_a_service_seen_down_after_the_start_is_a_red_row_with_its_log_next(
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    scripted.crash_loops = {"step-ca"}

    exit_code, out, err = switch()

    assert exit_code == 1
    assert row_line(out, "step-ca", ResultEvent.NOT_RUNNING).endswith("of the start")
    assert (
        partial_pair("step-ca", ResultEvent.NOT_RUNNING, f"{LOGS} {container_name('step-ca')}")
        in err
    )
    assert not find_row(out, "step-ca", ResultEvent.SWITCHED_ON)
    assert "after the change" not in err


def test_every_service_of_a_unit_that_never_started_is_a_row_and_apply_is_next(
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    scripted.starts_nothing = True

    exit_code, out, err = switch()

    assert exit_code == 1
    for service in STEP_CA_SERVICES:
        assert find_row(out, service, ResultEvent.NOT_RUNNING, "of the start")
    assert partial_pair(STEP_CA_SERVICES[0], ResultEvent.NOT_RUNNING, command(Verb.APPLY)) in err


def test_a_switch_that_appears_while_the_prompt_waits_is_a_row_that_ends_not_started(
    switch,  # noqa: F811
    scripted,  # noqa: F811
    state,  # noqa: F811
):
    exit_code, out, err = switch(while_prompt_waits=lambda: switch_off(state))

    assert exit_code == 1
    line = row_line(out, "step-ca", ResultEvent.APP_HELD_OFF)
    assert f"since {describe_since(SWITCHED_OFF_AT)} · " in line
    assert line.endswith("not started")
    assert partial_pair("step-ca", ResultEvent.APP_HELD_OFF, command(Verb.START, "step-ca")) in err
    assert scripted.changing_verbs() == []


def test_a_unit_whose_container_remains_after_the_switch_off_is_not_off(
    switch,  # noqa: F811
    scripted,  # noqa: F811
    repository,  # noqa: F811
    monkeypatch,
):
    switch()
    write_fleet(repository, DISABLED)
    monkeypatch.setattr(scripted, "verb_rm", lambda *_: "")

    exit_code, out, err = switch()

    assert exit_code == 1
    assert row_line(out, "step-ca", ResultEvent.NOT_OFF).endswith("a container of it remains")
    assert partial_pair("step-ca", ResultEvent.NOT_OFF, command(Verb.APPLY)) in err
    assert not find_row(out, "step-ca", ResultEvent.SWITCHED_OFF)
    assert "after the change" not in err


def test_a_failed_step_of_the_unit_switch_is_a_failed_row_with_the_cause(
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    scripted.failing_verb = "up"

    exit_code, out, err = switch()

    assert exit_code == 1
    assert row_line(out, "step-ca", ResultEvent.FAILED).endswith(
        "could not start · `docker compose up` exited 1: last line"
    )
    assert partial_pair("step-ca", ResultEvent.FAILED, command(Verb.APPLY)) in err
    assert not find_row(out, "step-ca", ResultEvent.SWITCHED_ON)
