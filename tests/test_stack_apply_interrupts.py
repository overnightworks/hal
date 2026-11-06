"""A Ctrl-C after the yes is one red row with its subject, then the pair, on the scripted
boundaries of `tests/support/stack_apply.py`."""

import shutil

from support.stack_apply import (
    applied_core,  # noqa: F401 the fixture, requested by name below
    at_terminal,  # noqa: F401 the fixture, requested by name below
    core_files,  # noqa: F401 the fixture, requested by name below
    edit_traefik_yml,
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
)
from support.stack_plan_rows import detail_lines, find_row
from test_stack_apply_legal import world  # noqa: F401 the fixture, requested by name below

from hal.output.command import Verb, command
from hal.stack import appkit_step, apply, core, legal_step, unit_plans
from hal.stack.result_rows import ResultEvent

PARTIAL = "its state may be partial"


def ctrl_c(*_arguments: object) -> None:
    raise KeyboardInterrupt


def assert_interrupted_at(exit_code: int, out: str, err: str, subject: str, step: str) -> None:
    """The row, its pair and the exit of the run; the line the row replaced is gone."""
    assert exit_code == apply.ApplyExit.REFUSED
    assert find_row(out, subject, ResultEvent.INTERRUPTED, f"{step} · {PARTIAL}")
    assert err.splitlines()[-2:] == [
        f"error: interrupted at {subject}",
        f"next: {command(Verb.APPLY)}",
    ]
    assert "interrupted while changing" not in err
    assert "Traceback" not in err


def test_a_ctrl_c_in_the_appkit_write_names_appkit(switch, repository):  # noqa: F811
    for target in appkit_step.served_directories(repository):
        shutil.rmtree(target)

    exit_code, out, err = switch(rename=ctrl_c)

    assert_interrupted_at(exit_code, out, err, "appkit", "write the appkit files")


def test_a_ctrl_c_in_the_legal_write_names_legal(world, monkeypatch):  # noqa: F811
    monkeypatch.setattr(legal_step, "_replace", ctrl_c)

    exit_code, out, err = world.switch()

    assert_interrupted_at(exit_code, out, err, "legal", "write the legal pages")


def test_a_ctrl_c_in_a_core_recreate_names_the_service_and_its_step(
    applied_core,  # noqa: F811
    switch,  # noqa: F811
    scripted,  # noqa: F811
    repository,  # noqa: F811
):
    edit_traefik_yml(repository)
    scripted.verb_up = ctrl_c

    exit_code, out, err = switch()

    assert_interrupted_at(exit_code, out, err, "traefik", "recreate traefik")
    assert detail_lines(out) == []


def test_a_ctrl_c_while_no_unit_is_set_names_core(
    applied_core,  # noqa: F811
    switch,  # noqa: F811
    repository,  # noqa: F811
    monkeypatch,
):
    edit_traefik_yml(repository)
    monkeypatch.setattr(core, "followed_services", ctrl_c)

    exit_code, out, err = switch()

    assert_interrupted_at(exit_code, out, err, "core", "find the services edge follows")


def test_a_ctrl_c_with_a_unit_and_no_step_says_only_that_its_state_may_be_partial(
    switch,  # noqa: F811
    monkeypatch,
):
    monkeypatch.setattr(unit_plans._Starter, "__init__", ctrl_c)

    exit_code, out, err = switch()

    assert exit_code == apply.ApplyExit.REFUSED
    row = find_row(out, "step-ca", ResultEvent.INTERRUPTED, PARTIAL)
    assert row
    assert " · " not in row.group(0)
    assert err.splitlines()[-2:] == ["error: interrupted at step-ca", "next: hal apply"]
