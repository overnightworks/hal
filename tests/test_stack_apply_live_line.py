"""After the yes, `hal apply` shows one live line with the step it runs: its frames follow
`Progress.begin`, every row erases the line first, and a Ctrl-C keeps its frame for the row below,
on the scripted boundaries of `tests/support/stack_apply.py`."""

import io
import shutil
import stat
import subprocess
import sys

import pytest
from support.stack_apply import (
    applied_core,  # noqa: F401 the fixture, requested by name below
    at_terminal,  # noqa: F401 the fixture, requested by name below
    core_files,  # noqa: F401 the fixture, requested by name below
    edit_traefik_yml,
    home,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    realm_backup,  # noqa: F401 the fixture, requested by name below
    realm_unit,  # noqa: F401 the fixture, requested by name below
    repository,  # noqa: F401 the fixture, requested by name below
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    switch,  # noqa: F401 the fixture, requested by name below
)
from support.stack_plan_rows import find_row, plain
from support.terminal_support import (
    ANSI,
    ERASE,
    TerminalStream,
    frames_of,
    press_ctrl_c,
    put_on_terminals,
    ticking_line,
)

import hal.output
from hal.output import LIVE_FRAMES, Glyph, verbose_run
from hal.stack import appkit_step, pre_apply
from hal.stack.realm.reconcile import REALM_UNIT
from hal.stack.result_rows import ResultEvent
from hal.stack.unit_plans import Progress


def a_person_watches(monkeypatch: pytest.MonkeyPatch) -> TerminalStream:
    """Stderr a terminal with colour, outside `-v` and JSON, as wide as no step is cut; the run
    puts stdout on its own terminal. Called in the test body: pytest swaps `sys.stderr` again
    between fixture setup and the call."""
    _, err = put_on_terminals(monkeypatch)
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    monkeypatch.setenv("COLUMNS", "200")
    return err


@pytest.fixture
def begun(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Each step `Progress.begin` started, under its subject, in order."""
    steps: list[tuple[str, str]] = []
    begin = Progress.begin

    def recorded(progress: Progress, step: str) -> None:
        steps.append((progress.subject, step))
        begin(progress, step)

    monkeypatch.setattr(Progress, "begin", recorded)
    return steps


@pytest.fixture
def stills(monkeypatch: pytest.MonkeyPatch) -> None:
    """The thread never redraws, so every frame is one `show`."""
    monkeypatch.setattr(hal.output, "LIVE_TICK_SECONDS", 3600)


def on_one_terminal(monkeypatch: pytest.MonkeyPatch):
    """Once the yes is asked, stderr is the terminal stdout is: one buffer orders frame and row."""
    return lambda: monkeypatch.setattr(sys, "stderr", sys.stdout)


def missing_appkit(tree) -> None:
    for target in appkit_step.served_directories(tree):
        shutil.rmtree(target)


def frame_words(frame: str) -> list[str]:
    """A frame's subject and step, without the spinner and the time."""
    return frame.split()[1:-2]


def step_words(subject: str, step: str) -> list[str]:
    return [subject, *step.split()]


def last_frame(out: str) -> list[str]:
    """The words of the last frame drawn on a terminal both streams share: the text after the
    last carriage return, up to the end of its line."""
    return frame_words(ANSI.sub("", out.split("\r")[-1]).split("\n")[0])


@pytest.mark.usefixtures("applied_core", "stills")
def test_the_frames_follow_the_begun_steps_and_stdout_is_the_run_without_the_line(
    switch,  # noqa: F811
    repository,  # noqa: F811
    begun,
    monkeypatch,
):
    person = a_person_watches(monkeypatch)
    missing_appkit(repository)
    _, with_the_line, _ = switch()
    shown = [step_words(*step) for step in begun if step[1]]
    missing_appkit(repository)
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    _, without_the_line, _ = switch()

    assert [frame_words(frame) for frame in frames_of(person)] == shown
    assert with_the_line == without_the_line


@pytest.mark.usefixtures("applied_core", "stills")
def test_stderr_ends_on_the_erase_of_the_line(switch, repository, monkeypatch):  # noqa: F811
    person = a_person_watches(monkeypatch)
    edit_traefik_yml(repository)

    switch()

    assert frames_of(person)
    assert person.getvalue().endswith(ERASE)


@pytest.mark.usefixtures("applied_core", "stills")
def test_a_key_step_without_a_row_leaves_the_verdict_on_a_clean_line(
    switch,  # noqa: F811
    repository,  # noqa: F811
    begun,
    monkeypatch,
):
    a_person_watches(monkeypatch)
    edit_traefik_yml(repository)

    exit_code, out, _ = switch(while_prompt_waits=on_one_terminal(monkeypatch))

    drawn, _, after_the_erase = out.rpartition(ERASE)
    assert exit_code == 0
    assert begun[-1][1] == "apply the key step"
    assert last_frame(drawn) == step_words(*begun[-1])
    assert plain(after_the_erase).startswith(f"{Glyph.DONE.value} ")
    assert "\r" not in after_the_erase


@pytest.mark.usefixtures("applied_core")
def test_a_ctrl_c_in_a_recreate_keeps_its_frame_and_the_row_stands_below_it_with_no_frame_after(
    switch,  # noqa: F811
    scripted,  # noqa: F811
    repository,  # noqa: F811
    monkeypatch,
):
    a_person_watches(monkeypatch)
    edit_traefik_yml(repository)
    scripted.verb_up = lambda *_arguments: press_ctrl_c()
    ticks = ticking_line(monkeypatch)

    _, out, _ = switch(while_prompt_waits=on_one_terminal(monkeypatch))

    row = find_row(out, "traefik", ResultEvent.INTERRUPTED, "recreate traefik")
    assert row
    assert ticks.redrawer_ended()
    kept, below = plain(out)[: row.start()], plain(out)[row.start() :]
    assert last_frame(kept) == ["traefik", "recreate", "traefik"]
    assert kept.endswith("\n")
    assert not kept.endswith("\n\n")
    assert "\r" not in below


@pytest.mark.usefixtures("realm_unit")
def test_a_ctrl_c_in_the_realm_stops_the_line_and_the_next_step_draws_no_frame(
    switch,  # noqa: F811
    realm_backup,  # noqa: F811
    begun,
    monkeypatch,
):
    a_person_watches(monkeypatch)
    monkeypatch.setattr(realm_backup, "pre_apply", lambda _unit: press_ctrl_c())
    ticks = ticking_line(monkeypatch)

    _, out, _ = switch(while_prompt_waits=on_one_terminal(monkeypatch))

    steps = [step for _, step in begun]
    realm_step = begun[steps.index("apply the realm step")]
    assert steps.index("apply the key step") > steps.index("apply the realm step")
    assert ticks.redrawer_ended()
    assert last_frame(out) == step_words(*realm_step)
    assert find_row(out, REALM_UNIT, ResultEvent.REALM_FAILED, "interrupted")


class CtrlCAtTheFirstWait(subprocess.Popen):
    """The snapshot's process, with a Ctrl-C as hal waits for it the first time."""

    pressed = False

    def communicate(self, *arguments, **options):
        if not CtrlCAtTheFirstWait.pressed:
            CtrlCAtTheFirstWait.pressed = True
            press_ctrl_c()
        return super().communicate(*arguments, **options)


@pytest.mark.usefixtures("realm_unit")
def test_a_ctrl_c_in_a_snapshot_puts_the_waiting_row_on_its_own_line_and_no_frame_follows(
    switch,  # noqa: F811
    repository,  # noqa: F811
    monkeypatch,
):
    a_person_watches(monkeypatch)
    hal = repository / ".venv/bin/hal"
    hal.parent.mkdir(parents=True)
    hal.write_text("#!/bin/sh\nexec sleep 30\n")
    hal.chmod(hal.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(pre_apply.subprocess, "Popen", CtrlCAtTheFirstWait)
    monkeypatch.setattr(CtrlCAtTheFirstWait, "pressed", False)
    ticks = ticking_line(monkeypatch)

    _, out, _ = switch(installed_backup=True, while_prompt_waits=on_one_terminal(monkeypatch))

    row = find_row(out, REALM_UNIT, ResultEvent.WAITING)
    assert row
    assert ticks.redrawer_ended()
    kept, below = plain(out)[: row.start()], plain(out)[row.start() :]
    assert last_frame(kept) == [REALM_UNIT, "apply", "the", "realm", "step"]
    assert not kept.endswith("\n\n")
    assert "\r" not in below


def without_colour(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")


def at_a_dumb_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM", "dumb")


def in_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_FORMAT", "json")


@pytest.mark.parametrize(
    ("arrange", "verbose"),
    [
        (without_colour, False),
        (at_a_dumb_terminal, False),
        (in_json, False),
        (lambda _monkeypatch: None, True),
    ],
    ids=["NO_COLOR", "TERM=dumb", "LOG_FORMAT=json", "-v"],
)
@pytest.mark.usefixtures("applied_core")
def test_without_colour_or_under_json_or_v_no_frame_byte_reaches_stderr(
    switch,  # noqa: F811
    repository,  # noqa: F811
    begun,
    monkeypatch,
    arrange,
    verbose: bool,
):
    person = a_person_watches(monkeypatch)
    edit_traefik_yml(repository)
    arrange(monkeypatch)

    with verbose_run(verbose):
        switch()

    assert "recreate traefik" in [step for _, step in begun]
    err = person.getvalue()
    assert "\r" not in err
    assert not set(LIVE_FRAMES) & set(err)
