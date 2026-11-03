"""The system step's Ansible runner: event reading and the one sudo call around the play."""

from __future__ import annotations

import io
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from hal.grammar import ExitCode
import hal.output
from hal.output import verbose_run
from hal.workstation import system_step
from hal.workstation.system_step import PlaybookFinished, PlaybookNotStarted, PlaybookRun, PlaybookUnfinished
from support.terminal_support import TerminalStream, put_stdout_on_a_terminal
from support.workstation_support import FRESH_APPLY, Sandbox, StubSudo, lines_of_the_run, run_hal_setup

COUNTS = system_step.EVENT_MARK + json.dumps({"event": "counts", "changed": 3, "failed": 0, "unreachable": 0})
FAILED_COUNTS = system_step.EVENT_MARK + json.dumps({"event": "counts", "changed": 1, "failed": 1, "unreachable": 0})
UNREACHABLE_COUNTS = system_step.EVENT_MARK + json.dumps({"event": "counts", "changed": 0, "failed": 0, "unreachable": 1})
FAILED_RESULT = system_step.EVENT_MARK + json.dumps({"event": "result", "status": "failed", "msg": "names no `tunnel:`"})
CHANGED_WRITE = system_step.EVENT_MARK + json.dumps({"event": "changed", "task": "Write edge files"})
CHANGED_RESTART = system_step.EVENT_MARK + json.dumps({"event": "changed", "task": "Restart Docker"})
STARTED = system_step.STARTED_LINE
TASK_START = system_step.EVENT_MARK + json.dumps({"event": "task", "task": "Read the default log driver"})
UNREACHABLE_RESULT = system_step.EVENT_MARK + json.dumps({"event": "result", "status": "unreachable", "msg": "no route"})


def counts_event(**counts: object) -> str:
    return system_step.EVENT_MARK + json.dumps({"event": "counts", **counts})


MALFORMED_COUNTS = [
    counts_event(changed=0, failed=0.5, unreachable=0),
    counts_event(changed=0, failed=False, unreachable=0),
    counts_event(changed=0, failed="0", unreachable=0),
    counts_event(changed=-1, failed=0, unreachable=0),
    system_step.EVENT_MARK + '{"event": "counts", "changed": 0, "failed": 1e309, "unreachable": 0}',
    system_step.EVENT_MARK + json.dumps({"event": "counts", "changed": 0, "failed": 0}),
]


@pytest.mark.parametrize(
    ("returncode", "events", "expected"),
    [
        (0, [STARTED, COUNTS], PlaybookFinished(3)),
        (0, [STARTED, CHANGED_WRITE, CHANGED_RESTART, COUNTS], PlaybookFinished(3, ("Write edge files", "Restart Docker"))),
        (2, [STARTED, FAILED_RESULT, FAILED_COUNTS], PlaybookUnfinished("names no `tunnel:`", 1)),
        (4, [STARTED, UNREACHABLE_RESULT, UNREACHABLE_COUNTS], PlaybookUnfinished("no route", 0)),
        (0, [STARTED, FAILED_RESULT, COUNTS, COUNTS], PlaybookUnfinished()),
        (0, [STARTED], PlaybookUnfinished()),
        (0, [STARTED, TASK_START, CHANGED_WRITE, COUNTS], PlaybookFinished(3, ("Write edge files",))),
        (0, [STARTED, system_step.EVENT_MARK + json.dumps({"event": "task"}), COUNTS], PlaybookUnfinished()),
        (0, [STARTED, system_step.EVENT_MARK + json.dumps({"event": "task", "task": None}), COUNTS], PlaybookUnfinished()),
        (0, [STARTED, system_step.EVENT_MARK + json.dumps({"event": "task", "task": 7}), COUNTS], PlaybookUnfinished()),
        (0, [STARTED, system_step.EVENT_MARK + json.dumps({"event": "task", "task": ["a"]}), COUNTS], PlaybookUnfinished()),
        (0, [STARTED, system_step.EVENT_MARK + json.dumps({"event": "task", "task": {"a": 1}}), COUNTS], PlaybookUnfinished()),
        (0, [STARTED, system_step.EVENT_MARK + json.dumps({"event": "heartbeat"}), COUNTS], PlaybookUnfinished()),
        (0, [STARTED, system_step.EVENT_MARK + "not json", COUNTS], PlaybookUnfinished()),
        (0, [STARTED, system_step.EVENT_MARK + json.dumps({"event": "changed"}), COUNTS], PlaybookUnfinished()),
        (0, [STARTED, system_step.EVENT_MARK + json.dumps({"event": "changed", "task": 7}), COUNTS], PlaybookUnfinished()),
        (0, [STARTED, system_step.EVENT_MARK + json.dumps({"event": "changed", "task": None}), COUNTS], PlaybookUnfinished()),
        (1, [STARTED, COUNTS], PlaybookUnfinished(changed=3)),
        (0, [STARTED, FAILED_RESULT, COUNTS], PlaybookFinished(3)),
        (2, [STARTED, CHANGED_WRITE, FAILED_RESULT, counts_event(changed=0, failed=1, unreachable=0)], PlaybookUnfinished("names no `tunnel:`", 1)),
        (1, [], PlaybookNotStarted()),
        (0, [], PlaybookUnfinished()),
        (1, [COUNTS], PlaybookUnfinished()),
        (0, [TASK_START, COUNTS], PlaybookUnfinished()),
        (0, [STARTED, STARTED, COUNTS], PlaybookUnfinished()),
    ],
    ids=[
        "clean counts",
        "changed tasks",
        "failed task",
        "unreachable",
        "two counts events",
        "no counts event",
        "task events are ignored",
        "task event without a name",
        "task named null",
        "task named by a number",
        "task named by an array",
        "task named by an object",
        "unknown event",
        "unreadable event",
        "changed event without a task",
        "changed event named by a number",
        "changed event named null",
        "nonzero exit",
        "rescued failure",
        "a changed task the counts missed",
        "sudo never ran the shell",
        "no line and exit 0",
        "counts without the started line",
        "an event before the started line",
        "a second started line",
    ],
)
def test_a_run_finishes_only_with_exit_0_and_one_counts_event_without_failures(returncode: int, events: list[str], expected: PlaybookRun) -> None:
    """Rule 4 and rule 7: a root run that cannot be read as finished never counts as done, and a handled message is no cause."""
    assert system_step.read_events(returncode, events) == expected


def fake_ansible(tmp_path: Path, script: str, counts: str = COUNTS) -> Path:
    playbook = tmp_path / "ansible-playbook"
    playbook.write_text(f"#!/bin/sh\n{script}\nprintf '%s\\n' '{counts}'\n")
    playbook.chmod(0o755)
    return playbook


@pytest.fixture
def stub_sudo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> StubSudo:
    return StubSudo(tmp_path, monkeypatch)


@pytest.mark.parametrize(
    "counts",
    MALFORMED_COUNTS,
    ids=["float count", "bool count", "string count", "negative count", "count beyond float range", "missing count"],
)
def test_a_counts_line_that_is_not_three_non_negative_integers_leaves_the_run_unfinished(tmp_path: Path, stub_sudo: StubSudo, counts: str) -> None:
    """Rule 4: the runner never counts a run as done on counts it cannot read, though the play exited 0."""
    playbook = fake_ansible(tmp_path, "true", counts)

    assert system_step.run_playbook_as_root([str(playbook)]) == PlaybookUnfinished()


def test_without_v_the_runner_shows_no_ansible_text_and_reads_its_events(tmp_path: Path, stub_sudo: StubSudo, capfd: pytest.CaptureFixture[str]) -> None:
    """Invariant 5 of #296: no raw tool text without `-v`, and the run is still judged by its events."""
    playbook = fake_ansible(tmp_path, "echo 'TASK [Write edge files]'", f"{CHANGED_WRITE}\n{COUNTS}")

    run = system_step.run_playbook_as_root([str(playbook)])

    assert run == PlaybookFinished(3, ("Write edge files",))
    shown = capfd.readouterr()
    assert (shown.out, shown.err) == ("", "")


def test_with_v_the_runner_shows_ansibles_text_indented_and_escaped_and_no_event_line(
    tmp_path: Path, stub_sudo: StubSudo, capfd: pytest.CaptureFixture[str]
) -> None:
    playbook = fake_ansible(tmp_path, r"printf 'TASK [Write]\n\033[31mred\tcolumn\n'", f"{CHANGED_WRITE}\n{COUNTS}")

    with verbose_run(True):
        run = system_step.run_playbook_as_root([str(playbook)])

    assert run == PlaybookFinished(3, ("Write edge files",))
    assert capfd.readouterr().out == "    TASK [Write]\n    \\x1b[31mred\\tcolumn\n"


class FlushRecordingStdout(io.StringIO):
    """What the terminal has been handed by each flush."""

    def __init__(self) -> None:
        super().__init__()
        self.flushed: list[str] = []

    def flush(self) -> None:
        super().flush()
        self.flushed.append(self.getvalue())


def test_with_v_each_line_is_flushed_when_it_is_read_so_a_pipe_sees_it_while_the_play_runs(
    tmp_path: Path, stub_sudo: StubSudo, monkeypatch: pytest.MonkeyPatch
) -> None:
    playbook = fake_ansible(tmp_path, "echo one\necho two")
    pipe = FlushRecordingStdout()
    monkeypatch.setattr(sys, "stdout", pipe)

    with verbose_run(True):
        system_step.run_playbook_as_root([str(playbook)])

    assert pipe.flushed == ["    one\n", "    one\n    two\n"]


def test_without_v_a_play_that_fills_the_pipe_finishes_because_the_runner_drains_it(
    tmp_path: Path, stub_sudo: StubSudo, capfd: pytest.CaptureFixture[str]
) -> None:
    playbook = fake_ansible(tmp_path, "head -c 1000000 /dev/zero | tr '\\0' 'x' | fold -w 100\necho")

    run = system_step.run_playbook_as_root([str(playbook)])

    assert run == PlaybookFinished(3)
    assert capfd.readouterr().out == ""


def test_ansibles_stderr_arrives_in_the_same_stream_and_is_shown_with_v(tmp_path: Path, stub_sudo: StubSudo, capfd: pytest.CaptureFixture[str]) -> None:
    playbook = fake_ansible(tmp_path, "echo '[WARNING]: a warning' >&2")

    with verbose_run(True):
        system_step.run_playbook_as_root([str(playbook)])

    shown = capfd.readouterr()
    assert (shown.out, shown.err) == ("    [WARNING]: a warning\n", "")


def test_ansibles_output_is_not_shown_without_v(tmp_path: Path, stub_sudo: StubSudo, capfd: pytest.CaptureFixture[str]) -> None:
    playbook = fake_ansible(tmp_path, "echo '[WARNING]: a warning' >&2")

    with verbose_run(False):
        system_step.run_playbook_as_root([str(playbook)])

    shown = capfd.readouterr()
    assert (shown.out, shown.err) == ("", "")


def test_ansibles_output_under_v_is_dim_on_a_terminal(tmp_path: Path, stub_sudo: StubSudo, monkeypatch: pytest.MonkeyPatch) -> None:
    playbook = fake_ansible(tmp_path, "echo 'TASK [Write]'")
    terminal = put_stdout_on_a_terminal(monkeypatch)

    with verbose_run(True):
        system_step.run_playbook_as_root([str(playbook)])

    assert terminal.getvalue() == "\x1b[2m    TASK [Write]\x1b[0m\n"


def test_the_play_runs_under_sudo_in_its_own_directory_and_sudo_forgets_the_ticket_after_it(tmp_path: Path, stub_sudo: StubSudo) -> None:
    """Ruled E1: one sudo call runs the play; `sudo -k` follows it, so no ticket outlives `hal setup`."""
    playbook = fake_ansible(tmp_path, "true")

    system_step.run_playbook_as_root([str(playbook), "--diff"])

    play_call, forget_call = stub_sudo.calls()
    assert play_call[0].startswith("env PYTHONDONTWRITEBYTECODE=1 sh -c ")
    assert system_step.STARTED_LINE in play_call[0]
    assert play_call[0].endswith(f" {playbook} --diff")
    assert play_call[1] == str(system_step.PLAYBOOK.parent)
    assert forget_call[0] == "-k"


def test_no_ansible_variable_reaches_the_play_and_no_become_prompt_is_asked(
    tmp_path: Path, stub_sudo: StubSudo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sudo's own configuration cannot let the operator's ANSIBLE_CONFIG or callback override the packaged one."""
    monkeypatch.setenv("ANSIBLE_STDOUT_CALLBACK", "json")
    monkeypatch.setenv("ANSIBLE_CONFIG", str(tmp_path / "other.cfg"))
    playbook = fake_ansible(tmp_path, "true")

    system_step.run_playbook_as_root([str(playbook)])

    play_call = stub_sudo.calls()[0]
    assert play_call[2] == ""
    assert "--ask-become-pass" not in play_call[0]


def test_sudo_forgets_the_ticket_after_a_failing_play(tmp_path: Path, stub_sudo: StubSudo) -> None:
    playbook = fake_ansible(tmp_path, "exit 2")

    run = system_step.run_playbook_as_root([str(playbook)])

    assert isinstance(run, PlaybookUnfinished)
    assert stub_sudo.calls()[-1][0] == "-k"


def test_a_sudo_that_refuses_runs_nothing_and_is_told_apart_from_an_ansible_that_died(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ruled S3b-3: no line from the shell under sudo means sudo never started the play; sudo still forgets its ticket."""
    stub_sudo = StubSudo(tmp_path, monkeypatch, refusing=True)

    run = system_step.run_playbook_as_root([str(fake_ansible(tmp_path, "true"))])

    assert run == PlaybookNotStarted()
    assert stub_sudo.calls()[-1][0] == "-k"


def test_an_ansible_that_dies_before_any_event_is_unfinished_and_not_a_refusal(tmp_path: Path, stub_sudo: StubSudo) -> None:
    run = system_step.run_playbook_as_root([str(fake_ansible(tmp_path, "exit 2"))])

    assert run == PlaybookUnfinished()


def test_a_failing_sudo_k_fails_the_step_after_a_successful_play(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ruled E1: a ticket that could not be forgotten is never swallowed."""
    StubSudo(tmp_path, monkeypatch, forgetting_exit_code=1)
    playbook = fake_ansible(tmp_path, "true")

    with pytest.raises(system_step.StepFailed) as failure:
        system_step.run_playbook_as_root([str(playbook)])

    assert isinstance(failure.value.__cause__, subprocess.CalledProcessError)


TICKET_SENTENCE = "sudo could not forget its ticket (exit 1) · it may still be valid"


def test_a_ctrl_c_in_the_play_is_an_interrupted_step_without_a_fact(tmp_path: Path, stub_sudo: StubSudo) -> None:
    playbook = fake_ansible(tmp_path, "kill -INT $PPID")

    with pytest.raises(system_step.SystemStepInterrupted) as interrupted:
        system_step.run_playbook_as_root([str(playbook)])

    assert str(interrupted.value) == ""
    assert stub_sudo.calls()[-1][0] == "-k"


def test_a_failing_sudo_k_after_a_ctrl_c_is_the_same_interrupted_step_carrying_the_ticket_sentence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ruled E1: the ticket that may still be valid is said, and the person still pressed Ctrl-C."""
    stub = StubSudo(tmp_path, monkeypatch, forgetting_exit_code=1)
    playbook = fake_ansible(tmp_path, "kill -INT $PPID")

    with pytest.raises(system_step.SystemStepInterrupted) as interrupted:
        system_step.run_playbook_as_root([str(playbook)])

    assert str(interrupted.value) == TICKET_SENTENCE
    assert stub.calls()[-1][0] == "-k"


def test_a_second_ctrl_c_while_the_play_stops_is_still_the_interrupted_step_carrying_the_ticket_sentence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first Ctrl-C is a real signal from the play; the second is raised from the play's context exit."""

    class PlayPopenInterruptedOnExit(subprocess.Popen[str]):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.is_the_play = kwargs.get("stdout") == subprocess.PIPE

        def __exit__(self, exception_type: Any, *exit_arguments: Any) -> None:
            super().__exit__(exception_type, *exit_arguments)
            if self.is_the_play:
                self.kill()
                self.wait()
                if exception_type is KeyboardInterrupt:
                    raise KeyboardInterrupt

    monkeypatch.setattr(subprocess, "Popen", PlayPopenInterruptedOnExit)
    stub = StubSudo(tmp_path, monkeypatch, forgetting_exit_code=1)
    # ulimit -t ends a play whose first signal never arrives; the printf loop ends on EPIPE once the runner closes the pipe.
    playbook = fake_ansible(tmp_path, "ulimit -t 2\ntrap '' PIPE\nkill -INT $PPID\nwhile printf '.\\n' 2>/dev/null; do :; done")

    with pytest.raises(system_step.SystemStepInterrupted) as interrupted:
        system_step.run_playbook_as_root([str(playbook)])

    assert str(interrupted.value) == TICKET_SENTENCE
    assert stub.calls()[-1][0] == "-k"


def test_a_failing_sudo_k_after_another_exception_is_a_failed_step_carrying_the_ticket_sentence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ruled E1: a ticket that could not be forgotten is never swallowed, whatever raised first."""
    StubSudo(tmp_path, monkeypatch, forgetting_exit_code=1)
    playbook = fake_ansible(tmp_path, r"printf '\377\n'")

    with pytest.raises(system_step.StepFailed) as failure:
        system_step.run_playbook_as_root([str(playbook)])

    assert type(failure.value) is system_step.StepFailed
    assert str(failure.value) == TICKET_SENTENCE


def test_a_ctrl_c_between_the_start_of_sudo_and_the_reading_still_ends_in_sudo_k(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ruled E1: `sudo -k` follows the sudo call, whatever the play did, also an interrupt that lands as the process context is entered."""

    class PlayPopenInterruptedOnEnter(subprocess.Popen[str]):
        interrupted = False

        def __enter__(self) -> PlayPopenInterruptedOnEnter:
            if self.stdout is None or type(self).interrupted:
                return super().__enter__()
            type(self).interrupted = True
            self.kill()
            self.wait()
            raise KeyboardInterrupt

    monkeypatch.setattr(subprocess, "Popen", PlayPopenInterruptedOnEnter)
    stub = StubSudo(tmp_path, monkeypatch)
    playbook = fake_ansible(tmp_path, "true")

    with pytest.raises(system_step.SystemStepInterrupted) as interrupted:
        system_step.run_playbook_as_root([str(playbook)])

    assert str(interrupted.value) == ""
    assert stub.calls()[-1][0] == "-k"


def test_a_play_that_runs_on_after_a_ctrl_c_is_not_waited_for(tmp_path: Path, stub_sudo: StubSudo) -> None:
    finished = tmp_path / "finished"
    playbook = fake_ansible(tmp_path, f"kill -INT $PPID\nsleep 3\ntouch {finished}")

    with pytest.raises(system_step.SystemStepInterrupted):
        system_step.run_playbook_as_root([str(playbook)])

    assert not finished.exists()


def test_another_exception_in_the_output_loop_is_no_interrupt_and_sudo_k_still_runs_last(tmp_path: Path, stub_sudo: StubSudo) -> None:
    playbook = fake_ansible(tmp_path, r"printf '\377\n'")

    with pytest.raises(UnicodeDecodeError):
        system_step.run_playbook_as_root([str(playbook)])

    assert stub_sudo.calls()[-1][0] == "-k"


def a_play_under_stub_sudo(
    sandbox: Sandbox, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, script: str, forgetting_exit_code: int = 0
) -> StubSudo:
    """`hal setup` whose system step runs the real runner over a fake `ansible-playbook` and a stub `sudo`."""
    stub = StubSudo(tmp_path, monkeypatch, forgetting_exit_code)
    playbook = fake_ansible(tmp_path, script)
    sandbox.layout.ansible_playbook_executable.parent.mkdir(parents=True, exist_ok=True)
    sandbox.layout.ansible_playbook_executable.write_text("")
    monkeypatch.setattr(
        system_step,
        "TERMINAL_BOUNDARIES",
        system_step.Boundaries(lambda: True, lambda _argv: system_step.run_playbook_as_root([str(playbook)]), lambda: "operator"),
    )
    return stub


@pytest.mark.parametrize(
    ("forgetting_exit_code", "fact"), [(0, ""), (1, f"    {TICKET_SENTENCE}")], ids=["ticket forgotten", "ticket kept"]
)
def test_a_ctrl_c_in_the_play_of_hal_setup_prints_the_system_row_and_the_pair_and_exits_130(
    sandbox: Sandbox,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    forgetting_exit_code: int,
    fact: str,
) -> None:
    stub = a_play_under_stub_sudo(sandbox, tmp_path, monkeypatch, "kill -INT $PPID", forgetting_exit_code)

    code = run_hal_setup(home=sandbox.home, secrets_setup_boundaries=sandbox.secrets_boundaries)

    captured = capsys.readouterr()
    assert code == ExitCode.INTERRUPTED
    assert captured.out.splitlines()[-3:] == ["", f"  ✗ system          interrupted{fact}".rstrip(), "  · secrets         not run"]
    assert captured.err == "error: setup stopped at system · /etc may be partial\nnext: hal setup\n"
    assert stub.calls()[-1][0] == "-k"


def test_a_ctrl_c_in_the_check_of_a_dry_run_says_etc_is_unchanged(
    sandbox: Sandbox, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    a_play_under_stub_sudo(sandbox, tmp_path, monkeypatch, "kill -INT $PPID")

    code = run_hal_setup("--dry-run", home=sandbox.home, secrets_setup_boundaries=sandbox.secrets_boundaries)

    captured = capsys.readouterr()
    assert code == ExitCode.INTERRUPTED
    assert "  ✗ system          interrupted" in captured.out.splitlines()
    assert captured.err == "error: setup stopped at system · /etc unchanged\nnext: hal setup\n"


def test_a_failing_sudo_k_after_a_finished_play_still_fails_the_system_row_with_exit_3(
    sandbox: Sandbox, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    a_play_under_stub_sudo(sandbox, tmp_path, monkeypatch, "true", forgetting_exit_code=1)

    code = run_hal_setup(home=sandbox.home, secrets_setup_boundaries=sandbox.secrets_boundaries)

    captured = capsys.readouterr()
    assert code == ExitCode.FAILURE
    assert f"  ✗ system          failed         {TICKET_SENTENCE}" in captured.out.splitlines()
    assert captured.err == "error: setup stopped at system · /etc may be partial\nnext: hal setup\n"


def test_a_missing_sudo_fails_alone_without_a_ticket_to_forget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))

    with pytest.raises(FileNotFoundError) as refusal:
        system_step.run_playbook_as_root(["ansible-playbook"])

    assert refusal.value.__context__ is None


# --- the live task line -----------------------------------------------------

ERASE = "\r\x1b[K"
ANSI = re.compile(r"\x1b\[[0-9;]*[mK]")
READ_LOG_DRIVER = "Read the default log driver"
WRITE_EDGE_FILES = "Write edge files"


class FlagOnFirstFrame(TerminalStream):
    """A terminal that raises a flag file once the first frame has been handed to it, as the play waits for the person to see it."""

    def __init__(self, flag: Path) -> None:
        super().__init__()
        self.flag = flag

    def write(self, text: str, /) -> int:
        written = super().write(text)
        if len(text) > len(ERASE):
            self.flag.touch()
        return written


def stderr_on_a_terminal(monkeypatch: pytest.MonkeyPatch, stream: TerminalStream | None = None) -> TerminalStream:
    """Stderr on a terminal that never redraws by itself, so a frame is one task the runner read; stdout stays where the test has it."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(hal.output, "LIVE_TICK_SECONDS", 3600)
    terminal = stream or TerminalStream()
    monkeypatch.setattr(sys, "stderr", terminal)
    return terminal


def shown_tasks(terminal: TerminalStream) -> list[str]:
    visible = [ANSI.sub("", frame) for frame in terminal.getvalue().split("\r")]
    return [match.group(1) for frame in visible if (match := re.search(r"system +(.*?) \xb7 [<\d]", frame))]


def play_starting(tmp_path: Path, *names: str, after: str = "") -> str:
    """The script of a play whose callback marks one task start for each name, then runs `after`."""
    events = tmp_path / "task-events"
    events.write_text("".join(f"{system_step.EVENT_MARK}{json.dumps({'event': 'task', 'task': name})}\n" for name in names))
    return f"cat {events}\n{after}"


def test_hal_setup_without_v_shows_each_task_on_stderr_and_erases_the_line_with_stdout_as_before(
    sandbox: Sandbox, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    terminal = stderr_on_a_terminal(monkeypatch)
    a_play_under_stub_sudo(sandbox, tmp_path, monkeypatch, play_starting(tmp_path, READ_LOG_DRIVER, WRITE_EDGE_FILES))

    code = run_hal_setup(home=sandbox.home, secrets_setup_boundaries=sandbox.secrets_boundaries)

    assert (code, lines_of_the_run(capsys.readouterr().out)) == (ExitCode.OK, FRESH_APPLY)
    assert shown_tasks(terminal) == [READ_LOG_DRIVER, WRITE_EDGE_FILES]
    assert terminal.getvalue().endswith(ERASE)


def test_hal_setup_dry_run_shows_the_tasks_of_the_check_the_same_way(
    sandbox: Sandbox, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    terminal = stderr_on_a_terminal(monkeypatch)
    a_play_under_stub_sudo(sandbox, tmp_path, monkeypatch, play_starting(tmp_path, READ_LOG_DRIVER))

    run_hal_setup("--dry-run", home=sandbox.home, secrets_setup_boundaries=sandbox.secrets_boundaries)

    assert shown_tasks(terminal) == [READ_LOG_DRIVER]
    assert terminal.getvalue().endswith(ERASE)


def test_a_play_that_never_marks_a_task_start_leaves_stderr_to_sudos_prompt(tmp_path: Path, stub_sudo: StubSudo, monkeypatch: pytest.MonkeyPatch) -> None:
    terminal = stderr_on_a_terminal(monkeypatch)
    playbook = fake_ansible(tmp_path, "echo 'TASK [Write edge files]'")

    system_step.run_playbook_as_root([str(playbook)])

    assert terminal.getvalue() == ""


def test_a_ctrl_c_in_the_play_leaves_the_live_line_and_hal_setup_still_ends_with_the_row_the_pair_and_sudo_k(
    sandbox: Sandbox, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    flag = tmp_path / "first-frame-seen"
    terminal = stderr_on_a_terminal(monkeypatch, FlagOnFirstFrame(flag))
    after = f"until [ -e {flag} ]; do sleep 0.05; done\nkill -INT $PPID\nsleep 3"
    stub = a_play_under_stub_sudo(sandbox, tmp_path, monkeypatch, play_starting(tmp_path, READ_LOG_DRIVER, after=after))

    code = run_hal_setup(home=sandbox.home, secrets_setup_boundaries=sandbox.secrets_boundaries)

    assert code == ExitCode.INTERRUPTED
    assert capsys.readouterr().out.splitlines()[-2:] == ["  \u2717 system          interrupted", "  \xb7 secrets         not run"]
    assert shown_tasks(terminal) == [READ_LOG_DRIVER]
    assert "error: setup stopped at system" in ANSI.sub("", terminal.getvalue())
    assert terminal.getvalue().count(ERASE) == 1
    assert stub.calls()[-1][0] == "-k"


def test_a_play_that_fills_the_pipe_finishes_with_the_live_line_on(tmp_path: Path, stub_sudo: StubSudo, monkeypatch: pytest.MonkeyPatch) -> None:
    stderr_on_a_terminal(monkeypatch)
    fills_the_pipe = "head -c 1000000 /dev/zero | tr '\\0' 'x' | fold -w 100\necho"
    playbook = fake_ansible(tmp_path, play_starting(tmp_path, READ_LOG_DRIVER, after=fills_the_pipe))

    assert system_step.run_playbook_as_root([str(playbook)]) == PlaybookFinished(3)


@pytest.mark.parametrize(
    "unreadable",
    ["not json", '{"event": "task"}', "[1]", '{"event": "task", "task": null}', '{"event": "task", "task": 7}'],
    ids=["no json", "task without a name", "json of another shape", "null name", "number name"],
)
def test_a_marked_line_that_cannot_be_read_shows_nothing_and_leaves_the_run_unfinished(
    tmp_path: Path, stub_sudo: StubSudo, monkeypatch: pytest.MonkeyPatch, unreadable: str
) -> None:
    terminal = stderr_on_a_terminal(monkeypatch)
    playbook = fake_ansible(tmp_path, f"echo '{system_step.EVENT_MARK}{unreadable}'")

    assert system_step.run_playbook_as_root([str(playbook)]) == PlaybookUnfinished()
    assert terminal.getvalue() == ""
