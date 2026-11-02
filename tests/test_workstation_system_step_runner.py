"""The system step's Ansible runner: event reading and the one sudo call around the play."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from hal.grammar import ExitCode
from hal.workstation import system_step
from hal.workstation.system_step import PlaybookFinished, PlaybookRun, PlaybookUnfinished
from support.workstation_support import Sandbox, StubSudo, run_hal_setup

COUNTS = system_step.EVENT_MARK + json.dumps({"event": "counts", "changed": 3, "failed": 0, "unreachable": 0})
FAILED_COUNTS = system_step.EVENT_MARK + json.dumps({"event": "counts", "changed": 1, "failed": 1, "unreachable": 0})
UNREACHABLE_COUNTS = system_step.EVENT_MARK + json.dumps({"event": "counts", "changed": 0, "failed": 0, "unreachable": 1})
FAILED_RESULT = system_step.EVENT_MARK + json.dumps({"event": "result", "status": "failed", "msg": "names no `tunnel:`; nothing was written"})
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
        (0, [COUNTS], PlaybookFinished(3)),
        (2, [FAILED_RESULT, FAILED_COUNTS], PlaybookUnfinished("names no `tunnel:`; nothing was written")),
        (4, [UNREACHABLE_RESULT, UNREACHABLE_COUNTS], PlaybookUnfinished("no route")),
        (0, [FAILED_RESULT, COUNTS, COUNTS], PlaybookUnfinished()),
        (0, [], PlaybookUnfinished()),
        (0, [system_step.EVENT_MARK + json.dumps({"event": "task"}), COUNTS], PlaybookUnfinished()),
        (0, [system_step.EVENT_MARK + "not json", COUNTS], PlaybookUnfinished()),
        (1, [COUNTS], PlaybookUnfinished()),
        (0, [FAILED_RESULT, COUNTS], PlaybookFinished(3)),
    ],
    ids=[
        "clean counts",
        "failed task",
        "unreachable",
        "two counts events",
        "no counts event",
        "unknown event",
        "unreadable event",
        "nonzero exit",
        "rescued failure",
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


def test_the_runner_shows_ansibles_output_and_reads_its_events(tmp_path: Path, stub_sudo: StubSudo, capfd: pytest.CaptureFixture[str]) -> None:
    """The output reaches the terminal as it comes, the run is judged by its events, and no event line is shown."""
    playbook = fake_ansible(tmp_path, "echo 'TASK [Write edge files]'")

    run = system_step.run_playbook_as_root([str(playbook)])

    assert run == PlaybookFinished(3)
    assert capfd.readouterr().out == "TASK [Write edge files]\n"


def test_ansibles_stderr_arrives_on_stdout_and_not_on_stderr(tmp_path: Path, stub_sudo: StubSudo, capfd: pytest.CaptureFixture[str]) -> None:
    playbook = fake_ansible(tmp_path, "echo '[WARNING]: a warning' >&2")

    system_step.run_playbook_as_root([str(playbook)])

    shown = capfd.readouterr()
    assert (shown.out, shown.err) == ("[WARNING]: a warning\n", "")


def test_the_play_runs_under_sudo_in_its_own_directory_and_sudo_forgets_the_ticket_after_it(tmp_path: Path, stub_sudo: StubSudo) -> None:
    """Ruled E1: one sudo call runs the play; `sudo -k` follows it, so no ticket outlives `hal setup`."""
    playbook = fake_ansible(tmp_path, "true")

    system_step.run_playbook_as_root([str(playbook), "--diff"])

    play_call, forget_call = stub_sudo.calls()
    assert play_call[0] == f"env PYTHONDONTWRITEBYTECODE=1 sh -c exec \"$@\" 2>&1 sh {playbook} --diff"
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
    stub = StubSudo(tmp_path, monkeypatch, forgetting_exit_code=1)
    playbook = fake_ansible(tmp_path, f"kill -INT $PPID\nuntil grep -q '^-k' {stub.log}; do sleep 0.05; done\nkill -INT $PPID\nsleep 3")

    with pytest.raises(system_step.SystemStepInterrupted) as interrupted:
        system_step.run_playbook_as_root([str(playbook)])

    assert str(interrupted.value) == TICKET_SENTENCE
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


def test_a_missing_sudo_fails_alone_without_a_ticket_to_forget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))

    with pytest.raises(FileNotFoundError) as refusal:
        system_step.run_playbook_as_root(["ansible-playbook"])

    assert refusal.value.__context__ is None

