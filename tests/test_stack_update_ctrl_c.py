"""`hal update` under a real Ctrl-C (#783): before the merge it is the door's; from the merge on it
is recorded, reads as O6 until the final line, kills the sync's group until its leader is reaped,
and changes nothing from the final line on."""

import os
import signal
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import support.stack_update as stack_update_support
import support.throwaway_home as throwaway_home
from support.git_support import head_of, subjects
from support.process_support import group_is_gone
from support.stack_apply_fakes import Terminal
from support.stack_update import APPLIED_RECORD, Tamper, answered, errors

from hal import cli
from hal.grammar import ExitCode
from hal.stack import checkout, update
from hal.stack import cli as stack_cli
from hal.stack.update import UpdateEnd

home = throwaway_home.home
world = stack_update_support.world

SIGNALLING_GIT = """#!/bin/sh
case "${FAKE_SIGNAL-}:$*" in
merge:*" merge "*|synced:*" rev-parse "*)
    if [ "$FAKE_SIGNAL" = merge ] || [ -e "$FAKE_LOG/sync.done" ]; then
        kill -INT -"$(ps -o pgid= -p "$PPID" | tr -d ' ')"
    fi ;;
esac
exec "$REAL_GIT" "$@"
"""


@pytest.fixture
def signalling_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable]:
    """A `git` on PATH that sends SIGINT to the run's process group, as a terminal's Ctrl-C does,
    on the call the returned setter names. pytest leads its own group meanwhile, so the signal
    reaches nothing of the group that started it (a session leader leads one already)."""
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "git").write_text(SIGNALLING_GIT)
    (shim / "git").chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim}{os.pathsep}{os.environ['PATH']}")
    started_in = os.getpgrp()
    if started_in != os.getpid():
        os.setpgid(0, 0)
    yield lambda signal_on: monkeypatch.setenv("FAKE_SIGNAL", signal_on)
    monkeypatch.delenv("FAKE_SIGNAL", raising=False)
    if started_in != os.getpid():
        os.setpgid(0, started_in)


def interrupt(*_) -> None:
    os.kill(os.getpid(), signal.SIGINT)


@pytest.mark.parametrize("moment", ["at the question", "during the recheck"])
def test_a_ctrl_c_before_the_merge_is_the_doors_130_and_changes_nothing(
    world, capsys, monkeypatch, moment
):
    """A4: a real SIGINT while the question waits or while the recheck asks git."""
    world.wait(*subjects("waiting"))
    before = head_of(world.live)
    recheck = Tamper(world, "merge-base", interrupt, merged=True)
    hit = {
        "at the question": {"at_the_question": interrupt},
        "during the recheck": {"git": recheck},
    }
    monkeypatch.setattr(stack_cli, "update_checkout", lambda: world.run(**hit[moment]))

    assert cli.main(["update"]) == ExitCode.INTERRUPTED
    assert head_of(world.live) == before
    assert world.lock_is_free
    assert errors(capsys) == ""
    assert "updated" not in world.stdout()


@pytest.mark.parametrize("moment", ["merge succeeds", "merge refused", "check fails", "synced"])
def test_a_real_ctrl_c_from_the_merge_on_waits_and_ends_interrupted_with_its_line_only(
    world, capsys, signalling_git, moment
):
    """M4: the group's SIGINT reaches the run while git merges in its own session; the merge ends
    and the sync never starts. O6: a merge git refuses, or a failed check after it, still ends
    130, with only its line; a refusal that changed nothing says so and names `hal update`. S6:
    a SIGINT after the sync names the HEAD check."""
    start, tip = head_of(world.live), world.wait(*subjects("waiting"))
    refused, synced = moment == "merge refused", moment == "synced"
    signalling_git("synced" if synced else "merge")
    hit = {
        "merge refused": {"at_the_question": (world.live / ".git/index.lock").touch},
        "check fails": {"git": Tamper(world, "status", answered(0, b" M README.md\0"))},
    }

    end = world.run(**hit.get(moment, {}))
    signalling_git("")

    error, next_line = errors(capsys).splitlines()
    assert end is UpdateEnd.INTERRUPTED
    assert head_of(world.live) == (start if refused else tip)
    assert error.startswith("error: interrupted at '")
    assert tip in error
    assert f"the sync had {'ended' if synced else 'not started'}" in error
    assert ("nothing changed" in error) == refused
    assert ("'check HEAD after the sync'" in error) == synced
    assert next_line == f"next: hal {'update' if refused else 'apply'}"
    assert (world.log / "sync.args").exists() == synced
    assert world.lock_is_free
    assert world.record() == APPLIED_RECORD


@pytest.mark.parametrize("moment", ["while it runs", "before it is registered"])
def test_a_real_ctrl_c_at_the_sync_kills_its_whole_group_before_the_lock_is_freed(
    world, capsys, monkeypatch, moment
):
    """S4: the stand-in has a child of its own; no process of its group is alive when the update
    returns, also after a Ctrl-C between the sync's start and its registration, and it never
    finished (`hold` would finish after a while)."""
    tip, sync = world.wait(*subjects("waiting")), str(world.live / update.SYNC_SCRIPT)
    monkeypatch.setenv("FAKE_SYNC", "interrupt" if moment == "while it runs" else "hold")
    started = []

    class Started(subprocess.Popen):
        def __init__(self, command, **options) -> None:
            super().__init__(command, **options)
            if command[0] == sync:
                started.append(self.pid)
                if moment == "before it is registered":
                    interrupt()

    monkeypatch.setattr(subprocess, "Popen", Started)
    end = world.run()

    err = errors(capsys)
    assert end is UpdateEnd.INTERRUPTED
    assert tip in err
    assert "half synced" in err
    assert group_is_gone(started[0])
    assert world.lock_is_free
    assert not (world.log / "sync.done").exists()


@dataclass(frozen=True)
class FinalLine:
    """A trouble at the end of the run and the line it ends with. `first_at_git`: the verb on which
    a Ctrl-C comes after the sync; `on`: the text whose writing meets `trouble`."""

    code: ExitCode
    says: str
    first_at_git: str = ""
    sync: str = ""
    names_error: str = ""
    on: str = "\0"
    trouble: Callable[[], None] = interrupt


class Troubled(Terminal):
    """A terminal on which writing a text that holds `on` runs `trouble` first."""

    def __init__(self, trouble: Callable[[], None], on: str) -> None:
        super().__init__()
        self.trouble, self.on = trouble, on

    def write(self, text: str) -> int:
        if self.on in text:
            self.trouble()
        return super().write(text)


def broken_pipe() -> None:
    raise BrokenPipeError


O6 = "interrupted at 'check HEAD after the sync'"
VERDICT = "checkout updated to "
FINAL_LINES = {
    "before it": FinalLine(ExitCode.INTERRUPTED, O6, "rev-parse"),
    "before it and again at O6": FinalLine(ExitCode.INTERRUPTED, O6, "rev-parse", on="interrupted"),
    "at the verdict": FinalLine(ExitCode.OK, VERDICT, on=VERDICT),
    "at an O5": FinalLine(
        ExitCode.FAILURE, "at 'sync the dependencies'", sync="fail", on="partial"
    ),
    "output fails at the verdict": FinalLine(
        ExitCode.FAILURE,
        "'write the closing verdict'",
        names_error="unexpected error (BrokenPipeError)",
        on=VERDICT,
        trouble=broken_pipe,
    ),
}


@pytest.mark.parametrize("moment", FINAL_LINES)
def test_a_ctrl_c_makes_the_final_line_o6_only_when_recorded_before_it(world, monkeypatch, moment):
    """O6: a real SIGINT recorded before the final line ends 130 with the sha and the step, and a
    second one while that line is written leaves it whole. One while the closing verdict or an O5
    line is written leaves exactly that line and its code. O8: a failing output at the verdict."""
    case, tip = FINAL_LINES[moment], world.wait(*subjects("waiting"))
    git = Tamper(world, case.first_at_git, checkout.run_git, "synced", interrupt)
    monkeypatch.setenv("FAKE_SYNC", case.sync)
    terminal = world.output = Troubled(case.trouble, case.on)
    monkeypatch.setattr(stack_cli, "update_checkout", lambda: world.run(git=git, stderr=terminal))

    assert cli.main(["update"]) == case.code

    shown = world.stdout()
    final, next_line = shown.splitlines()[-2:]
    assert case.says in final
    assert case.names_error in shown
    assert next_line == "next: hal apply"
    assert shown.count("error:") == (case.code is not ExitCode.OK)
    assert (tip in final) == (case.code is not ExitCode.OK)
    assert head_of(world.live) == tip
    assert world.lock_is_free


def test_a_ctrl_c_after_the_syncs_leader_is_reaped_sends_no_signal(world, capsys, monkeypatch):
    """Decision 11: the group id is only safe while the leader is unreaped, so a Ctrl-C between the
    reap and the end of the registration kills nothing; the run still ends as an interrupt."""
    tip, script = world.wait(*subjects("waiting")), str(world.live / update.SYNC_SCRIPT)
    run_in_own_group, signalled = checkout.run_in_own_group, []

    def reaped_then_interrupted(command, *arguments, **options):
        result = run_in_own_group(command, *arguments, **options)
        if command[0] == script:
            interrupt()
        return result

    monkeypatch.setattr(checkout, "run_in_own_group", reaped_then_interrupted)
    monkeypatch.setattr(os, "killpg", lambda *call: signalled.append(call))

    assert world.run() is UpdateEnd.INTERRUPTED
    assert signalled == []
    assert tip in errors(capsys)
    assert world.lock_is_free
