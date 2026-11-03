"""The packaged `hal_events` callback under real Ansible, run through the system step's own runner without root."""

from __future__ import annotations

import re
import sys
from importlib.metadata import version
from pathlib import Path

import pytest
from support.terminal_support import TerminalStream, put_stdout_on_a_terminal
from support.workstation_support import StubSudo

import hal.output
from hal.output import verbose_run
from hal.workstation import system_step
from hal.workstation.setup import ANSIBLE_SOURCE
from hal.workstation.system_step import PlaybookFinished, PlaybookRun, PlaybookUnfinished

FAILING_ASSERT = """
    - ansible.builtin.assert:
        that: [false]
        fail_msg: "the file names no tunnel"
"""
RESCUE_THAT_FAILS = """
    - block:
        - ansible.builtin.fail:
            msg: the block failed
      rescue:
        - ansible.builtin.fail:
            msg: the rescue refused
"""
RESCUE_THAT_HOLDS = """
    - block:
        - ansible.builtin.fail:
            msg: the block failed
      rescue:
        - ansible.builtin.debug:
            msg: rescued
"""
IGNORED_FAILURE = """
    - ansible.builtin.fail:
        msg: ignored
      ignore_errors: true
"""
CHANGED_SKIPPED_AND_HANDLED = """
    - name: changed task
      ansible.builtin.command: "true"
      changed_when: true
      notify: handler
    - name: skipped task
      ansible.builtin.debug:
        msg: skipped
      when: false
    - ansible.builtin.meta: flush_handlers
"""
LOOPED_AND_UNCHANGED = """
    - name: looped task
      ansible.builtin.command: "true"
      changed_when: true
      loop: [1, 2, 3]
    - name: unchanged task
      ansible.builtin.command: "true"
      changed_when: false
"""
LOOP_THAT_FAILS_AFTER_A_WRITE = """
    - name: looped write
      ansible.builtin.command: "test {{ item }} = 1"
      changed_when: true
      loop: [1, 2]
"""
HANDLER = """
  handlers:
    - name: handler
      ansible.builtin.command: "true"
      changed_when: true
"""


def run_scratch_play(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tasks: str, handlers: str = "", host_line: str = "localhost ansible_connection=local") -> PlaybookRun:
    StubSudo(tmp_path, monkeypatch)
    monkeypatch.setenv("HOME", str(tmp_path))
    play = tmp_path / "play.yml"
    play.write_text(f"- hosts: localhost\n  gather_facts: false\n  tasks:{tasks}{handlers}")
    inventory = tmp_path / "inventory"
    inventory.write_text(host_line + "\n")
    return system_step.run_playbook_as_root([str(Path(sys.executable).parent / "ansible-playbook"), str(play), "--inventory", str(inventory)])


@pytest.mark.parametrize(
    ("tasks", "handlers", "expected"),
    [
        (CHANGED_SKIPPED_AND_HANDLED, HANDLER, PlaybookFinished(2, ("changed task", "handler"))),
        (LOOPED_AND_UNCHANGED, "", PlaybookFinished(1, ("looped task",))),
        (FAILING_ASSERT, "", PlaybookUnfinished("the file names no tunnel", 0)),
        (RESCUE_THAT_FAILS, "", PlaybookUnfinished("the rescue refused", 0)),
        (LOOP_THAT_FAILS_AFTER_A_WRITE, "", PlaybookUnfinished("One or more items failed", 1)),
        (IGNORED_FAILURE, "", PlaybookFinished(0)),
        (RESCUE_THAT_HOLDS, "", PlaybookFinished(0)),
    ],
    ids=["changed skipped and handled", "looped and unchanged", "failed assert", "rescue that fails", "loop that fails after a write", "ignored failure", "rescued failure"],
)
def test_the_callback_reports_counts_and_the_message_of_the_last_failed_task(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tasks: str, handlers: str, expected: PlaybookRun
) -> None:
    """M18: the packaged cfg selects the callback; the reader gets the counts and the last failure."""
    assert run_scratch_play(tmp_path, monkeypatch, tasks, handlers) == expected


def test_an_unreachable_host_is_an_unfinished_run_with_the_connection_message(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The callback's unreachable branch: ssh's exit 255 is unreachable, and the reason carries what ssh printed."""
    refusing_ssh = tmp_path / "refusing-ssh"
    refusing_ssh.write_text("#!/bin/sh\necho 'hal-test: connection refused by fixture' >&2\nexit 255\n")
    refusing_ssh.chmod(0o755)
    host_line = f"localhost ansible_connection=ssh ansible_host=fixture ansible_ssh_executable={refusing_ssh}"

    run = run_scratch_play(tmp_path, monkeypatch, CHANGED_SKIPPED_AND_HANDLED, host_line=host_line)

    assert isinstance(run, PlaybookUnfinished)
    assert "hal-test: connection refused by fixture" in run.reason


def test_without_v_none_of_ansibles_text_shows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]) -> None:
    run_scratch_play(tmp_path, monkeypatch, FAILING_ASSERT)

    assert not capfd.readouterr().out


def test_with_v_ansibles_text_shows_indented_and_no_event_line_does(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    with verbose_run(True):
        run_scratch_play(tmp_path, monkeypatch, FAILING_ASSERT)

    shown = capfd.readouterr().out
    assert "    PLAY RECAP" in shown
    assert system_step.EVENT_MARK not in shown


def test_the_ansible_core_in_the_dev_group_is_the_one_hal_installs() -> None:
    assert f"ansible-core=={version('ansible-core')}" == ANSIBLE_SOURCE


def test_the_live_line_shows_each_task_start_in_run_order_and_a_looped_task_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    """A changed, a skipped, a handler and a looped task each start once; the callback marks the start, never the item."""
    monkeypatch.setattr(hal.output, "LIVE_TICK_SECONDS", 3600)
    put_stdout_on_a_terminal(monkeypatch)
    err = TerminalStream()
    monkeypatch.setattr(sys, "stderr", err)

    run_scratch_play(tmp_path, monkeypatch, CHANGED_SKIPPED_AND_HANDLED + LOOPED_AND_UNCHANGED, HANDLER)

    shown = [re.search(r"system +(.*) \xb7 \S+$", re.sub(r"\x1b\[[0-9;]*[mK]", "", frame)) for frame in err.getvalue().split("\r")]
    names = [match.group(1) for match in shown if match]
    in_run_order = ["changed task", "skipped task", "handler", "looped task", "unchanged task"]
    assert in_run_order == [name for name in names if name != "ansible.builtin.meta"]
