"""`hal setup` shows its plan, asks one exact yes and only then acts; `--dry-run` only shows (#633 E1-E6)."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest
from support.workstation_support import SUDO_ANNOUNCEMENT, Sandbox, run_hal_setup, split_at_the_prompt

from hal.grammar import ExitCode
from hal.workstation.layout import Layout
from hal.workstation.path_link import PathLink
from hal.workstation.system_step import AGENT_USER, Applied

PROMPT = "Type yes to set up 2 open rows: "
NOT_CHECKED_UNTIL_THE_YES = "  ! system          not checked    sudo checks it after your yes"
ABORTED = "error: aborted, nothing changed\n"
NOT_AT_A_TERMINAL = "error: setup asks yes at a terminal · nothing changed\nnext: hal setup in your own terminal window\n"


def nothing_was_done(sandbox: Sandbox) -> bool:
    """No hook file, no `core.hooksPath`, no tool install and no Ansible call: the machine is as the sandbox left it."""
    hooks_path = subprocess.run(["git", "config", "--global", "--get", "core.hooksPath"], capture_output=True, text=True, check=False)
    return (
        not sandbox.layout.git_hooks_dir.exists()
        and hooks_path.stdout.strip() == ""
        and not sandbox.uv_calls.exists()
        and sandbox.system.playbook.calls == []
    )


def run_at_the_prompt(sandbox: Sandbox, capsys: pytest.CaptureFixture[str], *flags: str, **kwargs) -> tuple[int, str, str]:
    code = run_hal_setup(*flags, home=sandbox.home, secrets_setup_boundaries=sandbox.secrets_boundaries, **kwargs)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def a_checkout_under(home: Path) -> Path:
    root = Layout(home).live_checkout
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "hal").write_text("#!/bin/sh\n")
    return root


def test_the_path_row_plans_the_link_changes_nothing_before_the_yes_and_creates_it_after(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """#655 L1, L2: the plan names the link, the yes creates it, and the second run is `unchanged` and asks nothing for it."""
    checkout = a_checkout_under(sandbox.home)
    entry = sandbox.home / ".local" / "bin" / "hal"
    planned_only = run_at_the_prompt(sandbox, capsys, "--dry-run")
    assert not entry.is_symlink()

    code, out, err = run_at_the_prompt(sandbox, capsys)
    plan, run = split_at_the_prompt(out)

    assert (code, err) == (ExitCode.OK, "")
    row = f"  ~ path            will change    ~/.local/bin/hal → ~/{checkout.relative_to(sandbox.home)}/bin/hal"
    assert row in planned_only[1].splitlines()
    assert row in plan
    assert "  ✓ path            changed" in run
    assert entry.readlink() == checkout / "bin" / "hal"

    again = run_at_the_prompt(sandbox, capsys)
    assert "  · path            unchanged" in again[1].splitlines()


def test_a_foreign_entry_at_the_link_fails_the_plan_before_any_change_and_the_later_rows_are_not_run(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """#655 L1: a file of the person's own is named, never replaced; no question is asked and nothing runs."""
    a_checkout_under(sandbox.home)
    entry = sandbox.home / ".local" / "bin" / "hal"
    entry.parent.mkdir(parents=True)
    entry.write_text("my own\n")

    code, out, err = run_at_the_prompt(sandbox, capsys)

    assert (code, err.splitlines()[0]) == (ExitCode.FAILURE, "error: setup stopped at path · nothing changed")
    assert "  ✗ path            failed         ~/.local/bin/hal is not a hal link · move or delete it, then rerun" in out.splitlines()
    assert "  · system          not run" in out.splitlines()
    assert "Type yes" not in out
    assert entry.read_text() == "my own\n"
    assert nothing_was_done(sandbox)


def test_a_path_failure_after_the_yes_does_not_claim_nothing_changed_because_the_commit_hook_was_installed(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """#655 L1: `nothing changed` belongs to a refusal before any change; after the yes the hook row already changed."""
    a_checkout_under(sandbox.home)

    def unwritable_directory(self: PathLink) -> Applied:
        raise PermissionError(13, "Permission denied", str(self.entry.parent))

    monkeypatch.setattr(PathLink, "apply", unwritable_directory)

    code, out, err = run_at_the_prompt(sandbox, capsys)

    assert code == ExitCode.FAILURE
    assert split_at_the_prompt(out)[1][0] == "  ✓ commit hook     changed"
    assert err.splitlines()[0] == "error: setup stopped at path"


def test_setup_prints_the_plan_asks_the_yes_and_then_runs_with_one_sudo_after_it(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """E1, E3 A, E4 A: plan rows, the prompt, then the run; sudo's announcement and the one playbook run come after the yes."""
    code, out, err = run_at_the_prompt(sandbox, capsys)

    plan, run = split_at_the_prompt(out)
    assert (code, err) == (ExitCode.OK, "")
    assert plan == [
        "  ~ commit hook     will change",
        "  · path            unchanged",
        "  · timers          unchanged",
        NOT_CHECKED_UNTIL_THE_YES,
        "  · secrets         complete",
    ]
    assert PROMPT in out
    assert run == [
        "  ✓ commit hook     changed",
        "  · path            unchanged",
        "  · timers          unchanged",
        SUDO_ANNOUNCEMENT,
        "  ✓ system          changed",
        "  · secrets         complete",
        "✓ setup done · 2 changed, 3 unchanged · 47s",
    ]
    assert [("--check" in argv) for argv in sandbox.system.playbook.calls] == [False]


@pytest.mark.parametrize("answer", ["no", "Yes", "YES", "y", " yes", "yes ", "", None], ids=repr)
def test_every_answer_but_exactly_yes_changes_nothing_and_asks_neither_sudo_nor_ansible(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], answer: str | None
) -> None:
    """E2 and cells 4-6, 32: not yes, an empty line and EOF end `aborted, nothing changed`, exit 1, with no step and no playbook call."""
    code, out, err = run_at_the_prompt(sandbox, capsys, answer=answer)

    assert (code, err) == (ExitCode.FINDINGS, ABORTED)
    assert split_at_the_prompt(out)[1] == []
    assert nothing_was_done(sandbox)


def test_ctrl_c_at_the_prompt_exits_130_without_a_line_and_changes_nothing(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """E2 and cell 7: the interrupt is not caught at the prompt; no error line, no step."""
    code, _, err = run_at_the_prompt(sandbox, capsys, answer=KeyboardInterrupt)

    assert (code, err) == (ExitCode.INTERRUPTED, "")
    assert nothing_was_done(sandbox)


@pytest.mark.parametrize("terminal", [True, False], ids=["at a terminal", "without a terminal"])
def test_dry_run_only_shows_and_never_acts_or_asks(sandbox: Sandbox, capsys: pytest.CaptureFixture[str], terminal: bool) -> None:
    """E1 and cells 10, 11: `--dry-run` prints the plan and `run hal setup`, takes no answer, writes nothing."""
    sandbox.system.terminal = terminal
    code, out, err = run_at_the_prompt(sandbox, capsys, "--dry-run", answer="yes")

    assert (code, err) == (ExitCode.OK, "")
    assert split_at_the_prompt(out)[1] == []
    assert out.splitlines()[-1] == "~ setup plan · 2 open, 3 unchanged · 47s · run hal setup"
    assert not sandbox.layout.git_hooks_dir.exists()
    assert not sandbox.uv_calls.exists()


@pytest.mark.parametrize("flags", [("--apply",), ("--dry-run", "--apply")])
def test_apply_is_an_unrecognized_argument_and_nothing_runs(sandbox: Sandbox, capsys: pytest.CaptureFixture[str], flags: tuple[str, ...]) -> None:
    """E1 and cell 12: the flag is gone, no alias; the usage pair names `--apply` and stdout stays empty."""
    with pytest.raises(SystemExit) as exit_of_usage:
        run_hal_setup(*flags, home=sandbox.home, secrets_setup_boundaries=sandbox.secrets_boundaries)

    captured = capsys.readouterr()
    assert (exit_of_usage.value.code, captured.out) == (ExitCode.USAGE, "")
    assert captured.err == "error: unrecognized arguments: --apply\nnext: hal setup --help\n"
    assert nothing_was_done(sandbox)


def test_without_a_terminal_the_plan_prints_and_the_refusal_runs_no_step(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """E5 and cell 9: with an open row and no terminal the plan stands, the pair says where to go, exit 4, and not even the local steps run."""
    sandbox.system.terminal = False
    code, out, err = run_at_the_prompt(sandbox, capsys)

    assert (code, err) == (ExitCode.REFUSED, NOT_AT_A_TERMINAL)
    assert out.splitlines() == [
        "  ~ commit hook     will change",
        "  · path            unchanged",
        "  · timers          unchanged",
        NOT_CHECKED_UNTIL_THE_YES,
        "  · secrets         complete",
    ]
    assert nothing_was_done(sandbox)


def test_the_agent_without_a_terminal_and_an_open_row_is_refused_with_its_files_unchanged(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    """E5, E6 and cell 31: the agent's account meets the same guard; the hook files and the config stay as they were."""
    sandbox.system.user = AGENT_USER
    sandbox.system.terminal = False
    code, _, err = run_at_the_prompt(sandbox, capsys)

    assert (code, err) == (ExitCode.REFUSED, NOT_AT_A_TERMINAL)
    assert nothing_was_done(sandbox)


def test_the_agent_with_nothing_open_gets_no_question_and_needs_no_terminal(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """E2, E6 and cell 8: once the hook is in place the agent's run shows `up to date`, asks nothing and exits 0, terminal or not."""
    sandbox.system.user = AGENT_USER
    run_at_the_prompt(sandbox, capsys)
    sandbox.system.terminal = False
    code, out, err = run_at_the_prompt(sandbox, capsys, answer=None)

    assert (code, err) == (ExitCode.OK, "")
    assert not re.search("Type yes", out)
    assert out.splitlines()[-1] == "✓ setup up to date · 1 unchanged, 4 skipped · 47s"


def test_a_failing_plan_check_stops_before_any_question_and_before_any_earlier_row_acts(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], use_manifest: Callable[[str], Path]
) -> None:
    """E2 and cell 13: the commit hook row would change, the secrets check cannot read its manifest: `setup stopped`, exit 3, no prompt, no earlier action."""
    use_manifest("secret = 5\n")
    code, out, err = run_at_the_prompt(sandbox, capsys)

    assert code == ExitCode.FAILURE
    assert err.splitlines()[0].startswith("error: setup stopped at secrets")
    assert err.splitlines()[-1] == "next: hal setup"
    assert "Type yes" not in out
    assert nothing_was_done(sandbox)
