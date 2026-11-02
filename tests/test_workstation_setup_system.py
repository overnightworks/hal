"""The system step of `hal setup` in a sandbox: the Ansible apply and its check mode, the running user that picks the role, and the failures that stop only this step."""

from __future__ import annotations

import json
import pwd
from dataclasses import replace
from pathlib import Path

import pytest
from support.workstation_support import (
    FRESH_APPLY,
    NOT_RUN,
    REPEATED_APPLY,
    SECRETS,
    SUDO_ANNOUNCEMENT,
    TASK_MESSAGE,
    Sandbox,
    global_hooks_path,
    run_setup,
)

import hal.workstation
from hal.grammar import ExitCode
from hal.workstation import system_step
from hal.workstation.layout import Layout
from hal.workstation.setup import RERUN, ExecutionRole
from hal.workstation.system_step import AGENT_USER, CheckState, SystemStep, TasksWouldChange


NOT_CHECKED = "  ! system          not checked    needs sudo at a terminal"

UP_TO_DATE = [*(line for line in REPEATED_APPLY[:-1] if line != SUDO_ANNOUNCEMENT), "✓ setup up to date · 5 unchanged · 47s"]


# --- the system step (#40) ---------------------------------------------------


def playbook_runs(sandbox: Sandbox) -> list[str]:
    """Each Ansible run the system step started: `check` for the dry run's check mode, `apply` for a real run."""
    return ["check" if "--check" in argv else "apply" for argv in sandbox.system.playbook.calls]


def test_the_system_step_comes_after_the_activation_and_asks_for_sudo_once(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """Rule 2 and rule 5: --apply runs Ansible once, with the diff, and only after the activation; sudo asks, never Ansible."""
    code, lines, _ = run_setup(sandbox, capsys)

    (argv,) = sandbox.system.playbook.calls
    assert (code, lines) == (ExitCode.OK, FRESH_APPLY)
    assert argv[:2] == [str(sandbox.layout.ansible_playbook_executable), str(system_step.PLAYBOOK)]
    assert ("--ask-become-pass" in argv, "--diff" in argv, "--check" in argv) == (False, True, False)


def test_the_playbook_gets_home_and_the_tunnel_files_from_layout_and_the_running_user(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    """Rule 5: @HOME@ and @OPERATOR_USER@ are extra vars from home's Layout and the running user, never facts gathered as root."""
    run_setup(sandbox, capsys)

    (argv,) = sandbox.system.playbook.calls
    extra_vars = json.loads(argv[argv.index("--extra-vars") + 1])
    assert {key: extra_vars[key] for key in ("home", "operator_user", "edge_tunnel_dir")} == {
        "home": str(sandbox.home),
        "operator_user": "operator",
        "edge_tunnel_dir": str(Layout(sandbox.home).live_checkout / "tunnel"),
    }


def test_the_playbook_gets_the_agents_account_name_and_the_digest_covers_it(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    run_setup(sandbox, capsys)

    (argv,) = sandbox.system.playbook.calls
    assert json.loads(argv[argv.index("--extra-vars") + 1])["agent_user"] == AGENT_USER == "agent"
    assert "agent_user" in SystemStep(sandbox.layout, sandbox.system.boundaries).extra_vars()


@pytest.mark.parametrize(
    ("user", "role"),
    [("agent", ExecutionRole.AGENT), ("operator", ExecutionRole.OPERATOR), ("root", ExecutionRole.OPERATOR), ("bystander", ExecutionRole.OPERATOR), ("agent2", ExecutionRole.OPERATOR), ("Agent", ExecutionRole.OPERATOR)],
)
def test_only_the_account_named_agent_resolves_to_the_agent_role(user: str, role: ExecutionRole) -> None:
    assert ExecutionRole.of(user) is role


def passwd_entry(name: str, uid: int) -> pwd.struct_passwd:
    return pwd.struct_passwd((name, "x", uid, uid, "", f"/home/{name}", "/bin/sh"))


@pytest.mark.parametrize("names", [("agent", "operator"), ("operator", "agent")])
def test_setup_fails_loud_instead_of_guessing_the_role_when_agent_shares_the_running_uid(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, names: tuple[str, str]
) -> None:
    """Whichever name the lookup by uid would pick, `hal setup` says so and runs no step, with either passwd order."""
    entries = [passwd_entry(name, 1001) for name in names]
    monkeypatch.setattr(system_step.pwd, "getpwall", lambda: entries)
    monkeypatch.setattr(system_step.pwd, "getpwuid", lambda _uid: entries[0])
    monkeypatch.setattr(system_step.os, "getuid", lambda: 1001)
    monkeypatch.setattr(system_step, "TERMINAL_BOUNDARIES", replace(sandbox.system.boundaries, operator_user=system_step._running_user))

    code, lines, error = run_setup(sandbox, capsys)

    assert (code, lines, error.splitlines()) == (
        ExitCode.FAILURE,
        [],
        [f"error: uid 1001 has the names {names[0]}, {names[1]}; agent must have a uid of its own"],
    )
    assert sandbox.system.playbook.calls == []


@pytest.mark.parametrize("names", [("operator", "bystander"), ("agent",)])
def test_the_running_user_is_the_name_of_its_uid_unless_agent_is_one_of_several(
    monkeypatch: pytest.MonkeyPatch, names: tuple[str, ...]
) -> None:
    entries = [passwd_entry(name, 1001) for name in names]
    monkeypatch.setattr(system_step.pwd, "getpwall", lambda: entries)
    monkeypatch.setattr(system_step.pwd, "getpwuid", lambda _uid: entries[0])
    monkeypatch.setattr(system_step.os, "getuid", lambda: 1001)

    assert system_step._running_user() == names[0]


def test_a_user_that_the_passwd_enumeration_omits_is_resolved_by_its_uid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(system_step.pwd, "getpwall", lambda: [])
    monkeypatch.setattr(system_step.pwd, "getpwuid", lambda _uid: passwd_entry("lookuponly", 1001))
    monkeypatch.setattr(system_step.os, "getuid", lambda: 1001)

    assert system_step._running_user() == "lookuponly"


def test_a_running_uid_without_a_passwd_name_is_unresolvable(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(_uid: int) -> pwd.struct_passwd:
        raise KeyError(_uid)

    monkeypatch.setattr(system_step.pwd, "getpwuid", missing)
    monkeypatch.setattr(system_step.os, "getuid", lambda: 1001)

    with pytest.raises(system_step.UnresolvableRunningUser, match="no passwd entry for uid 1001"):
        system_step._running_user()


@pytest.mark.parametrize("flags", [("--dry-run",), ()])
def test_as_the_agent_the_operators_steps_are_skipped_without_sudo_and_the_exit_is_0(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], flags: tuple[str, ...]
) -> None:
    """Cells 4 and 5: the per-user steps behave as for anyone, the operator's are skipped, and neither Ansible nor sudo is started."""
    sandbox.system.user = AGENT_USER
    code, lines, _ = run_setup(sandbox, capsys, *flags)

    hook = "  ~ commit hook     will change" if flags else "  ✓ commit hook     changed"
    closing = (
        "~ setup plan · 1 open, 4 skipped · 47s · run hal setup"
        if flags
        else "✓ setup done · 1 changed, 4 skipped · 47s"
    )
    assert (code, lines) == (
        0,
        [
            hook,
            "  · path            skipped        the operator's step",
            "  · timers          skipped        the operator's step",
            "  · system          skipped        the operator's step",
            "  · secrets         skipped        the operator's step",
            closing,
        ],
    )
    assert sandbox.system.playbook.calls == []


@pytest.mark.parametrize("user", ["root", "bystander"])
def test_every_user_but_the_agent_is_refused_without_a_terminal_before_any_step(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], user: str
) -> None:
    """Cell 7: no sudo inferred from the user's name or rights; root and a bystander meet the yes guard like the operator."""
    sandbox.system.user = user
    sandbox.system.terminal = False
    code, _, err = run_setup(sandbox, capsys)

    assert code == ExitCode.REFUSED
    assert err.splitlines()[0] == "error: setup asks yes at a terminal · nothing changed"
    assert sandbox.system.playbook.calls == []


def test_the_playbook_vacuums_two_days_short_of_the_ruled_retention(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    """T6: the timer's `--vacuum-time` is the ruled 30 days minus the file-span and slack days."""
    run_setup(sandbox, capsys)

    (argv,) = sandbox.system.playbook.calls
    extra_vars = json.loads(argv[argv.index("--extra-vars") + 1])
    assert (system_step.LOG_RETENTION_DAYS, extra_vars["journal_vacuum_days"]) == (30, 28)


def test_the_playbook_is_given_the_journal_as_docker_log_driver(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """E1 to E3: the play merges the one driver name `system_step` owns into `daemon.json`."""
    run_setup(sandbox, capsys)
    (argv,) = sandbox.system.playbook.calls
    extra_vars = json.loads(argv[argv.index("--extra-vars") + 1])
    assert extra_vars["docker_log_driver"] == system_step.DOCKER_LOG_DRIVER == "journald"


def test_the_playbook_ships_inside_the_package() -> None:
    """Rule 3: the playbook is read from beside the module, so a non-editable install carries it."""
    assert system_step.PLAYBOOK.is_file()
    assert system_step.PLAYBOOK.is_relative_to(Path(hal.workstation.__file__).parent)


@pytest.mark.parametrize(
    ("applied_before", "expected"),
    [
        (
            False,
            [
                *UP_TO_DATE[:3],
                "  ~ system          will change    2 tasks",
                "    Write edge files",
                "    Restart Docker",
                UP_TO_DATE[4],
                "~ setup plan · 1 open, 4 unchanged · 47s · run hal setup",
            ],
        ),
        (True, UP_TO_DATE),
    ],
    ids=["something to change", "nothing to change"],
)
def test_a_dry_run_at_a_terminal_checks_with_ansible_and_shows_whether_the_system_step_would_change(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], applied_before: bool, expected: list[str]
) -> None:
    """E1 and rule 7: the dry run asks once for sudo through Ansible's check mode."""
    run_setup(sandbox, capsys)
    sandbox.system.playbook.applied = applied_before

    code, lines, _ = run_setup(sandbox, capsys, "--dry-run")

    assert (code, lines) == (ExitCode.OK, expected)
    assert playbook_runs(sandbox) == ["apply", "check"]


def test_without_a_terminal_the_dry_run_says_not_checked_and_never_starts_ansible(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    """E1 and cell 11: without a terminal nothing root-only is read, and the dry run never claims `unchanged`."""
    run_setup(sandbox, capsys)
    sandbox.system.terminal = False

    code, lines, _ = run_setup(sandbox, capsys, "--dry-run")

    assert (code, lines) == (
        0,
        [
            *UP_TO_DATE[:3],
            NOT_CHECKED,
            UP_TO_DATE[4],
            "~ setup plan · 1 open, 4 unchanged · 47s · run hal setup",
        ],
    )
    assert playbook_runs(sandbox) == ["apply"]


@pytest.mark.parametrize(
    ("terminal", "applied_before", "expected"),
    [(False, True, CheckState.NOT_CHECKED), (True, False, TasksWouldChange(("Write edge files", "Restart Docker"))), (True, True, CheckState.UNCHANGED)],
    ids=["no terminal", "something to change", "nothing to change"],
)
def test_the_system_steps_check_answers_with_one_of_the_three_states(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], terminal: bool, applied_before: bool, expected: CheckState | TasksWouldChange
) -> None:
    """Rule 4: the check returns the enum itself, or the names of the tasks that would change; what a `not checked` step needs first is the presentation's text."""
    run_setup(sandbox, capsys)
    sandbox.system.playbook.applied = applied_before
    sandbox.system.terminal = terminal

    assert SystemStep(sandbox.layout, sandbox.system.boundaries).check() == expected


@pytest.mark.parametrize(
    ("flags", "failure", "fact"),
    [
        ((), "", "Ansible did not finish · hal setup -v shows why"),
        (("-v",), "", "Ansible did not finish · its output above says why"),
        ((), TASK_MESSAGE, TASK_MESSAGE),
    ],
    ids=["no failed task", "no failed task with -v", "a failed task's message"],
)
def test_a_failed_ansible_run_fails_the_system_step_alone_and_records_nothing(sandbox: Sandbox, capsys: pytest.CaptureFixture[str], flags: tuple[str, ...], failure: str, fact: str) -> None:
    """Rule 2, rule 7 and cells 12, 13, 17: a wrong password or a missing tunnel id fails only the last step, with exit 3; the failed task's message is the fact."""
    sandbox.system.playbook.succeeds = False
    sandbox.system.playbook.failure = failure
    code, lines, error = run_setup(sandbox, capsys, *flags)

    assert (code, lines) == (
        ExitCode.FAILURE,
        [
            *FRESH_APPLY[:3],
            SUDO_ANNOUNCEMENT,
            f"  ✗ system          failed         {fact}",
            NOT_RUN[SECRETS],
        ],
    )
    assert error.splitlines() == [
        "error: setup stopped at system · /etc may be partial",
        f"next: {RERUN}",
    ]
    assert global_hooks_path(sandbox) == str(sandbox.layout.git_hooks_dir)


@pytest.mark.parametrize(
    ("flags", "failure", "fact"),
    [
        ((), "", "Ansible's check did not finish · hal setup --dry-run -v shows why"),
        (("-v",), "", "Ansible's check did not finish · its output above says why"),
        ((), TASK_MESSAGE, TASK_MESSAGE),
    ],
    ids=["no failed task", "no failed task with -v", "a failed task's message"],
)
def test_a_failed_check_fails_the_dry_run(sandbox: Sandbox, capsys: pytest.CaptureFixture[str], flags: tuple[str, ...], failure: str, fact: str) -> None:
    """E1: a check Ansible could not finish (a wrong password) is a failure, never `unchanged`."""
    run_setup(sandbox, capsys)
    sandbox.system.playbook.succeeds = False
    sandbox.system.playbook.failure = failure
    code, lines, error = run_setup(sandbox, capsys, "--dry-run", *flags)

    assert (code, lines[3:]) == (
        ExitCode.FAILURE,
        [
            f"  ✗ system          failed         {fact}",
            NOT_RUN[SECRETS],
        ],
    )
    assert error.splitlines() == [
        "error: setup stopped at system · /etc unchanged",
        f"next: {RERUN}",
    ]


def test_a_dry_run_of_one_task_counts_one_task(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    run_setup(sandbox, capsys)
    sandbox.system.playbook.applied = False
    sandbox.system.playbook.tasks = ("Write edge files",)

    _, lines, _ = run_setup(sandbox, capsys, "--dry-run")

    assert lines[3:5] == ["  ~ system          will change    1 task", "    Write edge files"]


def test_a_dry_run_with_v_leaves_the_row_without_task_names_because_ansibles_text_names_them(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    run_setup(sandbox, capsys)
    sandbox.system.playbook.applied = False

    _, lines, _ = run_setup(sandbox, capsys, "--dry-run", "-v")

    assert lines[3:5] == ["  ~ system          will change    2 tasks", UP_TO_DATE[4]]


def test_a_task_name_with_an_escape_is_escaped_in_its_detail_line(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    run_setup(sandbox, capsys)
    sandbox.system.playbook.applied = False
    sandbox.system.playbook.tasks = ("Write \x1b[31mred",)

    _, lines, _ = run_setup(sandbox, capsys, "--dry-run")

    assert lines[4] == "    Write \\x1b[31mred"


def test_with_an_outdated_ansible_the_system_row_keeps_the_count_and_the_task_names(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    """Both steps of the row say `will change`; the row shows the one with the fact."""
    run_setup(sandbox, capsys)
    sandbox.system.playbook.applied = False
    sandbox.layout.ansible_uv_receipt.write_text('[tool]\nrequirements = [{ name = "ansible-core", specifier = "==2.0.0" }]\n')

    _, lines, _ = run_setup(sandbox, capsys, "--dry-run")

    assert lines[3:6] == ["  ~ system          will change    2 tasks", "    Write edge files", "    Restart Docker"]


def test_a_dry_run_under_json_logging_carries_the_task_names_under_details(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    run_setup(sandbox, capsys)
    sandbox.system.playbook.applied = False
    monkeypatch.setenv("LOG_FORMAT", "json")

    _, lines, _ = run_setup(sandbox, capsys, "--dry-run")

    events = [json.loads(line.removeprefix("<6>")) for line in lines]
    system_events = [event for event in events if event.get("subject") == "system"]
    assert len(system_events) == 1
    assert system_events[0]["details"] == ["Write edge files", "Restart Docker"]
