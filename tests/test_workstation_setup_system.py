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
    run_hal_setup,
    run_setup,
    split_at_the_prompt,
    write_hal_config,
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
    assert "agent_user" in SystemStep(sandbox.layout, sandbox.system.boundaries, system_step.DockerSettings()).extra_vars()


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
    """Cells 4 and 5, D6: the per-user steps behave as for anyone, the operator's are skipped, and neither Ansible, sudo nor Docker's answer is asked for, even when Docker does not answer."""
    sandbox.system.user = AGENT_USER
    sandbox.system.docker_driver = None
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


@pytest.mark.parametrize(
    ("size", "exact_bytes", "reported"),
    [
        ("20GB", 20 * 1024**3, "20GiB"),
        ("20gib", 20 * 1024**3, "20GiB"),
        ("20G", 20 * 1024**3, "20GiB"),
        ("1.5GB", int(1.5 * 1024**3), "1.5GiB"),
        ("512MiB", 512 * 1024**2, "512MiB"),
        ("1024MB", 1024**3, "1GiB"),
        ("1TB", 1024**4, "1TiB"),
        ("1k", 1024, "1KiB"),
        ("2000", 2000, "1.953KiB"),
        ("1B", 1, "1B"),
    ],
)
def test_a_size_is_read_and_shown_the_way_docker_reads_and_shows_it(size: str, exact_bytes: int, reported: str) -> None:
    """Docker's parseGCPolicy reads every unit as binary (go-units RAMInBytes), so `20GB` is 20 GiB, and buildx shows that as `20GiB`."""
    assert (system_step.docker_size_bytes(size), system_step.reported_docker_size(size)) == (exact_bytes, reported)


@pytest.mark.parametrize("malformed", ["", "lots", "GB", "20XB", "-1GB", "0GB", "0", "20 GB", "1e3", "9" * 400, "inf", "99999999PB"])
def test_a_size_hal_does_not_admit_is_no_size(malformed: str) -> None:
    assert system_step.docker_size_bytes(malformed) is None


def test_an_unreadable_size_cannot_be_shown() -> None:
    with pytest.raises(ValueError, match="lots"):
        system_step.reported_docker_size("lots")


def test_the_playbook_is_given_the_limit_and_the_text_docker_reports_for_it(sandbox: Sandbox) -> None:
    """The file gets the configured text; the restart compares with what buildx prints for it."""
    extra_vars = system_step.SystemStep(sandbox.layout, sandbox.system.boundaries, system_step.DockerSettings("15GB")).extra_vars()

    assert (extra_vars["docker_build_cache_max"], extra_vars["docker_build_cache_reported"]) == ("15GB", "15GiB")


def test_the_limit_in_the_settings_file_reaches_the_play_of_hal_setup(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    write_hal_config(sandbox.home, '[docker]\nbuild_cache_max = "15GB"\n')

    run_setup(sandbox, capsys)

    (argv,) = sandbox.system.playbook.calls
    assert json.loads(argv[argv.index("--extra-vars") + 1])["docker_build_cache_max"] == "15GB"


BUILDX_INSPECT = """Name: default
Driver: docker
GC Policy rule#0:
\tAll:\tfalse
\tFilters:\ttype==source.local
\tKeep Duration:\t48h0m0s
\tMax Used Space:\t11.84GiB
GC Policy rule#3:
\tAll:\ttrue
\tReserved Space:\t85.68GiB
\tMax Used Space:\t681.7GiB
\tMin Free Space:\t170.4GiB
"""


@pytest.mark.parametrize(
    ("output", "expected"),
    [(BUILDX_INSPECT, "681.7GiB"), ("Name: default\n", ""), (None, None)],
    ids=["the limit is the last rule's, not the temporary-files rule's", "no rule", "buildx does not answer"],
)
def test_the_limit_is_read_from_the_last_gc_rule_buildx_prints(monkeypatch: pytest.MonkeyPatch, output: str | None, expected: str | None) -> None:
    monkeypatch.setattr(system_step, "run_command", lambda _argv: output)

    assert system_step.TERMINAL_BOUNDARIES.docker_build_cache_limit() == expected


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

    assert SystemStep(sandbox.layout, sandbox.system.boundaries, system_step.DockerSettings()).check() == expected


@pytest.mark.parametrize(
    ("flags", "failure", "changed", "fact", "leaves"),
    [
        ((), "", None, "Ansible did not finish · hal setup -v shows why", "/etc may be partial"),
        (("-v",), "", None, "Ansible did not finish · its output above says why", "/etc may be partial"),
        ((), TASK_MESSAGE, None, TASK_MESSAGE, "/etc may be partial"),
        ((), TASK_MESSAGE, 0, TASK_MESSAGE, "/etc unchanged"),
        ((), system_step.DOCKER_DOES_NOT_ANSWER, 0, system_step.DOCKER_DOES_NOT_ANSWER, "/etc unchanged"),
        ((), TASK_MESSAGE, 2, TASK_MESSAGE, "/etc may be partial"),
        ((), "", 0, "Ansible did not finish · hal setup -v shows why", "/etc unchanged"),
    ],
    ids=["no failed task", "no failed task with -v", "a failed task's message without counts", "a refusal that changed nothing", "the play's own Docker refusal", "a failure after a change", "no failed host and no change"],
)
def test_a_failed_ansible_run_fails_the_system_step_alone_and_records_nothing(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], flags: tuple[str, ...], failure: str, changed: int | None, fact: str, leaves: str
) -> None:
    """Rule 2, rule 7, cells 12, 17 and B1-B4: an Ansible that stopped or a missing tunnel id fails only the last step, with exit 3; the final counts say whether /etc is unchanged."""
    sandbox.system.playbook.succeeds = False
    sandbox.system.playbook.failure = failure
    sandbox.system.playbook.changed_before_failing = changed
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
        f"error: setup stopped at system · {leaves}",
        f"next: {RERUN}",
    ]
    assert global_hooks_path(sandbox) == str(sandbox.layout.git_hooks_dir)


@pytest.mark.parametrize("flags", [(), ("-v",)], ids=["plain", "with -v"])
def test_a_sudo_that_refuses_the_password_fails_the_system_step_with_etc_unchanged(sandbox: Sandbox, capsys: pytest.CaptureFixture[str], flags: tuple[str, ...]) -> None:
    """Ruled S3b-3, cell 13: sudo never started the play, so the error line says the system files are unchanged."""
    sandbox.system.playbook.refused = True
    code, lines, error = run_setup(sandbox, capsys, *flags)

    assert (code, lines[3:]) == (
        ExitCode.FAILURE,
        [SUDO_ANNOUNCEMENT, "  ✗ system          failed         sudo refused", NOT_RUN[SECRETS]],
    )
    assert error.splitlines() == ["error: setup stopped at system · /etc unchanged", f"next: {RERUN}"]
    assert global_hooks_path(sandbox) == str(sandbox.layout.git_hooks_dir)


DOCKER_SILENT = "  ✗ system          failed         Docker does not answer `docker info`"


@pytest.mark.parametrize("flags", [(), ("-v",)], ids=["plain", "with -v"])
def test_a_docker_that_does_not_answer_stops_the_run_before_the_password_and_names_systemctl_status_docker(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], flags: tuple[str, ...]
) -> None:
    """Ruled S3b-4, cells D1 and D2: no needs-sudo row, no play, `/etc unchanged`."""
    sandbox.system.docker_driver = None
    code, lines, error = run_setup(sandbox, capsys, *flags)

    assert (code, lines[3:]) == (ExitCode.FAILURE, [DOCKER_SILENT, NOT_RUN[SECRETS]])
    assert error.splitlines() == ["error: setup stopped at system · /etc unchanged", f"next: {system_step.DOCKER_STATUS}"]
    assert playbook_runs(sandbox) == []
    assert global_hooks_path(sandbox) == str(sandbox.layout.git_hooks_dir)


def test_a_docker_that_does_not_answer_fails_the_dry_run_before_the_play(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """Ruled S3b-4, cell D3."""
    run_setup(sandbox, capsys)
    sandbox.system.docker_driver = None
    sandbox.system.playbook.calls.clear()
    code, lines, error = run_setup(sandbox, capsys, "--dry-run")

    assert (code, lines[3:]) == (ExitCode.FAILURE, [DOCKER_SILENT, NOT_RUN[SECRETS]])
    assert error.splitlines() == ["error: setup stopped at system · /etc unchanged", f"next: {system_step.DOCKER_STATUS}"]
    assert playbook_runs(sandbox) == []


@pytest.mark.parametrize("dry_run", [(), ("--dry-run",)], ids=["run", "dry run"])
def test_a_build_cache_limit_docker_does_not_report_stops_the_run_before_the_password(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], dry_run: tuple[str, ...]
) -> None:
    """The play restarts Docker for a limit it reads as root, so a limit the operator cannot read refuses before sudo and names `systemctl status docker`."""
    run_setup(sandbox, capsys)
    sandbox.system.build_cache_limit = None
    sandbox.system.playbook.calls.clear()
    code, lines, error = run_setup(sandbox, capsys, *dry_run)

    assert (code, lines[3], error.splitlines()) == (
        ExitCode.FAILURE,
        "  ✗ system          failed         Docker does not answer `docker buildx inspect default`",
        ["error: setup stopped at system · /etc unchanged", f"next: {system_step.DOCKER_STATUS}"],
    )
    assert playbook_runs(sandbox) == []


def test_a_dry_run_without_a_terminal_reads_no_docker(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """Ruled S3b-4, cell D5: `needs_first` answers before Docker is read."""
    sandbox.system.docker_driver = None
    sandbox.system.terminal = False
    code, lines, _ = run_setup(sandbox, capsys, "--dry-run")

    assert (code, NOT_CHECKED in lines) == (ExitCode.OK, True)


def test_a_sudo_that_refuses_the_password_fails_the_dry_run_with_etc_unchanged(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    run_setup(sandbox, capsys)
    sandbox.system.playbook.refused = True
    code, lines, error = run_setup(sandbox, capsys, "--dry-run")

    assert (code, lines[3:]) == (ExitCode.FAILURE, ["  ✗ system          failed         sudo refused", NOT_RUN[SECRETS]])
    assert error.splitlines()[0] == "error: setup stopped at system · /etc unchanged"


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
    """E1: a check Ansible could not finish is a failure, never `unchanged`."""
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


def docker_restarts(consequence: str) -> str:
    return f"  ! docker          restarts       {consequence}"


@pytest.mark.parametrize("flags", [(), ("-v",)], ids=["plain", "with -v"])
@pytest.mark.parametrize(
    ("policies", "consequence"),
    [
        (("no", "on-failure", "always", "unless-stopped"), "all containers stop · 2 stay down"),
        (("always", "no"), "all containers stop · 1 stays down"),
        (("always", "unless-stopped"), "all containers stop · 0 stay down"),
        ((), "all containers stop · 0 stay down"),
        (None, "all containers stop"),
    ],
    ids=["two stay down", "one stays down", "none stays down", "none running", "policies unreadable"],
)
def test_a_docker_that_restarts_is_named_with_the_containers_that_stay_down_before_the_password(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], flags: tuple[str, ...], policies: tuple[str, ...] | None, consequence: str
) -> None:
    """Ruled S3b-5, cells R1 to R4: the row stands after the timers and before the sudo row, the verdict counts what it counted, and the run goes on."""
    sandbox.system.docker_driver = "json-file"
    sandbox.system.running_policies = policies
    code, lines, _ = run_setup(sandbox, capsys, *flags)

    assert (code, lines) == (ExitCode.OK, [*FRESH_APPLY[:3], docker_restarts(consequence), *FRESH_APPLY[3:]])
    assert sandbox.system.driver_reads == 1


@pytest.mark.parametrize(
    "reported",
    ["681.7GiB", ""],
    ids=["another limit", "no limit"],
)
def test_a_docker_that_lacks_the_limit_is_forecast_to_restart(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], reported: str
) -> None:
    """Docker that does not report the limit restarts although the driver is already the journal."""
    sandbox.system.build_cache_limit = reported
    code, lines, _ = run_setup(sandbox, capsys)

    assert (code, any("restarts" in line for line in lines)) == (ExitCode.OK, True)


def test_a_docker_that_reports_the_limit_is_not_forecast_to_restart(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    code, lines, _ = run_setup(sandbox, capsys)

    assert (code, any("restarts" in line for line in lines)) == (ExitCode.OK, False)


def test_a_play_that_fails_after_the_restart_was_named_ends_with_the_red_row_and_etc_unchanged(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """Ruled S3b-5, cell R9."""
    sandbox.system.docker_driver = "json-file"
    sandbox.system.running_policies = ("no", "no")
    sandbox.system.playbook.succeeds = False
    sandbox.system.playbook.failure = TASK_MESSAGE
    sandbox.system.playbook.changed_before_failing = 0
    code, lines, error = run_setup(sandbox, capsys)

    assert (code, lines[3:]) == (
        ExitCode.FAILURE,
        [docker_restarts("all containers stop · 2 stay down"), SUDO_ANNOUNCEMENT, f"  ✗ system          failed         {TASK_MESSAGE}", NOT_RUN[SECRETS]],
    )
    assert error.splitlines() == ["error: setup stopped at system · /etc unchanged", f"next: {RERUN}"]


def test_the_agent_prints_no_restart_row_on_a_docker_that_would_restart(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """Ruled S3b-5, cell R7: the agent role reads no Docker."""
    sandbox.system.docker_driver = "json-file"
    sandbox.system.running_policies = ("no",)
    sandbox.system.user = AGENT_USER
    _, lines, _ = run_setup(sandbox, capsys)

    assert not any("restarts" in line for line in lines)
    assert sandbox.system.driver_reads == 0


def test_the_dry_run_and_the_plan_before_the_yes_print_no_restart_row_on_a_docker_that_would_restart(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """Ruled S3b-5, cell R6: the restart is named at the sudo announcement, so neither the dry run nor the plan half of a run holds it."""
    sandbox.system.docker_driver = "json-file"
    sandbox.system.running_policies = ("no",)
    _, dry_lines, _ = run_setup(sandbox, capsys, "--dry-run")
    run_hal_setup(home=sandbox.home, secrets_setup_boundaries=sandbox.secrets_boundaries)
    plan, _ = split_at_the_prompt(capsys.readouterr().out)

    assert not any("restarts" in line for line in [*dry_lines, *plan])
