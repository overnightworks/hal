"""The user-units step of `hal setup` against a sandboxed HOME and a fake `systemctl --user`."""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from support.workstation_support import Sandbox, run_hal_setup, write_hal_config

from hal import cli as hal_cli
from hal.grammar import ExitCode
from hal.workstation import jobs
from hal.workstation.system_step import Applied, CheckState, StepFailed
from hal.workstation.layout import Layout, run_command
from hal.workstation.user_units import GENERATED_MARKER, UnitsPartial, UserUnits

DECLARED_JOBS = jobs.TIMER_JOBS
UNIT_NAMES = [f"{job.name}{suffix}" for job in DECLARED_JOBS for suffix in (".service", ".timer")]
TIMER_NAMES = [name for name in UNIT_NAMES if name.endswith(".timer")]
TIMERS_WANTS = "timers.target.wants"
MUTATING_VERBS = {"daemon-reload", "enable", "disable", "stop"}
NOT_WRITTEN_BY_HAL = "was not written by hal · move or delete it, then rerun"
TIMER_COUNT = f"{len(TIMER_NAMES)} timers"
LINK_COUNT = f"{len(UNIT_NAMES)} links"


class FakeSystemctl:
    """systemd's view of the user units: what it loaded at the last reload, and what runs.

    Like systemd 259 it keeps a unit loaded until the next reload and counts a timer as enabled by
    the name of its link in `timers.target.wants/` alone, whatever the link points at.
    """

    def __init__(self, user_units: Path) -> None:
        self.user_units = user_units
        self.calls: list[list[str]] = []
        self.failing: list[str] | None = None
        self.loaded: dict[str, str] = {}
        self.active: set[str] = set()
        self.starts_nothing = False
        self.enables_to: Path | None = None

    def __call__(self, argv: Sequence[str]) -> str | None:
        assert argv[:2] == ["systemctl", "--user"]
        verb, *arguments = argv[2:]
        self.calls.append([verb, *arguments])
        if self.failing is not None and [verb, *arguments][: len(self.failing)] == self.failing:
            return None
        if verb == "daemon-reload":
            self.loaded = {
                link.name: link.read_text() for link in self.user_units.iterdir() if link.is_file()
            }
        elif verb == "enable":
            self.enable(arguments[-1])
        else:
            return self.show(arguments[0])
        return ""

    def enable(self, name: str) -> None:
        wants = self.user_units / TIMERS_WANTS
        wants.mkdir(exist_ok=True)
        if not os.path.lexists(wants / name):
            (wants / name).symlink_to(self.enables_to or self.user_units / name)
        if not self.starts_nothing:
            self.active.add(name)

    def show(self, name: str) -> str:
        entry = self.user_units / name
        stale = entry.exists() and self.loaded.get(name) != entry.read_text()
        enabled = os.path.lexists(self.user_units / TIMERS_WANTS / name)
        return "\n".join(
            [
                f"NeedDaemonReload={'yes' if stale else 'no'}",
                f"UnitFileState={'enabled' if enabled else 'linked'}",
                f"ActiveState={'active' if name in self.active else 'inactive'}",
            ]
        )

    @property
    def changes(self) -> list[list[str]]:
        return [call for call in self.calls if call[0] in MUTATING_VERBS]


class FailingSecondReplace:
    """`os.replace`, except that its second call raises as a full disk would."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, source: Path, destination: Path) -> None:
        self.calls += 1
        if self.calls == 2:
            raise OSError(28, "No space left on device", str(destination))
        os.replace(source, destination)


class Machine:
    """A home with the declared timer jobs, a fake systemd and the step over both."""

    def __init__(self, home: Path, replace: Callable[[Path, Path], None] = os.replace) -> None:
        self.home = home
        self.layout = Layout(home)
        self.user_units = home / ".config" / "systemd" / "user"
        self.user_units.mkdir(parents=True)
        self.systemctl = FakeSystemctl(self.user_units)
        self.step = UserUnits(self.layout, DECLARED_JOBS, self.systemctl, replace)

    @property
    def wants(self) -> Path:
        return self.user_units / TIMERS_WANTS

    def expected_unit_text(self, name: str) -> str:
        live = self.layout.live_checkout.relative_to(self.home)
        return GENERATED_MARKER + "\n" + EXPECTED_UNIT_TEXTS[name].format(live=live)

    @property
    def legacy_directory(self) -> Path:
        return self.layout.live_checkout / "systemd"

    def arrange_legacy_links(self, *, dangling: bool) -> None:
        """Today's state: a link per unit into `<live checkout>/systemd/`, one per timer in the
        wants directory, systemd loaded and every timer running."""
        self.legacy_directory.mkdir(parents=True)
        self.wants.mkdir()
        for name in UNIT_NAMES:
            (self.legacy_directory / name).write_text(f"[Unit]\nDescription={name}\n")
            (self.user_units / name).symlink_to(self.legacy_directory / name)
        for name in TIMER_NAMES:
            (self.wants / name).symlink_to(self.legacy_directory / name)
        self.systemctl(["systemctl", "--user", "daemon-reload"])
        self.systemctl.active.update(TIMER_NAMES)
        self.systemctl.calls.clear()
        if dangling:
            for name in UNIT_NAMES:
                (self.legacy_directory / name).unlink()

    def arrange_complete_state(self) -> None:
        self.step.apply()
        self.systemctl.calls.clear()

    def unit_text(self, name: str) -> str:
        return (self.user_units / name).read_text()

    def tree(self) -> dict[str, tuple[str, str]]:
        """Every entry below the unit directory: links by target, files by content."""
        return {
            str(path.relative_to(self.user_units)): (
                ("link", str(path.readlink())) if path.is_symlink() else ("file", path.read_text())
            )
            for path in sorted(self.user_units.rglob("*"))
            if path.is_symlink() or path.is_file()
        }

    def assert_complete(self) -> None:
        for name in UNIT_NAMES:
            entry = self.user_units / name
            assert entry.is_file()
            assert not entry.is_symlink()
            assert self.unit_text(name).startswith(GENERATED_MARKER + "\n")
        for name in TIMER_NAMES:
            assert (self.wants / name).readlink() == self.user_units / name
        assert self.systemctl.active >= set(TIMER_NAMES)
        assert self.step.verify()


@pytest.fixture
def machine(tmp_path: Path) -> Machine:
    return Machine(tmp_path / "home")


def test_a_fresh_apply_writes_a_marker_file_per_unit_reloads_then_enables_every_timer(
    machine: Machine,
) -> None:
    assert machine.step.apply().applied is Applied.CHANGED

    machine.assert_complete()
    assert machine.systemctl.changes == [
        ["daemon-reload"],
        *(["enable", "--now", name] for name in TIMER_NAMES),
    ]


def calendar_timer(description: str, calendar: str) -> str:
    """A timer on a calendar that catches up a missed run."""
    return f"""\
[Unit]
Description={description}

[Timer]
OnCalendar={calendar}
Persistent=true

[Install]
WantedBy=timers.target
"""


EXPECTED_UNIT_TEXTS = {
    "hal-backup.service": """\
[Unit]
Description=hal backup: encrypted restic backup of the declared apps
Documentation=file://%h/{live}/docs/backup.md

[Service]
Type=oneshot
Environment=LOG_FORMAT=json
ExecStart=%h/{live}/.venv/bin/hal backup
TimeoutStartSec=6h
""",
    "hal-backup.timer": calendar_timer("hal backup weekly, Sunday 03:00", "Sun *-*-* 03:00:00"),
    "hal-check.timer": calendar_timer("Daily hal check", "*-*-* 09:00"),
    "hal-check.service": """\
[Unit]
Description=hal check: reports what is wrong on this machine and in the secrets manifest; mails only when a finding appears or goes

[Service]
Type=oneshot
ExecStart=%h/{live}/.venv/bin/hal check
SuccessExitStatus=1
""",
    "hal-alarm.timer": """\
[Unit]
Description=hal alarm every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
""",
    "hal-alarm.service": """\
[Unit]
Description=hal alarm: mails a service or backup finding that several runs in a row reported, and one that went

[Service]
Type=oneshot
ExecStart=%h/{live}/.venv/bin/hal alarm
""",
    "hal-backup-restore-test.service": """\
[Unit]
Description=hal backup: restore the latest snapshots and prove they are good
Documentation=file://%h/{live}/docs/backup.md

[Service]
Type=oneshot
Environment=LOG_FORMAT=json
ExecStart=%h/{live}/.venv/bin/hal restore --test
TimeoutStartSec=6h
""",
    "hal-backup-restore-test.timer": calendar_timer(
        "hal backup restore test monthly, first Sunday 05:00", "Sun *-*-01..07 05:00:00"
    ),
    "hal-expire.service": """\
[Unit]
Description=hal expire: deletes what LiteLLM keeps per person or per tool once unused for its retention period
Documentation=file://%h/{live}/docs/agent-service.md

[Service]
Type=oneshot
Environment=LOG_FORMAT=json
ExecStart=%h/{live}/.venv/bin/hal expire
TimeoutStartSec=15min
""",
    "hal-expire.timer": calendar_timer("Daily hal expire, 04:00", "*-*-* 04:00:00"),
}


@pytest.mark.parametrize("name", EXPECTED_UNIT_TEXTS)
def test_a_generated_unit_is_the_marker_then_the_declared_unit_text(
    machine: Machine, name: str
) -> None:
    machine.step.apply()

    assert machine.unit_text(name) == machine.expected_unit_text(name)


@pytest.mark.parametrize("job", DECLARED_JOBS, ids=lambda job: job.name)
def test_every_declared_job_runs_a_verb_the_cli_registers(job: jobs.TimerJob) -> None:
    with pytest.raises(SystemExit) as help_shown:
        hal_cli.main([job.verb, *job.arguments, "--help"])

    assert help_shown.value.code == 0


def test_a_dry_run_reports_a_change_and_touches_nothing(machine: Machine) -> None:
    assert machine.step.check() is CheckState.WOULD_CHANGE

    assert machine.tree() == {}
    assert machine.systemctl.changes == []


def test_a_second_apply_changes_nothing(machine: Machine) -> None:
    machine.arrange_complete_state()
    before = machine.tree()

    assert (machine.step.apply().applied, machine.step.check()) == (
        Applied.UNCHANGED,
        CheckState.UNCHANGED,
    )
    assert machine.systemctl.changes == []
    assert machine.tree() == before


@pytest.mark.parametrize("dangling", [False, True], ids=["existing", "dangling"])
def test_the_legacy_links_are_replaced_by_files_and_nothing_is_stopped(
    machine: Machine, dangling: bool
) -> None:
    machine.arrange_legacy_links(dangling=dangling)

    assert machine.step.check() is CheckState.WOULD_CHANGE
    assert machine.step.apply().applied is Applied.CHANGED

    machine.assert_complete()
    assert not any(
        target.startswith(str(machine.legacy_directory))
        for kind, target in machine.tree().values()
        if kind == "link"
    )
    assert machine.systemctl.changes == [["daemon-reload"]]


@pytest.mark.parametrize("dangling_wants_link", [False, True], ids=["existing", "dangling"])
def test_an_enabled_active_timer_with_a_legacy_wants_link_is_repointed_without_enable(
    machine: Machine, dangling_wants_link: bool
) -> None:
    machine.arrange_complete_state()
    machine.legacy_directory.mkdir(parents=True)
    for position, name in enumerate(TIMER_NAMES):
        (machine.wants / name).unlink()
        (machine.wants / name).symlink_to(machine.legacy_directory / name)
        if not (dangling_wants_link and position == 0):
            (machine.legacy_directory / name).write_text("[Timer]\n")

    assert machine.step.check() is CheckState.WOULD_CHANGE
    machine.step.apply()

    machine.assert_complete()
    assert [call[0] for call in machine.systemctl.calls if call[0] in ("enable", "stop")] == []


def test_the_plan_fact_names_the_replaced_links_only_while_a_link_points_into_systemd(
    machine: Machine,
) -> None:
    assert machine.step.open_fact() == ""
    machine.arrange_legacy_links(dangling=False)
    assert machine.step.open_fact() == f"replaces {LINK_COUNT} with {TIMER_COUNT}"
    machine.step.apply()
    (machine.user_units / "hal-check.service").unlink()
    assert machine.step.open_fact() == ""


def test_a_stale_marker_file_is_rewritten_and_systemd_reloaded(machine: Machine) -> None:
    machine.arrange_complete_state()
    stale = machine.user_units / "hal-check.service"
    stale.write_text(GENERATED_MARKER + "\n[Service]\nExecStart=%h/git/old/.venv/bin/hal check\n")

    assert machine.step.check() is CheckState.WOULD_CHANGE
    machine.step.apply()

    assert machine.unit_text("hal-check.service") == (
        machine.expected_unit_text("hal-check.service")
    )
    assert machine.systemctl.changes == [["daemon-reload"]]
    machine.assert_complete()


def test_an_older_backup_unit_without_the_log_format_is_rewritten_with_it_and_stays_enabled(
    sandboxed_machine: Machine, sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    sandboxed_machine.arrange_complete_state()
    older = sandboxed_machine.user_units / "hal-backup.service"
    older.write_text(
        "".join(
            line
            for line in older.read_text().splitlines(keepends=True)
            if not line.startswith("Environment=")
        )
    )

    _, planned, _ = setup_lines(sandboxed_machine, sandbox, capsys, "--dry-run")
    setup_lines(sandboxed_machine, sandbox, capsys)

    assert any(line.startswith("  ~ timers          will change") for line in planned)
    assert "Environment=LOG_FORMAT=json" in older.read_text().splitlines()
    assert "UnitFileState=enabled" in sandboxed_machine.systemctl.show(TIMER_NAMES[0])
    sandboxed_machine.assert_complete()


def test_a_drop_in_directory_is_never_touched(machine: Machine) -> None:
    drop_in = machine.user_units / "hal-check.service.d" / "override.conf"
    drop_in.parent.mkdir()
    drop_in.write_text("[Service]\nNice=5\n")

    machine.step.apply()
    machine.step.apply()

    assert drop_in.read_text() == "[Service]\nNice=5\n"


def own_file_without_marker(machine: Machine, unit: Path) -> str:
    unit.write_text("[Service]\nExecStart=/mine\n")
    return unit.name


def link_elsewhere(machine: Machine, unit: Path) -> str:
    unit.symlink_to(machine.user_units.parent / "another-project.service")
    return unit.name


def mask(machine: Machine, unit: Path) -> str:
    unit.symlink_to("/dev/null")
    return unit.name


def symlink_to_a_marker_file(machine: Machine, unit: Path) -> str:
    target = machine.user_units.parent / "elsewhere.service"
    target.write_text(GENERATED_MARKER + "\n[Service]\n")
    unit.symlink_to(target)
    return unit.name


def dependency_link_of_another_target(machine: Machine, unit: Path) -> str:
    requires = machine.user_units / "custom.target.requires"
    requires.mkdir()
    machine.legacy_directory.mkdir(parents=True, exist_ok=True)
    (requires / "hal-backup.service").symlink_to(machine.legacy_directory / "hal-backup.service")
    return "custom.target.requires/hal-backup.service"


def symlinked_dependency_directory(machine: Machine, unit: Path) -> str:
    elsewhere = machine.user_units.parent / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "hal-backup.service").symlink_to("/tmp/foreign.service")  # noqa: S108 - a symlink target that is never opened
    (machine.user_units / "custom.target.requires").symlink_to(elsewhere)
    return "custom.target.requires/hal-backup.service"


def directory_named_like_a_unit(machine: Machine, unit: Path) -> str:
    unit.mkdir()
    return unit.name


def file_inside_a_wants_directory(machine: Machine, unit: Path) -> str:
    machine.wants.mkdir()
    (machine.wants / "hal-backup.timer").write_text("[Timer]\n")
    return f"{TIMERS_WANTS}/hal-backup.timer"


@pytest.mark.parametrize(
    "occupy",
    [
        own_file_without_marker,
        link_elsewhere,
        mask,
        symlink_to_a_marker_file,
        directory_named_like_a_unit,
        dependency_link_of_another_target,
        symlinked_dependency_directory,
        file_inside_a_wants_directory,
    ],
)
def test_an_entry_hal_did_not_write_is_refused_before_any_change(
    machine: Machine, occupy: Callable[[Machine, Path], str]
) -> None:
    (machine.user_units / "hal-backup.service").write_text(GENERATED_MARKER + "\nstale\n")
    refused = occupy(machine, machine.user_units / "hal-check.service")
    before = machine.tree()

    for action in (machine.step.apply, machine.step.check):
        with pytest.raises(StepFailed, match=f"^{refused} {NOT_WRITTEN_BY_HAL}$") as raised:
            action()
        assert not isinstance(raised.value, UnitsPartial)

    assert machine.tree() == before
    assert machine.systemctl.changes == []


def test_the_generated_wants_links_are_accepted_and_left_untouched(machine: Machine) -> None:
    machine.arrange_complete_state()
    links_before = {name: (machine.wants / name).lstat().st_ino for name in TIMER_NAMES}

    machine.step.apply()

    assert {name: (machine.wants / name).lstat().st_ino for name in TIMER_NAMES} == links_before


def test_a_failed_replacement_after_one_success_leaves_a_mixed_tree_a_fresh_apply_completes(
    tmp_path: Path,
) -> None:
    machine = Machine(tmp_path / "home", replace=FailingSecondReplace())
    machine.arrange_legacy_links(dangling=False)

    with pytest.raises(UnitsPartial, match="^.*hal-.*: No space left on device$"):
        machine.step.apply()

    entries = [machine.user_units / name for name in UNIT_NAMES]
    assert [entry.is_symlink() for entry in entries] == [False, *[True] * (len(UNIT_NAMES) - 1)]
    assert all(
        entry.readlink().parent == machine.legacy_directory
        for entry in entries
        if entry.is_symlink()
    )
    machine.step = UserUnits(machine.layout, DECLARED_JOBS, machine.systemctl)
    machine.step.apply()
    machine.assert_complete()
    assert not any(
        target.startswith(str(machine.legacy_directory))
        for kind, target in machine.tree().values()
        if kind == "link"
    )


def test_a_timer_of_another_job_in_the_wants_directory_is_left_alone(machine: Machine) -> None:
    other = machine.wants / "other.timer"
    machine.wants.mkdir()
    other.symlink_to(machine.user_units.parent / "other.timer")

    machine.step.apply()

    assert other.readlink() == machine.user_units.parent / "other.timer"
    machine.assert_complete()


def test_a_marker_file_with_undecodable_bytes_is_rewritten(machine: Machine) -> None:
    machine.arrange_complete_state()
    (machine.user_units / "hal-check.service").write_bytes(GENERATED_MARKER.encode() + b"\n\xff")

    machine.step.apply()

    machine.assert_complete()
    assert machine.unit_text("hal-check.service") == (
        machine.expected_unit_text("hal-check.service")
    )


def test_an_entry_of_the_person_at_the_temporary_name_survives_a_failed_apply(
    machine: Machine,
) -> None:
    temporary = machine.user_units / ".hal-backup.service.tmp"
    temporary.write_text("mine\n")

    with pytest.raises(UnitsPartial):
        machine.step.apply()

    assert temporary.read_text() == "mine\n"


def test_a_write_that_fails_after_the_temporary_exists_leaves_none_and_a_fresh_apply_completes(
    machine: Machine, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_chmod = Path.chmod
    failures = [OSError(28, "No space left on device")]

    def chmod_failing_once(path: Path, mode: int) -> None:
        if failures:
            raise failures.pop()
        real_chmod(path, mode)

    monkeypatch.setattr(Path, "chmod", chmod_failing_once)
    with pytest.raises(UnitsPartial, match="No space left on device"):
        machine.step.apply()

    assert not list(machine.user_units.glob(".*.tmp"))
    machine.step.apply()
    machine.assert_complete()


def test_the_generated_wants_links_in_a_symlinked_wants_directory_are_accepted_on_a_rerun(
    machine: Machine, tmp_path: Path
) -> None:
    (tmp_path / "elsewhere").mkdir()
    machine.wants.symlink_to(tmp_path / "elsewhere")
    machine.step.apply()
    machine.systemctl.calls.clear()

    machine.step.apply()

    machine.assert_complete()
    assert machine.systemctl.changes == []


@pytest.mark.parametrize("verb", ["daemon-reload", "enable", "show"])
def test_a_failing_systemctl_fails_the_step_as_partial_and_a_fresh_apply_recovers(
    machine: Machine, verb: str
) -> None:
    machine.systemctl.failing = [verb]

    with pytest.raises(UnitsPartial, match=f"^systemctl {verb}.* failed$"):
        machine.step.apply()

    machine.systemctl.failing = None
    machine.step.apply()
    machine.assert_complete()


def test_a_failing_enable_of_the_second_timer_leaves_the_first_enabled_and_recovers(
    machine: Machine,
) -> None:
    machine.systemctl.failing = ["enable", "--now", TIMER_NAMES[1]]

    with pytest.raises(UnitsPartial, match="enable --now hal-backup-restore-test.timer failed"):
        machine.step.apply()

    assert (machine.wants / TIMER_NAMES[0]).is_symlink()
    machine.systemctl.failing = None
    machine.step.apply()
    machine.assert_complete()


def test_a_failing_enable_after_current_files_without_a_reload_is_partial_and_recovers(
    machine: Machine,
) -> None:
    machine.arrange_complete_state()
    for name in TIMER_NAMES:
        (machine.wants / name).unlink()
    machine.systemctl.active.clear()
    machine.systemctl.failing = ["enable", "--now", TIMER_NAMES[1]]

    with pytest.raises(UnitsPartial):
        machine.step.apply()

    assert ["daemon-reload"] not in machine.systemctl.calls
    machine.systemctl.failing = None
    machine.step.apply()
    machine.assert_complete()


def test_a_timer_that_does_not_run_after_enabling_fails_the_step_naming_it(
    machine: Machine,
) -> None:
    machine.systemctl.starts_nothing = True

    with pytest.raises(UnitsPartial, match="hal-backup.timer.* enabled but not active"):
        machine.step.apply()


def test_a_wants_link_that_does_not_read_back_as_the_generated_timer_fails_the_step(
    machine: Machine, tmp_path: Path
) -> None:
    machine.systemctl.enables_to = tmp_path / "somewhere-else.timer"

    with pytest.raises(UnitsPartial, match=f"{TIMERS_WANTS}/hal-backup.timer"):
        machine.step.apply()


@pytest.fixture
def sandboxed_machine(sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch) -> Machine:
    """The sandbox's home with the declared jobs, and the fake systemd in place of the real one."""
    monkeypatch.setattr(jobs, "TIMER_JOBS", DECLARED_JOBS)
    return Machine(sandbox.home)


def setup_lines(
    machine: Machine, sandbox: Sandbox, capsys: pytest.CaptureFixture[str], *flags: str
) -> tuple[int, list[str], list[str]]:
    """The exit code, the stdout lines and the stderr lines of `hal setup`, systemd answered by the machine's fake and every other tool as in the sandbox."""

    def run(argv: Sequence[str]) -> str | None:
        return machine.systemctl(argv) if argv[0] == "systemctl" else run_command(argv)

    code = run_hal_setup(
        *flags, home=sandbox.home, secrets_setup_boundaries=sandbox.secrets_boundaries, run=run
    )
    captured = capsys.readouterr()
    return code, captured.out.splitlines(), captured.err.splitlines()


def test_a_changed_timers_row_counts_the_timers_and_says_systemd_reloaded(
    sandboxed_machine: Machine, sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    code, lines, _ = setup_lines(sandboxed_machine, sandbox, capsys)

    assert code == ExitCode.OK
    assert f"  ✓ timers          changed        {TIMER_COUNT} · systemd reloaded" in lines


def test_a_changed_timers_row_without_a_reload_only_counts_the_timers(
    sandboxed_machine: Machine, sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    sandboxed_machine.arrange_complete_state()
    sandboxed_machine.systemctl.active.clear()
    (sandboxed_machine.wants / TIMER_NAMES[0]).unlink()

    _, lines, _ = setup_lines(sandboxed_machine, sandbox, capsys)

    assert f"  ✓ timers          changed        {TIMER_COUNT}" in lines


def test_an_unchanged_timers_row_is_bare(
    sandboxed_machine: Machine, sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    sandboxed_machine.arrange_complete_state()

    _, lines, _ = setup_lines(sandboxed_machine, sandbox, capsys)

    assert "  · timers          unchanged" in lines


def test_no_loaded_unit_line_follows_the_timers_row(
    sandboxed_machine: Machine, sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    output = "\n".join(setup_lines(sandboxed_machine, sandbox, capsys)[1])

    assert "ExecStart=" not in output
    assert "Result=" not in output


def test_the_plan_of_the_first_run_after_the_move_names_the_replaced_links(
    sandboxed_machine: Machine, sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    sandboxed_machine.arrange_legacy_links(dangling=False)

    _, lines, _ = setup_lines(sandboxed_machine, sandbox, capsys, "--dry-run")

    assert f"  ~ timers          will change    replaces {LINK_COUNT} with {TIMER_COUNT}" in lines
    assert sandboxed_machine.systemctl.changes == []


def test_a_refused_entry_stops_setup_at_timers_with_nothing_changed(
    sandboxed_machine: Machine, sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    (sandboxed_machine.user_units / "hal-check.timer").write_text("[Timer]\n")

    code, lines, errors = setup_lines(sandboxed_machine, sandbox, capsys)

    assert code == ExitCode.FAILURE
    assert f"  ✗ timers          failed         hal-check.timer {NOT_WRITTEN_BY_HAL}" in lines
    assert errors == ["error: setup stopped at timers · nothing changed", "next: hal setup"]


def test_a_failure_after_the_classification_stops_setup_at_timers_with_units_partial(
    sandboxed_machine: Machine, sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    sandboxed_machine.systemctl.failing = ["daemon-reload"]

    code, lines, errors = setup_lines(sandboxed_machine, sandbox, capsys)

    assert code == ExitCode.FAILURE
    assert "  ✗ timers          failed         systemctl daemon-reload failed" in lines
    assert errors == ["error: setup stopped at timers · units may be partial", "next: hal setup"]
    sandboxed_machine.systemctl.failing = None
    assert setup_lines(sandboxed_machine, sandbox, capsys)[0] == ExitCode.OK
    sandboxed_machine.assert_complete()


@pytest.mark.parametrize(("table", "minutes"), [("", 5), ("[alarm]\ninterval = 12\n", 12)])
def test_hal_setup_writes_the_alarm_timer_from_the_configured_interval(
    sandboxed_machine: Machine,
    sandbox: Sandbox,
    capsys: pytest.CaptureFixture[str],
    table: str,
    minutes: int,
) -> None:
    write_hal_config(sandbox.home, table)

    code, _, _ = setup_lines(sandboxed_machine, sandbox, capsys)

    assert code == ExitCode.OK
    timer = sandboxed_machine.unit_text("hal-alarm.timer")
    assert f"OnUnitActiveSec={minutes}min\n" in timer
    assert "OnCalendar" not in timer


def test_a_new_interval_rewrites_the_alarm_timer_and_reloads_systemd(
    sandboxed_machine: Machine, sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    setup_lines(sandboxed_machine, sandbox, capsys)
    write_hal_config(sandbox.home, "[alarm]\ninterval = 20\n")
    sandboxed_machine.systemctl.calls.clear()

    code, _, _ = setup_lines(sandboxed_machine, sandbox, capsys)

    assert code == ExitCode.OK
    assert "OnUnitActiveSec=20min\n" in sandboxed_machine.unit_text("hal-alarm.timer")
    assert ["daemon-reload"] in sandboxed_machine.systemctl.changes


def test_hal_setup_with_a_wrong_alarm_table_stops_before_any_step(
    sandboxed_machine: Machine, sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    write_hal_config(sandbox.home, "[alarm]\ninterval = 0\n")

    code, _, errors = setup_lines(sandboxed_machine, sandbox, capsys)

    assert code == ExitCode.USAGE
    assert any("interval must be a whole number of at least 1" in line for line in errors)
    assert sandboxed_machine.systemctl.changes == []
