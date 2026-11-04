"""`hal restore <app> --live` (#974) on the scripted Docker host: the door's guard, the record
refusals, the question, the database started alone, the held signals and each ending of the
outcome table. `docker compose config` answers the checkout's compose.yaml as it is."""

import dataclasses
import os
import signal
from contextlib import ExitStack, contextmanager
from pathlib import Path

import pytest
import yaml
from support.backup_support import (
    DUMP,
    LIVE_ROW_VALUE_CANARY,
    declare_apps,
    declare_shipped_apps,
)
from support.terminal_support import type_at_prompt

from hal import backup_commands
from hal.backup import host, runner
from hal.backup import live as live_step
from hal.backup.docker import LIVE_LOAD_LABEL, SESSION_COUNT_LABEL
from hal.backup.runner import RUN_MARK_SUFFIX, STAGING_PREFIX, StepFailed
from hal.backup.settings import Settings
from hal.backup.status import ExitCategory
from hal.stack import compose, switches, terminal, unit_plans

APP = "litellm"
SERVICE = "litellm-db"
CONTAINER = ("hal", SERVICE)
COMPOSE_FILE = compose.REPOSITORY / "compose.yaml"


def squeezed(text: str) -> str:
    return "\n".join(" ".join(line.split()) for line in text.splitlines())


@pytest.fixture
def live(edge_backup, machine, home, monkeypatch, restored_signal_handlers):
    """A backup of the app taken, the unit switched off, a terminal where the operator types
    `yes`; `run` restores it live and returns the outcome."""
    resolved = yaml.safe_load(COMPOSE_FILE.read_text())
    monkeypatch.setattr(compose.Compose, "resolved_configuration", lambda _: resolved)
    monkeypatch.setattr(terminal, "at_terminal", lambda: True)
    assert edge_backup(*declare_shipped_apps(), "backup", APP).exit_code == 0
    switch_off(home)
    type_at_prompt(monkeypatch, "yes")

    def run(*options: str, apps: tuple[str, str] = declare_shipped_apps()):
        return edge_backup(*apps, "restore", APP, "--live", *options)

    return run


def switch_off(home: Path, unit: str = APP) -> Path:
    marker = home / ".local/state/edge/stopped" / unit
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("2026-11-04T10:00:00+01:00")
    return marker


def work_directory(home: Path) -> Path:
    return Settings.for_home(home, os.getuid(), os.getgid()).work_dir


def snapshot(machine) -> str:
    return machine.snapshots[-1]["id"][:8]


def live_loads_started(machine) -> bool:
    return LIVE_LOAD_LABEL in machine.labels()


def test_a_loaded_snapshot_starts_only_the_stopped_database_and_names_hal_start(
    live, machine, home
):
    machine.stopped_containers.add("hal-litellm-db")

    outcome = live()

    assert (outcome.exit_code, outcome.err) == (0, "")
    [row, next_line] = squeezed(outcome.out).splitlines()[-2:]
    assert row.split(": ")[-1].startswith(f"✓ {APP} loaded {snapshot(machine)} · ")
    assert next_line == f"next: hal start {APP}"
    assert machine.started_containers == ["hal-litellm-db"]
    assert machine.live_loads == [DUMP]
    assert machine.live_new_session == [True]
    assert LIVE_LOAD_LABEL not in machine.lock_free_during
    assert list(work_directory(home).iterdir()) == []


def test_a_running_database_is_left_as_it_is(live, machine):
    outcome = live()

    assert outcome.exit_code == 0
    assert machine.started_containers == []


def test_the_question_names_the_snapshot_and_the_app(live, machine):
    outcome = live()

    assert f"Type yes to load snapshot {snapshot(machine)} of " in outcome.out
    assert f"into {APP}'s live database: " in outcome.out


def test_a_named_snapshot_is_the_one_loaded_and_named(live, machine, edge_backup):
    first = machine.snapshots[-1]["id"]
    machine.snapshots[-1]["db"] = {"db.dump": DUMP + b" first"}
    assert edge_backup(*declare_shipped_apps(), "backup", APP).exit_code == 0

    outcome = live("--snapshot", first)

    assert outcome.exit_code == 0
    assert machine.live_loads == [DUMP + b" first"]


def test_a_unit_that_is_on_is_refused_before_anything_runs(live, machine, home):
    (home / ".local/state/edge/stopped" / APP).unlink()
    calls = len(machine.calls)

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (
        4,
        [f"error: stop it first: hal stop {APP}"],
    )
    assert machine.calls[calls:] == []


def test_a_unit_that_is_on_is_refused_before_the_host_lock_is_taken(live, monkeypatch, home):
    (home / ".local/state/edge/stopped" / APP).unlink()
    locked = []
    real_lock = host.exclusive_lock

    @contextmanager
    def watched(path):
        locked.append(path)
        with real_lock(path):
            yield

    monkeypatch.setattr(host, "exclusive_lock", watched)

    assert live().exit_code == 4
    assert locked == []


def test_a_guard_that_cannot_read_fails_with_its_error_as_the_line(live, monkeypatch):
    def unreadable(engine, repository):
        raise compose.ComposeError("the fleet cannot be read")

    monkeypatch.setattr(unit_plans, "read_fleet", unreadable)

    outcome = live()

    assert (outcome.exit_code, outcome.err) == (3, "error: the fleet cannot be read\n")


def test_a_disabled_unit_is_refused_before_anything_runs(live, machine, monkeypatch):
    read = unit_plans.read_fleet

    def disabled(engine, repository):
        fleet = read(engine, repository)
        units = tuple(dataclasses.replace(unit, enabled=unit.key != APP) for unit in fleet.units)
        return dataclasses.replace(fleet, units=units)

    monkeypatch.setattr(unit_plans, "read_fleet", disabled)
    calls = len(machine.calls)

    outcome = live()

    assert (outcome.exit_code, outcome.err) == (4, f"error: {APP} is disabled in the catalog\n")
    assert machine.calls[calls:] == []


def test_a_name_that_is_no_unit_is_refused_and_the_units_are_named(live, machine, edge_backup):
    calls = len(machine.calls)

    outcome = edge_backup(*declare_shipped_apps(), "restore", "nobody", "--live")

    assert outcome.exit_code == 4
    assert outcome.err.startswith("error: nobody is not a unit of fleet.yaml (units: ")
    assert APP in outcome.err
    assert machine.calls[calls:] == []


AUDIO_RECORD = f"""
[app.{APP}]
compose_project = "hal"
db_service = "{SERVICE}"
dump = "pg_dump_custom"
db_user = "litellm"
db_name = "litellm"
postgres_major = 17
volume = "audiofiles"
[app.{APP}.restore_test]
count_table = "LiteLLM_VerificationToken"
audio_reference_table = "generations"
audio_reference_column = "mp3_path"
"""
SQLITE_RECORD = f"""
[app.{APP}]
compose_project = "hal"
dump = "sqlite_online_copy"
database_volume = "database"
database_file = "litellm.sqlite3"
[app.{APP}.restore_test]
count_table = "users"
"""


@pytest.mark.parametrize("record", [AUDIO_RECORD, SQLITE_RECORD], ids=["audio", "sqlite"])
def test_a_record_with_files_is_refused_with_one_line_and_starts_nothing(
    live, machine, home, record
):
    calls = len(machine.calls)

    outcome = live(apps=declare_apps(home, record))

    assert outcome.exit_code == 3
    assert outcome.err.splitlines() == [
        f"error: {APP} keeps audio or files; its live restore is manual: docs/backup.md"
    ]
    assert machine.calls[calls:] == []


def test_two_database_containers_are_refused_with_one_line_naming_the_app_once(live, machine):
    machine.other_db_containers[CONTAINER] = ["one", "two"]

    outcome = live()

    assert outcome.exit_code == 3
    assert outcome.err.splitlines() == [
        f"error: 2 database containers for {APP} instead of exactly one"
    ]
    assert not live_loads_started(machine)


def test_a_failure_before_the_spawn_names_the_app_and_not_the_plain_restore(live, machine):
    machine.failing["restic restore"] = 1

    outcome = live()

    assert outcome.exit_code == 3
    assert outcome.err.splitlines() == [f"error: {APP}: restic restore ended with exit 1"]


def test_a_reason_holding_the_name_inside_another_word_still_names_the_app(live, monkeypatch):
    def failing_step(*_arguments, **_guards):
        raise StepFailed(ExitCategory.NOT_READY, f"{SERVICE} did not answer")

    monkeypatch.setattr(live_step, "restore_live", failing_step)

    outcome = live()

    assert outcome.exit_code == 3
    assert outcome.err.splitlines() == [f"error: {APP}: {SERVICE} did not answer"]


def test_without_a_terminal_it_refuses_and_restores_nothing(live, machine, monkeypatch, home):
    monkeypatch.setattr(terminal, "at_terminal", lambda: False)
    calls = len(machine.calls)

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (
        4,
        ["error: restore --live asks yes at a terminal · nothing changed"],
    )
    assert "restic restore" not in machine.labels()[calls:]


@pytest.mark.parametrize("answer", ["no", "", None, "YES"])
def test_anything_but_yes_aborts_and_starts_nothing(live, machine, monkeypatch, answer):
    machine.stopped_containers.add("hal-litellm-db")
    type_at_prompt(monkeypatch, answer)

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (1, ["error: aborted, nothing changed"])
    assert machine.started_containers == []
    assert not live_loads_started(machine)


def test_ctrl_c_at_the_question_loads_nothing(live, machine, monkeypatch, home):
    type_at_prompt(monkeypatch, KeyboardInterrupt)

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (
        130,
        ["error: interrupted · nothing loaded"],
    )
    assert not live_loads_started(machine)
    assert list(work_directory(home).iterdir()) == []


def test_a_snapshot_without_a_dump_is_refused_before_the_question(live, machine):
    machine.snapshots[-1]["db"] = {}

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (
        3,
        [f"error: {APP}: the snapshot holds no database dump"],
    )
    assert not live_loads_started(machine)


def test_a_load_still_running_is_refused(live, machine):
    machine.restore_sessions = 1

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (
        4,
        [f"error: {APP}: a load is still running in {SERVICE} · nothing loaded"],
    )
    assert not live_loads_started(machine)


def test_a_switch_changed_after_the_guard_is_refused(live, machine, monkeypatch, home):
    def stop_again():
        marker = switch_off(home)
        marker.unlink()
        switch_off(home)

    type_at_prompt(monkeypatch, "yes", while_waiting=stop_again)

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (
        4,
        [f"error: {APP}'s switch changed · nothing loaded"],
    )
    assert not live_loads_started(machine)


def test_a_switch_that_cannot_be_read_at_the_recheck_is_refused_as_changed(
    live, machine, monkeypatch
):
    def unreadable(self, unit, read):
        raise switches.SwitchError("the switch cannot be read")

    monkeypatch.setattr(switches.Switches, "changed", unreadable)

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (
        4,
        [f"error: {APP}'s switch changed · nothing loaded"],
    )
    assert not live_loads_started(machine)


@pytest.mark.parametrize(
    ("code", "client_exit", "cause"),
    [
        (1, 0, "pg_restore ended with exit 1"),
        (127, 0, "the shell could not start pg_restore"),
        (None, 0, "no exit code of pg_restore"),
        (0, 1, "live load ended with exit 1"),
    ],
    ids=["code 1", "code 127", "no code line", "failed client"],
)
def test_a_failed_load_names_its_cause_and_the_rerun_of_its_snapshot(
    live, machine, home, code, client_exit, cause
):
    machine.live_code, machine.live_client_exit = code, client_exit

    outcome = live()

    assert outcome.exit_code == 3
    assert outcome.err.splitlines() == [
        f"error: {APP} load failed · {cause} · a rerun loads the snapshot whole",
        f"next: hal restore {APP} --live --snapshot {snapshot(machine)}",
    ]
    assert "loaded" not in outcome.out
    assert list(work_directory(home).iterdir()) == []


@pytest.mark.parametrize("number", [signal.SIGINT, signal.SIGTERM], ids=["SIGINT", "SIGTERM"])
def test_a_signal_during_the_load_waits_for_its_real_outcome(live, machine, number):
    machine.during_live_load = lambda: os.kill(os.getpid(), number)

    outcome = live()

    assert (outcome.exit_code, outcome.err) == (0, "")
    assert f"✓ {APP} loaded" in squeezed(outcome.out)


def test_a_signal_during_a_failed_load_keeps_the_failure(live, machine):
    machine.live_code = 1
    machine.during_live_load = lambda: os.kill(os.getpid(), signal.SIGINT)

    outcome = live()

    assert outcome.exit_code == 3
    assert outcome.err.splitlines()[0].startswith(f"error: {APP} load failed")


@contextmanager
def _raising_at_release():
    yield
    raise KeyboardInterrupt


@contextmanager
def _raising_at_entry():
    raise KeyboardInterrupt
    yield  # pragma: no cover - the generator form of a context manager


def test_an_interrupt_at_the_holds_release_leaves_the_outcome_line_and_its_exit(
    live, machine, monkeypatch
):
    monkeypatch.setattr(backup_commands, "signals_ignored", _raising_at_release)

    outcome = live()

    assert (outcome.exit_code, outcome.err) == (0, "")
    assert squeezed(outcome.out).splitlines()[-1] == f"next: hal start {APP}"


def test_an_interrupt_at_the_holds_entry_spawns_no_client(live, machine, monkeypatch):
    monkeypatch.setattr(backup_commands, "signals_ignored", _raising_at_entry)

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (
        130,
        ["error: interrupted · nothing loaded"],
    )
    assert not live_loads_started(machine)


def test_the_hold_is_entered_before_the_client_is_spawned(live, machine, monkeypatch):
    entered = []

    @contextmanager
    def watched():
        entered.append(len(machine.calls))
        yield

    monkeypatch.setattr(backup_commands, "signals_ignored", watched)

    live()

    assert machine.labels()[entered[0] :] == [LIVE_LOAD_LABEL]
    assert SESSION_COUNT_LABEL in machine.labels()[: entered[0]]


@pytest.mark.parametrize(
    ("where", "exit_code", "lines"),
    [
        ("while waiting", 130, ["error: interrupted"]),
        ("at the release", 0, []),
    ],
)
def test_an_interrupt_at_the_host_lock_claims_nothing_or_keeps_the_outcome(
    live, machine, monkeypatch, where, exit_code, lines
):
    real_lock = host.exclusive_lock

    @contextmanager
    def interrupted_lock(path):
        if where == "while waiting":
            raise KeyboardInterrupt
        with real_lock(path):
            yield
        raise KeyboardInterrupt

    monkeypatch.setattr(host, "exclusive_lock", interrupted_lock)

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (exit_code, lines)


@pytest.mark.parametrize("code", [0, 1], ids=["loaded", "failed load"])
@pytest.mark.parametrize("where", ["after the step returned", "at the exit of the staging"])
def test_an_interrupt_after_the_client_was_spawned_never_says_nothing_loaded(
    live, machine, monkeypatch, where, code
):
    machine.live_code = code
    if where == "after the step returned":
        real_held = live_step._held

        def held_then_interrupted(*arguments):
            real_held(*arguments)
            raise KeyboardInterrupt

        monkeypatch.setattr(live_step, "_held", held_then_interrupted)
    else:

        class InterruptedAtExit(ExitStack):
            """Interrupts the leaving of the with block, after the step's own close ran."""

            def __exit__(self, *exception):
                was_closed = not self._exit_callbacks
                super().__exit__(*exception)
                if was_closed:
                    raise KeyboardInterrupt

        monkeypatch.setattr(live_step, "ExitStack", InterruptedAtExit)

    outcome = live()

    assert "nothing loaded" not in outcome.err
    if code == 0:
        assert f"✓ {APP} loaded" in squeezed(outcome.out)
        assert (outcome.exit_code, outcome.err) == (0, "")
    else:
        assert f"{APP} load failed" in outcome.err
        assert outcome.exit_code == 3


def test_an_interrupt_in_the_client_itself_is_plain_and_never_says_nothing_loaded(
    live, machine, monkeypatch
):
    def interrupted(*_):
        raise KeyboardInterrupt

    monkeypatch.setattr(live_step.docker, "load_live", interrupted)

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (130, ["error: interrupted"])


@pytest.mark.parametrize("code", [0, 1], ids=["loaded", "failed load"])
def test_a_signal_during_the_removal_of_the_directory_leaves_the_outcome_as_it_is(
    live, machine, home, monkeypatch, code
):
    machine.live_code = code
    quiet = live()
    assert quiet.exit_code == (0 if code == 0 else 3)
    real_removal = runner._remove_staging

    def signalled_removal(mark):
        os.kill(os.getpid(), signal.SIGINT)
        real_removal(mark)

    monkeypatch.setattr(runner, "_remove_staging", signalled_removal)
    type_at_prompt(monkeypatch, "yes")

    outcome = live()

    assert (outcome.exit_code, outcome.err) == (quiet.exit_code, quiet.err)
    assert squeezed(outcome.out).splitlines()[-2:] == squeezed(quiet.out).splitlines()[-2:]
    assert list(work_directory(home).iterdir()) == []


def test_an_interrupt_while_the_container_is_discovered_loads_nothing(live, machine, home):
    machine.failing["docker ps"] = KeyboardInterrupt

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (
        130,
        ["error: interrupted · nothing loaded"],
    )
    assert not live_loads_started(machine)


@pytest.mark.parametrize("code", [0, 1], ids=["loaded", "failed load"])
def test_no_row_value_of_the_restored_tables_reaches_the_output(live, machine, code):
    machine.live_code = code

    outcome = live()

    assert LIVE_ROW_VALUE_CANARY not in outcome.out + outcome.err
    assert machine.live_loads == [DUMP]


def test_a_killed_runs_plaintext_is_swept_by_the_next_run(live, home):
    work = work_directory(home)
    left = work / f"{STAGING_PREFIX}killed"
    left.mkdir(parents=True)
    (left / "db.dump").write_bytes(DUMP)
    left.with_name(left.name + RUN_MARK_SUFFIX).touch()

    assert live().exit_code == 0
    assert list(work.iterdir()) == []
