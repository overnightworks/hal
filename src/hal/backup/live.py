"""`hal restore <app> --live`: a DB-only Postgres app's snapshot loaded into its live database.

hal's door checks that the app is switched off and hands in the hold of the stop signals, the
switch re-check and whether a terminal is there. This step starts the app's database container
alone, never another one, and spawns the client only inside the hold, which it leaves only by
returning: an interrupt before the spawn is `Interrupted`, one after it leaves the outcome as it is.
"""

import argparse
from collections.abc import Callable
from contextlib import AbstractContextManager, ExitStack
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from hal.backup import docker, host, restic, runner
from hal.backup.apps import DB_FOLDER, App, PostgresDatabase
from hal.backup.cli import StepExit, apps_of, checked
from hal.backup.runner import MIN_SNAPSHOT_PREFIX, Interrupted, StepFailed
from hal.backup.settings import READINESS_POLL_SECONDS, Settings
from hal.backup.status import ExitCategory
from hal.backup.verify import DUMP_NAME
from hal.output import Glyph, Row, confirmed, format_moment, write_error, write_line, write_row
from hal.output.command import Verb, command

# The shell's own codes when it cannot run its command: not executable, not found.
_SHELL_CANNOT_START = frozenset({126, 127})


class LiveEvent(StrEnum):
    LOADED = "loaded"


@dataclass(frozen=True)
class Guards:
    """What only the door can read: the hold, whether the switch is still the one its guard
    read, and whether somebody can answer at a terminal."""

    hold: Callable[[], AbstractContextManager[None]]
    switch_unchanged: Callable[[], bool]
    at_terminal: bool


@dataclass
class _Client:
    """Whether the step spawned the client, and the exit it decided once it had: the one fact
    that tells an interrupt that loaded nothing from one that came after the load."""

    spawned: bool = False
    exit: StepExit | None = None


@dataclass(frozen=True)
class _Load:
    app: App
    database: PostgresDatabase
    container: str
    dump: Path
    snapshot: str
    taken: str  # the snapshot's time as the question showed it


def restore_live(settings: Settings, arguments: argparse.Namespace, guards: Guards) -> StepExit:
    client = _Client()
    try:
        with ExitStack() as staging:
            apps = apps_of(arguments.apps)
            app = runner.declared_app(apps, arguments.app)
            database = _database_only(app)
            container = _resolved(lambda: docker.only_database_container(app, database))
            if not guards.at_terminal:
                write_error("restore --live asks yes at a terminal · nothing changed")
                return StepExit.REFUSED
            load = _staged(settings, apps, app, database, container, arguments.snapshot, staging)
            if isinstance(load, StepExit):
                return load
            return _held(load, guards, staging, client)
    except KeyboardInterrupt as interrupt:
        if not client.spawned:
            raise Interrupted(arguments.app) from interrupt
        if client.exit is None:
            raise
        return client.exit


def _database_only(app: App) -> PostgresDatabase:
    match app.database:
        case PostgresDatabase(audio=None) as database:
            return database
        case _:
            raise StepFailed(
                ExitCategory.CONFIGURATION,
                f"{app.name} keeps audio or files; its live restore is manual: docs/backup.md",
            )


def _staged(
    settings: Settings,
    apps: tuple[App, ...],
    app: App,
    database: PostgresDatabase,
    container: str,
    snapshot_prefix: str | None,
    staging: ExitStack,
) -> _Load | StepExit:
    """The snapshot restored into a run-marked private directory, the yes, and the database up
    with no load of an earlier run still in it; nothing is loaded here."""
    runner.sweep_leftover_staging(settings.work_dir)
    runner.require_secret_and_repository(settings)
    snapshot = checked(runner.snapshot_to_restore, settings, apps, app, snapshot_prefix)
    taken = checked(restic.snapshot_time, settings, app.name, snapshot)
    restored = staging.enter_context(runner.private_directory(settings.work_dir))
    checked(restic.restore, settings, app.name, snapshot, restored)
    dump = restored / DB_FOLDER / DUMP_NAME
    if not dump.is_file():
        raise StepFailed(ExitCategory.VERIFICATION_FAILED, "the snapshot holds no database dump")
    shown = format_moment(taken, host.now())
    short = snapshot[:MIN_SNAPSHOT_PREFIX]
    if not confirmed(f"load snapshot {short} of {shown} into {app.name}'s live database"):
        write_error("aborted, nothing changed")
        return StepExit.DECLINED
    checked(docker.start_if_stopped, container)
    runner.wait_until_ready(
        lambda: docker.database_container(app, database),
        runner.Deadline.start(),
        READINESS_POLL_SECONDS,
    )
    if checked(docker.restore_sessions, container, database):
        write_error(
            f"{app.name}: a load is still running in {database.db_service} · nothing loaded"
        )
        return StepExit.REFUSED
    return _Load(app, database, container, dump, snapshot, shown)


def _held(load: _Load, guards: Guards, staging: ExitStack, client: _Client) -> StepExit:
    """The re-check of the switch, then the hold, and only inside it the client."""
    if not guards.switch_unchanged():
        write_error(f"{load.app.name}'s switch changed · nothing loaded")
        return StepExit.REFUSED
    with guards.hold():
        return _load(load, staging, client)


def _load(load: _Load, staging: ExitStack, client: _Client) -> StepExit:
    """Spawns the client, prints the outcome, removes the plaintext, then decides the exit."""
    client.spawned = True
    try:
        cause = _cause(docker.load_live(load.container, load.database, load.dump))
    except host.HostError as error:
        cause = str(error)
    app, short = load.app.name, load.snapshot[:MIN_SNAPSHOT_PREFIX]
    if cause is None:
        write_row(Row(Glyph.DONE, app, LiveEvent.LOADED, f"{short} · {load.taken}"))
        write_line(f"next: {command(Verb.START, app)}")
    else:
        write_error(
            f"{app} load failed · {cause} · a rerun loads the snapshot whole",
            command(Verb.RESTORE, app, "--live", "--snapshot", short),
        )
    outcome = StepExit.OK if cause is None else StepExit.FAILED
    staging.close()
    client.exit = outcome
    return outcome


def _cause(code: int | None) -> str | None:
    """Why the load failed by the code pg_restore printed; None when it loaded."""
    match code:
        case 0:
            return None
        case None:
            return "no exit code of pg_restore"
        case code if code in _SHELL_CANNOT_START:
            return "the shell could not start pg_restore"
        case code:
            return f"pg_restore ended with exit {code}"


def _resolved[T](probe: Callable[[], T]) -> T:
    try:
        return checked(probe)
    except docker.TargetError as error:
        raise StepFailed(ExitCategory.CONFIGURATION, str(error)) from error
