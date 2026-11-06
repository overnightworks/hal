"""`hal restore <app> --live`: a DB-only app's snapshot loaded into its live database.

hal's door checks that the app is switched off and hands in the hold of the stop signals, the
switch lock, the switch re-check and whether a terminal is there. A Postgres app's database
container is started alone, never another one; a SQLite app's verified copy is written into its
live file through SQLite's backup API by the file's owner. The step takes the switch lock, so no
start comes in between, re-checks the switch under it, proves for SQLite that no container uses
the volume, and spawns the client only inside the hold, which it leaves only by returning: an
interrupt before the spawn is `Interrupted`, one after it leaves the outcome as it is.
"""

import argparse
from collections.abc import Callable
from contextlib import AbstractContextManager, ExitStack
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from hal.backup import docker, host, restic, runner
from hal.backup.apps import DB_FOLDER, App, PostgresDatabase, SqliteDatabase
from hal.backup.cli import StepExit, apps_of, checked
from hal.backup.runner import MIN_SNAPSHOT_PREFIX, Interrupted, StepFailed
from hal.backup.settings import READINESS_POLL_SECONDS, Settings
from hal.backup.sqlite_copy import LoadExit
from hal.backup.status import ExitCategory
from hal.backup.verify import DUMP_NAME, VerificationError
from hal.output import Glyph, Row, confirmed, format_moment, write_error, write_line, write_row
from hal.output.command import Verb, command

# The shell's own codes when it cannot run its command: not executable, not found.
_SHELL_CANNOT_START = frozenset({126, 127})
# Why the loader refused before its copy began; the live content is unchanged.
_REFUSALS = {
    LoadExit.REFUSED: "the copy or the live file does not fit",
    LoadExit.BUSY: "another connection holds the live database",
}
# Why a copy that began did not end as loaded.
_UNFINISHED = {
    LoadExit.UNFINISHED: "the copy did not finish",
    LoadExit.UNCHECKED: "the check after the copy failed",
}


class LiveEvent(StrEnum):
    LOADED = "loaded"


@dataclass(frozen=True)
class Guards:
    """What only the door can read: the hold, the switch lock that every start and stop takes,
    whether the switch is still the one its guard read, and whether somebody can answer at a
    terminal."""

    hold: Callable[[], AbstractContextManager[None]]
    switch_lock: Callable[[], AbstractContextManager[None]]
    switch_unchanged: Callable[[], bool]
    at_terminal: bool


@dataclass
class _Client:
    """Whether the step spawned the client, and the exit it decided once it had: the one fact
    that tells an interrupt that loaded nothing from one that came after the load."""

    spawned: bool = False
    exit: StepExit | None = None


@dataclass(frozen=True)
class _PostgresTarget:
    database: PostgresDatabase
    container: str


@dataclass(frozen=True)
class _SqliteTarget:
    database: SqliteDatabase
    volume: str
    owner: str  # `uid:gid` of the live file


@dataclass(frozen=True)
class _PostgresDump:
    target: _PostgresTarget
    file: Path


@dataclass(frozen=True)
class _SqliteCopy:
    target: _SqliteTarget
    file: Path
    rows: int  # the rows its verification counted


@dataclass(frozen=True)
class _Load:
    settings: Settings
    app: App
    staged: _PostgresDump | _SqliteCopy
    snapshot: str
    taken: str  # the snapshot's time as the question showed it


@dataclass(frozen=True)
class _Failure:
    line: str
    exit: StepExit


def restore_live(settings: Settings, arguments: argparse.Namespace, guards: Guards) -> StepExit:
    client = _Client()
    try:
        with ExitStack() as staging:
            apps = apps_of(arguments.apps)
            app = runner.declared_app(apps, arguments.app)
            target = _target(settings, app)
            if not guards.at_terminal:
                write_error("restore --live asks yes at a terminal · nothing changed")
                return StepExit.REFUSED
            load = _staged(settings, apps, app, target, arguments.snapshot, staging)
            if isinstance(load, StepExit):
                return load
            return _held(load, guards, staging, client)
    except KeyboardInterrupt as interrupt:
        if not client.spawned:
            raise Interrupted(arguments.app) from interrupt
        if client.exit is None:
            raise
        return client.exit


def _target(settings: Settings, app: App) -> _PostgresTarget | _SqliteTarget:
    """What the load goes into; a record that keeps audio is refused."""
    match app.database:
        case PostgresDatabase(audio=None) as database:
            return _PostgresTarget(
                database, _resolved(lambda: docker.only_database_container(app, database))
            )
        case SqliteDatabase() as database:
            volume = _resolved(lambda: docker.app_volume(app, database.volume))
            owner = _resolved(lambda: docker.database_owner(settings, volume, database.file))
            return _SqliteTarget(database, volume, owner)
        case _:
            raise StepFailed(
                ExitCategory.CONFIGURATION,
                f"{app.name} keeps audio; its live restore is manual: docs/backup.md",
            )


def _staged(
    settings: Settings,
    apps: tuple[App, ...],
    app: App,
    target: _PostgresTarget | _SqliteTarget,
    snapshot_prefix: str | None,
    staging: ExitStack,
) -> _Load | StepExit:
    """The snapshot restored into a run-marked private directory and verified, the yes, and a
    Postgres database up with no load of an earlier run still in it; nothing is loaded here."""
    runner.sweep_leftover_staging(settings.work_dir)
    runner.require_secret_and_repository(settings)
    snapshot = checked(runner.snapshot_to_restore, settings, apps, app, snapshot_prefix)
    taken = checked(restic.snapshot_time, settings, app.name, snapshot)
    restored = staging.enter_context(runner.private_directory(settings.work_dir))
    checked(restic.restore, settings, app.name, snapshot, restored)
    staged = _verified(settings, app, target, restored)
    shown = format_moment(taken, host.now())
    short = snapshot[:MIN_SNAPSHOT_PREFIX]
    if not confirmed(f"load snapshot {short} of {shown} into {app.name}'s live database"):
        write_error("aborted, nothing changed")
        return StepExit.DECLINED
    if isinstance(target, _PostgresTarget) and _earlier_load_running(app, target):
        return StepExit.REFUSED
    return _Load(settings, app, staged, snapshot, shown)


def _verified(
    settings: Settings, app: App, target: _PostgresTarget | _SqliteTarget, restored: Path
) -> _PostgresDump | _SqliteCopy:
    """The staged dump, or the SQLite copy with the rows it holds."""
    if isinstance(target, _PostgresTarget):
        dump = restored / DB_FOLDER / DUMP_NAME
        if not dump.is_file():
            raise StepFailed(
                ExitCategory.VERIFICATION_FAILED, "the snapshot holds no database dump"
            )
        return _PostgresDump(target, dump)
    try:
        copy, rows = checked(runner.verified_sqlite_copy, settings, app, restored)
    except VerificationError as error:
        raise StepFailed(ExitCategory.VERIFICATION_FAILED, str(error)) from error
    return _SqliteCopy(target, copy, rows)


def _earlier_load_running(app: App, target: _PostgresTarget) -> bool:
    """The database container, started if it is stopped: whether a killed run's load is still in
    it, said in its own line."""
    checked(docker.start_if_stopped, target.container)
    runner.wait_until_ready(
        lambda: docker.database_container(app, target.database),
        runner.Deadline.start(),
        READINESS_POLL_SECONDS,
    )
    if not checked(docker.restore_sessions, target.container, target.database):
        return False
    write_error(
        f"{app.name}: a load is still running in {target.database.db_service} · nothing loaded"
    )
    return True


def _held(load: _Load, guards: Guards, staging: ExitStack, client: _Client) -> StepExit:
    """Under the switch lock to the end of the load: the re-check of the switch, the proof that
    no container uses a SQLite volume, then the hold, and only inside it the client."""
    with guards.switch_lock():
        if not guards.switch_unchanged():
            write_error(f"{load.app.name}'s switch changed · nothing loaded")
            return StepExit.REFUSED
        if isinstance(load.staged, _SqliteCopy) and checked(
            docker.volume_users, load.staged.target.volume
        ):
            write_error(
                f"a container still uses {load.app.name}'s database · nothing loaded",
                f"{command(Verb.STOP, load.app.name)}, or wait for an earlier load to end; "
                "then rerun",
            )
            return StepExit.REFUSED
        with guards.hold():
            return _load(load, staging, client)


def _load(load: _Load, staging: ExitStack, client: _Client) -> StepExit:
    """Spawns the client, prints the outcome, removes the plaintext, then decides the exit."""
    client.spawned = True
    match load.staged:
        case _PostgresDump() as dump:
            failure = _postgres_failure(load, dump)
        case _SqliteCopy() as copy:
            failure = _sqlite_failure(load, copy)
    app, short = load.app.name, load.snapshot[:MIN_SNAPSHOT_PREFIX]
    if failure is None:
        write_row(Row(Glyph.DONE, app, LiveEvent.LOADED, f"{short} · {load.taken}"))
        write_line(f"next: {command(Verb.START, app)}")
    else:
        write_error(failure.line, command(Verb.RESTORE, app, "--live", "--snapshot", short))
    outcome = StepExit.OK if failure is None else failure.exit
    staging.close()
    client.exit = outcome
    return outcome


def _postgres_failure(load: _Load, dump: _PostgresDump) -> _Failure | None:
    target = dump.target
    try:
        cause = _cause(docker.load_live(target.container, target.database, dump.file))
    except host.HostError as error:
        cause = str(error)
    if cause is None:
        return None
    return _Failure(
        f"{load.app.name} load failed · {cause} · a rerun loads the snapshot whole",
        StepExit.FAILED,
    )


def _sqlite_failure(load: _Load, copy: _SqliteCopy) -> _Failure | None:
    """Only the loader's own refusal says nothing changed; any other end may have loaded."""
    app, target = load.app.name, copy.target
    try:
        rows = docker.load_sqlite(
            load.settings,
            target.volume,
            target.database,
            target.owner,
            copy.file,
            load.app.restore_test.count_table,
        )
    except host.HostError as error:
        code = error.exit_code if isinstance(error, host.HostCommandError) else None
        if code in _REFUSALS:
            refusal = _REFUSALS[LoadExit(code)]
            return _Failure(f"{app} load refused · {refusal} · nothing changed", StepExit.REFUSED)
        cause = _UNFINISHED[LoadExit(code)] if code in _UNFINISHED else str(error)
    else:
        if rows == copy.rows:
            return None
        cause = "the loaded database counts other rows than the snapshot"
    return _Failure(
        f"{app} load failed · {cause} · it holds the old or the new database · "
        "a rerun loads the snapshot whole",
        StepExit.FAILED,
    )


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
