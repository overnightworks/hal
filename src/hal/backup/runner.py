"""The weekly backup and the monthly restore test, phase by phase, each phase in the status.

A run counts as success only after its last phase; every failure names its phase.
"""

import shutil
import stat
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import Self

from hal.backup import docker, host, restic
from hal.backup.apps import DB_FOLDER, App, PostgresDatabase, SqliteDatabase
from hal.backup.restic import KeptVolume, MountKind
from hal.backup.settings import (
    READINESS_POLL_SECONDS,
    READINESS_TIMEOUT,
    RESTORE_IMAGES,
    RESTORE_SERVER_POLL_SECONDS,
    RESTORE_SERVER_TIMEOUT,
    Settings,
)
from hal.backup.status import (
    ExitCategory,
    Phase,
    Status,
    StatusFileError,
    read_status,
    write_status,
)
from hal.backup.verify import (
    DUMP_NAME,
    MANIFEST_NAME,
    SQLITE_COPY_NAME,
    Manifest,
    VerificationError,
    check_audio_references,
    check_file_count,
    check_row_count,
    check_rows,
)
from hal.output import Field, Glyph, Row
from hal.output.command import Verb, command

# A run stages in `staging-<random>` and first creates `staging-<random>.run` beside it: that
# mark, not the name, proves the directory is a run's own, so a sweep removes only what runs made.
STAGING_PREFIX = "staging-"
RUN_MARK_SUFFIX = ".run"
# restic's own short ID length, as `hal restore --list` lists it.
MIN_SNAPSHOT_PREFIX = 8


class BackupEvent(StrEnum):
    BACKED_UP = "backed up"
    NOT_BACKED_UP = "not backed up"
    PRUNED = "pruned"
    NOT_PRUNED = "not pruned"


class RestoreEvent(StrEnum):
    PROVEN = "restore proven"
    NOT_PROVEN = "not proven"
    CHECKED = "checked"
    NOT_CHECKED = "not checked"


REPOSITORY = "repository"


class StepFailed(Exception):
    """A handled failure: the run is over and the status says `failed`. `error_line` and
    `next_step` are what the door prints instead of the message and its default, once the run
    has more to say than the first failure."""

    def __init__(self, category: ExitCategory, message: str, *, shared: bool = False) -> None:
        self.category = category
        self.shared = shared
        self.app: str | None = None
        self.phase: Phase | None = None
        self.error_line: str | None = None
        self.next_step: str | None = None
        super().__init__(message)


class Interrupted(Exception):
    """Ctrl-C or SIGTERM, with the app the run was working on, if any."""

    def __init__(self, app: str | None) -> None:
        self.app = app
        super().__init__()


class Run:
    """The status file as this run's journal: every phase change is written at once."""

    def __init__(self, path: Path, status: Status) -> None:
        self._path = path
        self._status = status
        self._first_app_failure: StepFailed | None = None
        self.interrupted_app: str | None = None
        self.backed_up_apps = 0
        self.proven_apps = 0
        self.failed_apps: list[str] = []
        write_status(path, status)

    @contextmanager
    def phase(
        self, phase: Phase, failing: ExitCategory = ExitCategory.COMMAND_FAILED
    ) -> Iterator[None]:
        self._record(self._status.entering(phase))
        try:
            yield
        except host.HostError as error:
            raise StepFailed(
                failing,
                f"{phase}: {error}",
                shared=isinstance(error, restic.RepositoryUnusableError),
            ) from error
        except VerificationError as error:
            raise StepFailed(ExitCategory.VERIFICATION_FAILED, f"{phase}: {error}") from error

    @contextmanager
    def isolated(
        self, app: str, on_failure: Callable[[StepFailed], None] = lambda _: None
    ) -> Iterator[None]:
        """One app's failure is kept for the verdict while the other apps go on."""
        try:
            yield
        except KeyboardInterrupt:
            self.interrupted_app = app
            raise
        except StepFailed as failure:
            if failure.shared:
                raise
            failure.app, failure.phase = app, self._status.phase
            self._first_app_failure = self._first_app_failure or failure
            self.failed_apps.append(app)
            on_failure(failure)

    @property
    def first_app_failure(self) -> StepFailed | None:
        return self._first_app_failure

    def raise_first_app_failure(self) -> None:
        if self._first_app_failure is not None:
            raise self._first_app_failure

    def snapshot_of(self, app: str) -> str | None:
        return self._status.snapshot_of(app)

    def last_backup_of(self, app: str) -> datetime | None:
        return self._status.last_backup_of(app)

    def attribute_legacy_evidence(self, settings: Settings, apps: tuple[App, ...]) -> None:
        attributed = attributed_status(settings, self._status, apps)
        if attributed is not self._status:
            self._record(attributed)

    def backed_up(self, app: str, snapshot_id: str) -> None:
        self.backed_up_apps += 1
        self._record(self._status.backed_up(app, host.now(), snapshot_id))

    def restore_tested(self, apps: list[str]) -> None:
        self._record(self._status.restore_tested(host.now(), apps))

    def succeeded(self) -> None:
        self._record(self._status.succeeded())

    def failed(
        self, category: ExitCategory, app: str | None = None, phase: Phase | None = None
    ) -> None:
        self._record(self._status.failed(category, app, phase))

    def _record(self, status: Status) -> None:
        self._status = status
        write_status(self._path, status)


def require_secret_and_repository(settings: Settings) -> None:
    require_password_file(settings)
    if not (settings.repository / "config").is_file():
        raise StepFailed(
            ExitCategory.CONFIGURATION,
            "the restic repository is not initialised (docs/backup.md: Setup)",
        )


def require_password_file(settings: Settings) -> None:
    """The file is only stat-ed here; its content never passes through this process."""
    try:
        mode = settings.password_file.stat().st_mode
    except FileNotFoundError:
        raise StepFailed(
            ExitCategory.CONFIGURATION, "the password file is missing (docs/backup.md: Setup)"
        ) from None
    if not stat.S_ISREG(mode) or stat.S_IMODE(mode) & 0o077:
        raise StepFailed(
            ExitCategory.CONFIGURATION, "the password file must be a regular file with mode 600"
        )


@dataclass(frozen=True)
class _Deadline:
    """One waiting budget that several consecutive waits draw from."""

    timeout: timedelta
    expires_at: float

    @classmethod
    def start(cls, timeout: timedelta = READINESS_TIMEOUT) -> Self:
        return cls(timeout, host.monotonic() + timeout.total_seconds())


def backup(
    settings: Settings,
    apps: tuple[App, ...],
    run: Run,
    *,
    only: str | None = None,
    pre_apply: bool = False,
    report: Callable[[Row], None] = lambda _: None,
) -> None:
    """Every declared app, or `only` that one; `pre_apply` tags its snapshot and thins those.
    `report` gets a row as each app ends and for the repository."""
    targets = _targets(apps, only)
    with run.phase(Phase.PREPARE, failing=ExitCategory.CONFIGURATION):
        require_secret_and_repository(settings)
    first_readiness = _Deadline.start(READINESS_TIMEOUT)
    _require_docker_with_pinned_images(run, targets, first_readiness)
    with run.phase(Phase.PREPARE):
        run.attribute_legacy_evidence(settings, apps)
    for index, app in enumerate(targets):
        with run.isolated(app.name, partial(_report_not_backed_up, report, app)):
            started = host.monotonic()
            summary = _back_up(
                settings,
                app,
                run,
                first_readiness if index == 0 else _Deadline.start(),
                pre_apply=pre_apply,
            )
            report(_backed_up_row(app, summary, started))
    _forget_and_check(settings, targets, run, pre_apply=pre_apply, report=report)
    run.raise_first_app_failure()


def _forget_and_check(
    settings: Settings,
    targets: tuple[App, ...],
    run: Run,
    *,
    pre_apply: bool,
    report: Callable[[Row], None],
) -> None:
    """Forgets each app that backed up and checks the repository, whatever another app did.

    A failed app is not forgotten, so a partial snapshot of it never displaces its last good one.
    A forget or check failure is the run's verdict, also after an app failure.
    """
    failed = set(run.failed_apps)
    for app in run.failed_apps:
        report(
            Row(
                Glyph.UNCHANGED,
                app,
                BackupEvent.NOT_PRUNED,
                fields=((Field.REASON, "its backup failed"),),
            )
        )
    if not (backed_up := [app for app in targets if app.name not in failed]):
        return
    started = host.monotonic()
    with _repository_row_on_failure(report, BackupEvent.NOT_PRUNED):
        for app in backed_up:
            with run.phase(Phase.FORGET):
                restic.forget(settings, app.name, pre_apply=pre_apply)
    with _repository_row_on_failure(report, RestoreEvent.NOT_CHECKED), run.phase(Phase.CHECK):
        restic.check(settings, read_data=False)
    report(
        Row(
            Glyph.DONE,
            REPOSITORY,
            BackupEvent.PRUNED,
            "checked",
            fields=((Field.SECONDS, host.monotonic() - started),),
        )
    )


@contextmanager
def _repository_row_on_failure(
    report: Callable[[Row], None], event: BackupEvent | RestoreEvent
) -> Iterator[None]:
    """A repository step that fails says so in a row; an unusable repository ends the run with
    the rows printed so far."""
    try:
        yield
    except StepFailed as failure:
        if not failure.shared:
            report(Row(Glyph.FAILED, REPOSITORY, event, fields=((Field.REASON, str(failure)),)))
        raise


def _backed_up_row(app: App, summary: restic.BackupSummary, started: float) -> Row:
    fields = (
        (Field.SNAPSHOT, summary.snapshot_id[:8]),
        (Field.BYTES, summary.source_bytes),
        (Field.SECONDS, host.monotonic() - started),
    )
    return Row(Glyph.DONE, app.name, BackupEvent.BACKED_UP, fields=fields)


def _report_not_backed_up(report: Callable[[Row], None], app: App, failure: StepFailed) -> None:
    report(
        Row(
            Glyph.FAILED,
            app.name,
            BackupEvent.NOT_BACKED_UP,
            fields=((Field.REASON, str(failure)),),
        )
    )


def _report_not_proven(report: Callable[[Row], None], app: App, failure: StepFailed) -> None:
    report(
        Row(Glyph.FAILED, app.name, RestoreEvent.NOT_PROVEN, fields=((Field.REASON, str(failure)),))
    )


def restore_test(
    settings: Settings,
    apps: tuple[App, ...],
    run: Run,
    *,
    only: str | None = None,
    snapshot_prefix: str | None = None,
    report: Callable[[Row], None] = lambda _: None,
) -> None:
    """Every declared app, or `only` that one, which skips the data-reading check. With
    `snapshot_prefix` (one app only) it tests that snapshot instead of the last successful one.
    `report` gets a row as each app ends and for the repository."""
    targets = _targets(apps, only)
    with run.phase(Phase.PREPARE, failing=ExitCategory.CONFIGURATION):
        require_secret_and_repository(settings)
    _require_docker_with_pinned_images(run, targets, _Deadline.start())
    with run.phase(Phase.PREPARE):
        run.attribute_legacy_evidence(settings, apps)
    verified = []
    for app in targets:
        with run.isolated(app.name, partial(_report_not_proven, report, app)):
            snapshot_id = _restore_test(settings, app, run, snapshot_prefix)
            verified.append(app.name)
            run.proven_apps += 1
            report(
                Row(
                    Glyph.DONE,
                    app.name,
                    RestoreEvent.PROVEN,
                    fields=((Field.SNAPSHOT, snapshot_id[:8]),),
                )
            )
    try:
        with run.phase(Phase.CHECK):
            restic.check(settings, read_data=only is None)
    except StepFailed as failure:
        report(
            Row(
                Glyph.FAILED,
                REPOSITORY,
                RestoreEvent.NOT_CHECKED,
                fields=((Field.REASON, str(failure)),),
            )
        )
        raise
    report(Row(Glyph.DONE, REPOSITORY, RestoreEvent.CHECKED))
    run.restore_tested(verified)
    run.raise_first_app_failure()


def declared_app(apps: tuple[App, ...], name: str) -> App:
    if (app := {app.name: app for app in apps}.get(name)) is None:
        raise StepFailed(ExitCategory.CONFIGURATION, f"{name} is not declared")
    return app


def _targets(apps: tuple[App, ...], only: str | None) -> tuple[App, ...]:
    return apps if only is None else (declared_app(apps, only),)


def _require_docker_with_pinned_images(
    run: Run, apps: tuple[App, ...], readiness: _Deadline
) -> None:
    """A daemon that is still starting is waited for; only then are missing images pulled."""
    with run.phase(Phase.READINESS):
        _wait_until_ready(docker.require_daemon, readiness, READINESS_POLL_SECONDS)
    with run.phase(Phase.PREPARE, failing=ExitCategory.CONFIGURATION):
        _resolved(lambda: docker.ensure_pinned_images(apps))


def previous_status(settings: Settings) -> Status | None:
    """The file holds the only record of past successes: unreadable, it is left untouched."""
    try:
        return read_status(settings.status_file)
    except StatusFileError as error:
        raise StepFailed(
            ExitCategory.CONFIGURATION, f"{error}; the file stays unchanged"
        ) from error


def attributed_status(settings: Settings, status: Status, apps: tuple[App, ...]) -> Status:
    """Legacy evidence belongs to the one declared app only if restic knows its snapshot there."""
    legacy = status.unattributed
    if legacy is None or legacy.last_snapshot_id is None or len(apps) != 1:
        return status
    [app] = apps
    if app.name in status.apps or not restic.has_snapshot(
        settings, app.name, legacy.last_snapshot_id
    ):
        return status
    return status.attributed_to(app.name)


def restore(
    settings: Settings,
    apps: tuple[App, ...],
    app: App,
    target: Path,
    snapshot_prefix: str | None,
) -> str:
    """The operator's restore into a new private directory: the last successful backup's snapshot,
    or the one of this app that the operator names.

    Never inside the work directory: the operator's plaintext stays out of what runs own and sweep.
    """
    if target.resolve().is_relative_to(settings.work_dir.resolve()):
        raise StepFailed(
            ExitCategory.CONFIGURATION,
            "the target is inside the work directory (~/.cache/edge-backup)",
        )
    if target.exists():
        raise StepFailed(ExitCategory.CONFIGURATION, "the target already exists")
    require_secret_and_repository(settings)
    snapshot_id = (
        _last_successful_snapshot(settings, app, _recorded_snapshot(settings, apps, app))
        if snapshot_prefix is None
        else _chosen_snapshot(settings, app, snapshot_prefix)
    )
    target.mkdir(mode=0o700, parents=True)
    restic.restore(settings, app.name, snapshot_id, target)
    return snapshot_id


@dataclass(frozen=True)
class _PostgresTarget:
    database: PostgresDatabase
    container: str
    kept: KeptVolume | None


@dataclass(frozen=True)
class _SqliteTarget:
    database: SqliteDatabase
    volume: str
    kept: KeptVolume | None


def _ready_target(app: App, readiness: _Deadline) -> _PostgresTarget | _SqliteTarget:
    match app.database:
        case PostgresDatabase(audio=audio) as database:
            return _PostgresTarget(
                database,
                _wait_until_ready(
                    lambda: docker.database_container(app, database),
                    readiness,
                    READINESS_POLL_SECONDS,
                ),
                _kept_volume(app, restic.AUDIO_FOLDER, audio.volume, None) if audio else None,
            )
        case SqliteDatabase(volume=volume, files=files) as database:
            return _SqliteTarget(
                database,
                _resolved(lambda: docker.app_volume(app, volume)),
                _kept_volume(app, files.volume, files.volume, files.skip) if files else None,
            )


def _kept_volume(app: App, folder: str, volume: str, skip: str | None) -> KeptVolume:
    return KeptVolume(folder, _resolved(lambda: docker.app_volume(app, volume)), skip)


def _back_up(
    settings: Settings, app: App, run: Run, readiness: _Deadline, *, pre_apply: bool
) -> restic.BackupSummary:
    with run.phase(Phase.READINESS):
        target = _ready_target(app, readiness)
    with _private_directory(settings.work_dir) as staging:
        with run.phase(Phase.DUMP):
            _dump(settings, target, staging)
        with run.phase(Phase.MANIFEST):
            manifest = _manifest(settings, app, target, staging)
            _write_private(staging / MANIFEST_NAME, manifest.as_json())
        with run.phase(Phase.BACKUP):
            summary = restic.backup(settings, app.name, staging, target.kept, pre_apply=pre_apply)
            run.backed_up(app.name, summary.snapshot_id)
    return summary


def _dump(settings: Settings, target: _PostgresTarget | _SqliteTarget, staging: Path) -> None:
    match target:
        case _PostgresTarget(database=database, container=container):
            docker.dump_database(database, container, staging / DUMP_NAME)
        case _SqliteTarget(database=database, volume=volume):
            _resolved(
                lambda: docker.copy_sqlite(settings, volume, database, staging / SQLITE_COPY_NAME)
            )


def _manifest(
    settings: Settings, app: App, target: _PostgresTarget | _SqliteTarget, staging: Path
) -> Manifest:
    match target:
        case _PostgresTarget(kept=None):
            return Manifest(app.name, None)
        case _PostgresTarget(kept=kept):
            return Manifest(app.name, _count_kept(settings, kept))
        case _SqliteTarget(kept=kept):
            rows = docker.check_sqlite(
                settings, staging, SQLITE_COPY_NAME, app.restore_test.count_table
            )
            return Manifest(app.name, None, rows, _count_kept(settings, kept) if kept else None)


def _count_kept(settings: Settings, kept: KeptVolume) -> int:
    return docker.count_files(settings, MountKind.VOLUME, kept.volume, kept.skip)


def _restore_test(settings: Settings, app: App, run: Run, snapshot_prefix: str | None) -> str:
    with run.phase(Phase.RESTORE):
        snapshot_id = (
            _last_successful_snapshot(settings, app, run.snapshot_of(app.name))
            if snapshot_prefix is None
            else _chosen_snapshot(settings, app, snapshot_prefix)
        )
    with _private_directory(settings.work_dir) as restored:
        with run.phase(Phase.RESTORE):
            restic.restore(settings, app.name, snapshot_id, restored)
        with run.phase(Phase.VERIFY):
            _verify(settings, app, restored, run)
    return snapshot_id


def _verify(settings: Settings, app: App, restored: Path, run: Run) -> None:
    """Only what the copy shows fails verification; a container that will not run is a command."""
    restored_db = restored / DB_FOLDER
    manifest_file = _restored_file(restored_db / MANIFEST_NAME, "no manifest")
    manifest = Manifest.from_json(manifest_file.read_text(encoding="utf-8"))
    match app.database:
        case PostgresDatabase() as database:
            _verify_postgres(settings, app, database, restored, manifest, run)
        case SqliteDatabase(files=files):
            _restored_file(restored_db / SQLITE_COPY_NAME, "no SQLite database")
            with run.phase(Phase.VERIFY):
                if files:
                    _verify_files(settings, restored / files.volume, files.skip, manifest)
                rows = docker.check_sqlite(
                    settings, restored_db, SQLITE_COPY_NAME, app.restore_test.count_table
                )
                check_rows(manifest, rows)
                check_row_count(
                    app.restore_test.count_table, rows, require_rows=app.restore_test.require_rows
                )


def _verify_files(settings: Settings, restored: Path, skip: str | None, manifest: Manifest) -> None:
    if not restored.is_dir():
        raise VerificationError("the snapshot holds no file list")
    check_file_count(
        manifest.files, docker.count_files(settings, MountKind.BIND, str(restored), skip), "files"
    )


def _verify_postgres(
    settings: Settings,
    app: App,
    database: PostgresDatabase,
    restored: Path,
    manifest: Manifest,
    run: Run,
) -> None:
    restored_db, restored_audio = restored / DB_FOLDER, restored / restic.AUDIO_FOLDER
    dump = _restored_file(restored_db / DUMP_NAME, "no database dump")
    audio = database.audio
    if audio:
        check_file_count(
            manifest.audio_files,
            docker.count_files(settings, MountKind.BIND, str(restored_audio)),
            "audio files",
        )
    with docker.restore_server(
        RESTORE_IMAGES[database.postgres_major], settings.lock_file
    ) as server:
        _wait_until_ready(
            lambda: _ready_or_raise(server),
            _Deadline.start(RESTORE_SERVER_TIMEOUT),
            RESTORE_SERVER_POLL_SECONDS,
        )
        with run.phase(Phase.VERIFY, failing=ExitCategory.VERIFICATION_FAILED):
            server.list_dump(dump)
            server.load_dump(dump)
            restore_test = app.restore_test
            check_row_count(
                restore_test.count_table,
                server.row_count(restore_test.count_table),
                require_rows=restore_test.require_rows,
            )
            references = (
                server.column_values(audio.reference_table, audio.reference_column) if audio else []
            )
    check_audio_references(references, restored_audio)


def _recorded_snapshot(settings: Settings, apps: tuple[App, ...], app: App) -> str | None:
    """A restore only reads the status: legacy evidence is attributed in memory, never written."""
    status = previous_status(settings)
    if status is None:
        return None
    return attributed_status(settings, status, apps).snapshot_of(app.name)


def _last_successful_snapshot(settings: Settings, app: App, recorded: str | None) -> str:
    """Never a newer snapshot a failed run left behind; if it is gone, the newest is only named."""
    if recorded is None:
        raise StepFailed(
            ExitCategory.CONFIGURATION,
            f"no successful backup of {app.name} recorded" + _newest_snapshot_hint(settings, app),
        )
    if not restic.has_snapshot(settings, app.name, recorded):
        raise StepFailed(
            ExitCategory.CONFIGURATION,
            f"the recorded snapshot {recorded[:8]} of {app.name} is missing from the repository"
            + _newest_snapshot_hint(settings, app),
        )
    return recorded


def _newest_snapshot_hint(settings: Settings, app: App) -> str:
    """An app restic holds no snapshot of has nothing to name."""
    newest = restic.latest_snapshot(settings, app.name)
    if newest is None:
        return ""
    return (
        f"; the newest snapshot is {newest[:8]}; choose it with: "
        f"{command(Verb.RESTORE, app.name, '--snapshot', '<ID>', '--target', '<folder>')}"
    )


def _chosen_snapshot(settings: Settings, app: App, prefix: str) -> str:
    """Only this app's snapshots count, so another app's ID is as unknown as a mistyped one."""
    matches = [
        snapshot_id
        for snapshot_id in restic.snapshot_ids(settings, app.name)
        if len(prefix) >= MIN_SNAPSHOT_PREFIX and snapshot_id.startswith(prefix)
    ]
    if len(matches) != 1:
        raise StepFailed(
            ExitCategory.CONFIGURATION,
            f"{prefix} names no single snapshot of {app.name} "
            f"(at least {MIN_SNAPSHOT_PREFIX} characters of an ID from "
            f"`{command(Verb.RESTORE, '--list')}`)",
        )
    return matches[0]


def _wait_until_ready[T](probe: Callable[[], T], deadline: _Deadline, poll_seconds: float) -> T:
    while True:
        try:
            return _resolved(probe)
        except docker.NotReadyError as error:
            if host.monotonic() >= deadline.expires_at:
                minutes = int(deadline.timeout.total_seconds() // 60)
                raise StepFailed(ExitCategory.NOT_READY, f"{error} after {minutes} min") from error
            host.sleep(poll_seconds)


def _resolved[T](probe: Callable[[], T]) -> T:
    try:
        return probe()
    except docker.TargetError as error:
        raise StepFailed(ExitCategory.CONFIGURATION, str(error)) from error


def _ready_or_raise(server: docker.RestoreServer) -> None:
    if not server.is_ready():
        raise docker.NotReadyError("the throwaway database does not start")


def _restored_file(path: Path, missing: str) -> Path:
    if not path.is_file():
        raise VerificationError(f"the snapshot holds {missing}")
    return path


def _write_private(path: Path, text: str) -> None:
    path.touch(mode=0o600, exist_ok=False)
    path.write_text(text, encoding="utf-8")


def sweep_leftover_staging(parent: Path) -> None:
    """A killed run never reaches its cleanup, so every run first removes the plaintext it left,
    whether or not it gets far enough to stage anything itself.

    Only directories with a run's mark go; anything else here is left alone.
    The host lock guarantees no other run is using them.
    """
    try:
        for mark in parent.glob(f"{STAGING_PREFIX}*{RUN_MARK_SUFFIX}"):
            _remove_staging(mark)
    except OSError as error:
        raise StepFailed(
            ExitCategory.INTERNAL,
            f"the plaintext of an aborted run cannot be removed: {error.strerror}",
        ) from error


@contextmanager
def _private_directory(parent: Path) -> Iterator[Path]:
    """A 0700 directory for dumps and restored copies, removed on success and on failure.

    The directory is reserved under a fresh name before it is marked, so the mark never
    claims a directory this run did not create; plaintext enters only once it is marked.
    """
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=parent))
    mark = _run_mark(directory)
    try:
        mark.touch(mode=0o600, exist_ok=False)
    except BaseException:
        directory.rmdir()
        raise
    try:
        yield directory
    finally:
        _remove_staging(mark)


def _run_mark(directory: Path) -> Path:
    return directory.with_name(directory.name + RUN_MARK_SUFFIX)


def _staged_directory(mark: Path) -> Path:
    return mark.with_name(mark.name.removesuffix(RUN_MARK_SUFFIX))


def _remove_staging(mark: Path) -> None:
    """The directory goes before its mark, so a run killed in between leaves it findable."""
    directory = _staged_directory(mark)
    if directory.exists():
        shutil.rmtree(directory)
    mark.unlink()
