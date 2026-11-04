"""The apps' containers and volumes, found by compose labels, and the throwaway restore server."""

import hashlib
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from hal.backup import host, sqlite_copy
from hal.backup.apps import App, PostgresDatabase, SqliteDatabase
from hal.backup.restic import Mount, MountKind, container_argv
from hal.backup.settings import (
    PROBE_TIMEOUT,
    RESTIC_IMAGE,
    RESTORE_IMAGES,
    SQLITE_IMAGE,
    Settings,
)
from hal.backup.verify import VerificationError

PROJECT_LABEL = "com.docker.compose.project"
SERVICE_LABEL = "com.docker.compose.service"
VOLUME_LABEL = "com.docker.compose.volume"
# `docker compose run` leaves one-off containers with the same project and service labels.
ONEOFF_LABEL = "com.docker.compose.oneoff"
# A throwaway server's name carries its home, so a run under another HOME (a probe's) never meets
# it; the runs of one home are serialised by its lock.
RESTORE_SERVER_PREFIX = "hal-backup-restore-test"
_HOME_DIGEST_LENGTH = 8
# Marks a throwaway server as hal backup's own: only a container carrying it is ever removed.
RESTORE_OWNER_LABEL = "hal-backup.role"
RESTORE_OWNER_ROLE = "restore-test"
RESTORE_DATABASE = "restore_test"
# The image's superuser; `docker exec` runs as root, which is no role in the server.
RESTORE_ROLE = "postgres"
# Host-run labels: they name the step in `<label> ended with exit N` and key the test fakes.
SQLITE_COPY_LABEL = "SQLite copy"
SQLITE_CHECK_LABEL = "SQLite copy check"
FILE_COUNT_LABEL = "file count"
SERVER_START_LABEL = "throwaway database start"
SERVER_REMOVAL_LABEL = "throwaway database removal"
SQLITE_OWNER_LABEL = "SQLite owner read"
DATABASE_START_LABEL = "database start"
SESSION_COUNT_LABEL = "pg_restore session count"
LIVE_LOAD_LABEL = "live load"
# Bounds the one wait a load into a switched-off database can meet, a lock another session holds;
# past it the load fails in its transaction.
LIVE_LOCK_TIMEOUT = timedelta(seconds=60)
# pg_restore names its session so (postgres src/bin/pg_dump/pg_backup_db.c); no PGAPPNAME hides it.
PG_RESTORE_APPLICATION = "pg_restore"
_SCANNED = "/scanned"
_SQLITE_SCRIPT = "/sqlite_copy.py"
_SQLITE_DATA = "/data"
_OWNER = re.compile(r"(\d+):(\d+)\n")
_RUNNING = "running"
_READY_STATES = frozenset({_RUNNING, "running healthy"})
# What `docker run --detach` prints: the full ID, never a name or a shortened one.
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}")


class NotReadyError(RuntimeError):
    """Docker or the app's database is not up yet; worth waiting for."""


class TargetError(RuntimeError):
    """The labels do not name exactly one container or volume; waiting will not fix that."""


class DockerSilentError(NotReadyError):
    """Docker did not answer: worth waiting for in a backup, a failure for a run that cannot
    wait."""


def require_daemon() -> None:
    try:
        host.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            label="docker info",
            timeout=PROBE_TIMEOUT,
        )
    except host.HostCommandError as error:
        raise DockerSilentError(f"docker does not answer: {error}") from error


def ensure_pinned_images(apps: tuple[App, ...]) -> None:
    """`docker image prune -a` removes the pinned images; a missing one is pulled by its digest."""
    images = dict.fromkeys(
        [RESTIC_IMAGE]
        + [
            RESTORE_IMAGES[app.database.postgres_major]
            if isinstance(app.database, PostgresDatabase)
            else SQLITE_IMAGE
            for app in apps
        ]
    )
    for image in images:
        if not _image_present(image):
            _pull(image)


def _image_present(image: str) -> bool:
    try:
        host.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image],
            label="docker image inspect",
            timeout=PROBE_TIMEOUT,
            discard_stderr=True,
        )
    except host.HostCommandError:
        return False
    return True


def _pull(image: str) -> None:
    try:
        host.run(["docker", "pull", "--quiet", image], label="docker pull", discard_stderr=True)
    except host.HostCommandError as error:
        raise TargetError(f"the pinned image {image} is missing and cannot be pulled") from error


def database_container(app: App, database: PostgresDatabase) -> str:
    return service_container(app.compose_project, database.db_service, app.name)


def service_container(project: str, service: str, name: str) -> str:
    """The one ready database container of the project's service; `name` stands in messages."""
    try:
        ids = _service_containers(project, service)
        if len(ids) > 1:
            raise TargetError(f"{len(ids)} database containers for {name} instead of exactly one")
        if not ids:
            raise NotReadyError("no database container")
        state = _state(ids[0])
    except host.HostCommandError as error:
        raise DockerSilentError(f"docker does not answer: {error}") from error
    if state not in _READY_STATES:
        raise NotReadyError("database not ready")
    return ids[0]


def only_database_container(app: App, database: PostgresDatabase) -> str:
    """The one database container of the app's service in any state, running or stopped."""
    ids = _service_containers(app.compose_project, database.db_service)
    if len(ids) != 1:
        raise TargetError(f"{len(ids)} database containers for {app.name} instead of exactly one")
    return ids[0]


def start_if_stopped(container_id: str) -> bool:
    """Starts the container by its ID unless it runs; whether it had to."""
    if _state(container_id).split()[0] == _RUNNING:
        return False
    host.run(["docker", "start", container_id], label=DATABASE_START_LABEL, discard_stderr=True)
    return True


def _service_containers(project: str, service: str) -> list[str]:
    return _lines(
        host.run(
            ["docker", "ps", "--all", "--quiet", "--no-trunc",
             *_label_filter(PROJECT_LABEL, project),
             *_label_filter(SERVICE_LABEL, service),
             *_label_filter(ONEOFF_LABEL, "False")],
            label="docker ps",
            timeout=PROBE_TIMEOUT,
        )
    )  # fmt: skip


def _state(container_id: str) -> str:
    """`<status>` or `<status> <health>`, as `docker inspect` reports them."""
    state = host.run(
        ["docker", "inspect", "--format",
         "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", container_id],
        label="docker inspect",
        timeout=PROBE_TIMEOUT,
    )  # fmt: skip
    return state.decode().strip()


def app_volume(app: App, volume: str) -> str:
    """The one volume of the app's compose project with this compose volume name."""
    names = _lines(
        host.run(
            ["docker", "volume", "ls", "--quiet",
             *_label_filter(PROJECT_LABEL, app.compose_project),
             *_label_filter(VOLUME_LABEL, volume)],
            label="docker volume ls",
            timeout=PROBE_TIMEOUT,
        )
    )  # fmt: skip
    if len(names) != 1:
        raise TargetError(f"{len(names)} volumes {volume} for {app.name} instead of exactly one")
    return names[0]


def dump_database(database: PostgresDatabase, container_id: str, target: Path) -> None:
    host.run(
        ["docker", "exec", "-i", container_id, "pg_dump",
         "--username", database.db_user, "--format=custom", "--dbname", database.db_name],
        label="pg_dump",
        stdout=target,
    )  # fmt: skip


def restore_sessions(container_id: str, database: PostgresDatabase) -> int:
    """How many sessions of `pg_restore` the live database holds, a killed run's load among them."""
    output = host.run(
        ["docker", "exec", container_id, "psql",
         "--username", database.db_user, "--dbname", database.db_name,
         "--no-psqlrc", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1",
         "--command", "SELECT count(*) FROM pg_stat_activity"
         f" WHERE application_name = '{PG_RESTORE_APPLICATION}'"],
        label=SESSION_COUNT_LABEL,
        timeout=PROBE_TIMEOUT,
        discard_stderr=True,
    )  # fmt: skip
    try:
        return int(output)
    except ValueError as error:
        raise host.UnreadableOutputError("the pg_restore session count is unreadable") from error


# The shell parses no argument: pg_restore's argv are its positional parameters. Its messages
# quote row values, so they go to /dev/null; its exit code is the shell's last stdout line.
_REPORTING_SHELL = ("sh", "-c", '"$@" >/dev/null 2>&1; echo $?', "sh")


def load_live(container_id: str, database: PostgresDatabase, dump: Path) -> int | None:
    """The dump loaded into the live database in one transaction; the exit code pg_restore
    printed, or None when no code line came. The client runs in its own session, so a Ctrl-C
    at the terminal reaches only hal; a failed client raises `HostCommandError`."""
    lock_timeout = f"lock_timeout={int(LIVE_LOCK_TIMEOUT.total_seconds())}s"
    options = " ".join((*_SILENT_SERVER_SETTINGS, "-c", lock_timeout))
    output = host.run(
        ["docker", "exec", "-i", "--env", f"PGOPTIONS={options}", container_id,
         *_REPORTING_SHELL, "pg_restore", "--clean", "--if-exists", "--single-transaction",
         "--exit-on-error", "--username", database.db_user, "--dbname", database.db_name],
        label=LIVE_LOAD_LABEL,
        stdin=dump,
        discard_stderr=True,
        new_session=True,
    )  # fmt: skip
    match output.decode(errors="replace").split():
        case [*_, last] if last.isdigit():
            return int(last)
        case _:
            return None


def _sqlite_argv(
    settings: Settings, *mounts: Mount, user: str | None = None, command: list[str]
) -> list[str]:
    """The script of this package, mounted read-only, run by the image's Python in isolated mode."""
    script = Mount(MountKind.BIND, str(Path(sqlite_copy.__file__).resolve()), _SQLITE_SCRIPT)
    argv = container_argv(
        settings, script, *mounts, entrypoint="python", image=SQLITE_IMAGE, user=user
    )
    return [*argv, "-I", _SQLITE_SCRIPT, *command]


def _read_owner(settings: Settings, volume: str, file: str) -> bytes:
    """The script's `VERDICT_EXIT` on `owner` means the file is missing or unreadable."""
    label = SQLITE_OWNER_LABEL
    try:
        return host.run(
            _sqlite_argv(
                settings,
                Mount(MountKind.VOLUME, volume, _SQLITE_DATA),
                command=["owner", f"{_SQLITE_DATA}/{file}"],
            ),
            label=label,
            discard_stderr=True,
        )
    except host.HostCommandError as error:
        if error.exit_code != sqlite_copy.VERDICT_EXIT:
            raise
        raise host.HostCommandError(
            label,
            f"ended with exit {error.exit_code}: {file} is missing or unreadable",
            error.exit_code,
        ) from error


def copy_sqlite(settings: Settings, volume: str, database: SqliteDatabase, target: Path) -> None:
    """The online copy runs as the file's owner with the volume writable: a WAL reader keeps its
    read lock in the `-shm` file. Its connection is read-only: the database file stays unwritten."""
    path = f"{_SQLITE_DATA}/{database.file}"
    answer = _read_owner(settings, volume, database.file)
    owner = _OWNER.fullmatch(answer.decode(errors="replace"))
    if owner is None or int(owner[1]) == 0:
        raise TargetError(f"the owner of the database {database.file} is unreadable or root")
    host.run(
        _sqlite_argv(
            settings,
            Mount(MountKind.VOLUME, volume, _SQLITE_DATA, readonly=False),
            user=f"{owner[1]}:{owner[2]}",
            command=["copy", path],
        ),
        label=SQLITE_COPY_LABEL,
        stdout=target,
        discard_stderr=True,
    )


def check_sqlite(settings: Settings, directory: Path, file: str, table: str) -> int:
    """The row count of a copy whose integrity check answers `ok`; it mounts no volume.

    The script's `VERDICT_EXIT` is its verdict on the copy; any other failure is a run that did
    not happen.
    """
    try:
        output = host.run(
            _sqlite_argv(
                settings,
                Mount(MountKind.BIND, str(directory), _SQLITE_DATA),
                command=["check", f"{_SQLITE_DATA}/{file}", table],
            ),
            label=SQLITE_CHECK_LABEL,
            discard_stderr=True,
        )
    except host.HostCommandError as error:
        if error.exit_code == sqlite_copy.VERDICT_EXIT:
            raise VerificationError("the SQLite copy fails its check") from error
        raise
    try:
        return int(output)
    except ValueError as error:
        raise host.UnreadableOutputError(
            "the row count of the SQLite copy is unreadable"
        ) from error


def count_files(settings: Settings, kind: MountKind, source: str, skip: str | None = None) -> int:
    """Regular files under a volume or host directory, counted read-only in a container.

    The one rule for the manifest's count and the restored copy's; names never leave it. An entry
    matching the skip is pruned at every depth below the root, as restic leaves it out; any read
    error fails the count.
    """
    # `-mindepth 1` keeps the pattern from matching the root itself (`s*` over `/scanned`).
    pruned = ["-mindepth", "1", "-name", skip, "-prune", "-o"] if skip is not None else []
    listing = host.run(
        [
            *container_argv(settings, Mount(kind, source, _SCANNED), entrypoint="find"),
            _SCANNED, *pruned, "-type", "f", "-print0",
        ],
        label=FILE_COUNT_LABEL,
    )  # fmt: skip
    return listing.count(b"\0")


_SILENT_SERVER_SETTINGS = (
    "-c", "log_min_messages=panic", "-c", "log_min_error_statement=panic",
)  # fmt: skip


def restore_server_name(lock_file: Path) -> str:
    """The home's own name: the first hex digits of the sha256 of its lock file's absolute path."""
    digest = hashlib.sha256(str(lock_file.absolute()).encode()).hexdigest()
    return f"{RESTORE_SERVER_PREFIX}-{digest[:_HOME_DIGEST_LENGTH]}"


@contextmanager
def restore_server(image: str, lock_file: Path) -> Iterator[RestoreServer]:
    """A PostgreSQL without network or volume of ours, under the name of the home whose lock is
    held; removed again whatever happens.

    Removal goes by container ID and only to containers with our owner label and this home's
    name: a foreign container holding the name makes the start fail instead of being deleted,
    and another home's server is never seen.
    """
    name = restore_server_name(lock_file)
    _remove_owned_restore_servers(name)
    started = host.run(
        ["docker", "run", "--detach", "--name", name, "--network", "none",
         "--label", f"{RESTORE_OWNER_LABEL}={RESTORE_OWNER_ROLE}",
         # No container log and no server-side error logging: a failed COPY logs row values.
         "--log-driver", "none",
         # trust is safe here: the server has no network and holds only the restored copy.
         "--env", "POSTGRES_HOST_AUTH_METHOD=trust", "--env", f"POSTGRES_DB={RESTORE_DATABASE}",
         image, *_SILENT_SERVER_SETTINGS],
        label=SERVER_START_LABEL,
    )  # fmt: skip
    try:
        yield RestoreServer(_started_container(started))
    finally:
        # By name and owner label, not by the reported ID: the server goes even when
        # docker run's output could not be read.
        _remove_owned_restore_servers(name)


@dataclass(frozen=True)
class RestoreServer:
    container_id: str

    def is_ready(self) -> bool:
        """Asked over TCP: the image's init server listens on the socket only, then restarts."""
        try:
            self._exec(
                ["pg_isready", "--host", "127.0.0.1", "--quiet"],
                label="pg_isready",
                timeout=PROBE_TIMEOUT,
            )
        except host.HostCommandError:
            return False
        return True

    def list_dump(self, dump: Path) -> None:
        self._exec(["pg_restore", "--list"], label="pg_restore --list", stdin=dump)

    def load_dump(self, dump: Path) -> None:
        self._exec(
            ["pg_restore", "--exit-on-error", "--single-transaction", "--no-owner",
             "--no-privileges", "--username", RESTORE_ROLE, "--dbname", RESTORE_DATABASE],
            label="pg_restore",
            stdin=dump,
        )  # fmt: skip

    def row_count(self, table: str) -> int:
        output = self._query(f'SELECT count(*) FROM "{table}"')  # noqa: S608 - the table name comes from apps.toml and is quoted
        try:
            return int(output.strip(b"\0\n"))
        except ValueError as error:
            raise host.UnreadableOutputError(f"the row count of {table} is unreadable") from error

    def column_values(self, table: str, column: str) -> list[str]:
        """The non-empty values; identifiers are validated by apps.toml, so quoting suffices."""
        output = self._query(
            f'SELECT "{column}" FROM "{table}" WHERE "{column}" IS NOT NULL AND "{column}" <> \'\''  # noqa: S608 - table and column names come from apps.toml and are quoted
        )
        return [value.decode() for value in output.strip(b"\n").split(b"\0") if value]

    def _query(self, sql: str) -> bytes:
        return self._exec(
            ["psql", "--username", RESTORE_ROLE, "--dbname", RESTORE_DATABASE, "--no-psqlrc",
             "--tuples-only", "--no-align", "--record-separator-zero",
             "--set", "ON_ERROR_STOP=1", "--command", sql],
            label="psql",
        )  # fmt: skip

    def _exec(
        self,
        command: list[str],
        *,
        label: str,
        stdin: Path | None = None,
        timeout: timedelta | None = None,
    ) -> bytes:
        interactive = ["-i"] if stdin else []
        return host.run(
            ["docker", "exec", *interactive, self.container_id, *command],
            label=label,
            stdin=stdin,
            timeout=timeout,
            discard_stderr=True,  # pg_restore and psql quote row values of the restored tables
        )


def _started_container(run_output: bytes) -> str:
    match _lines(run_output):
        case [container_id] if _CONTAINER_ID.fullmatch(container_id):
            return container_id
        case _:
            raise host.UnreadableOutputError("docker run reported no container id")


def _remove_owned_restore_servers(name: str) -> None:
    for container_id in _lines(
        host.run(
            ["docker", "ps", "--all", "--quiet", "--no-trunc",
             "--filter", f"name=^{name}$",
             *_label_filter(RESTORE_OWNER_LABEL, RESTORE_OWNER_ROLE)],
            label="docker ps",
        )
    ):  # fmt: skip
        _remove_restore_server(container_id)


def _remove_restore_server(container_id: str) -> None:
    host.run(
        ["docker", "rm", "--force", "--volumes", container_id],
        label=SERVER_REMOVAL_LABEL,
    )


def _label_filter(label: str, value: str) -> list[str]:
    return ["--filter", f"label={label}={value}"]


def _lines(output: bytes) -> list[str]:
    try:
        return output.decode().split()
    except UnicodeDecodeError as error:
        raise host.UnreadableOutputError("docker printed output that is not UTF-8") from error
