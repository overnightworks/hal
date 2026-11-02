"""A scripted Docker host in place of docker and restic, for the edge-backup test modules."""

import fcntl
import fnmatch
import json
import re
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hal.backup import host, sqlite_copy
from hal.backup.cli import DEFAULT_APPS
from hal.backup.docker import (
    FILE_COUNT_LABEL,
    RESTORE_OWNER_LABEL,
    RESTORE_OWNER_ROLE,
    RESTORE_SERVER,
    SERVER_REMOVAL_LABEL,
    SERVER_START_LABEL,
    SQLITE_CHECK_LABEL,
    SQLITE_COPY_LABEL,
    SQLITE_OWNER_LABEL,
)
from hal.backup.settings import RESTIC_HOSTNAME

CANARY_PASSWORD = "canary-7f3e-never-print-me"
DUMP = b"PGDMP custom archive"
AUDIO = {"u1/one.mp3": b"ID3 one", "u1/two.mp3": b"ID3 two", "u2/cover.png": b"PNG"}
SONGMAKER_CONTAINER = "c0ffee"
RESTORE_SERVER_ID = "deadbeef" * 8
RADIO_CONTAINER = "beef01"
KEYCLOAK_CONTAINER = "kc01"
STATUS_KEYS = {
    "schema",
    "state",
    "phase",
    "failing_phase",
    "failing_app",
    "exit_category",
    "last_attempt",
    "apps",
}
APP_HISTORY_KEYS = {"last_snapshot_id", "last_successful_backup", "last_successful_restore_test"}
SONGMAKER_TOML = """
[app.songmaker]
compose_project = "songmaker"
db_service = "postgres"
dump = "pg_dump_custom"
db_user = "songmaker"
db_name = "songmaker"
postgres_major = 16
volume = "audiofiles"
[app.songmaker.restore_test]
count_table = "songs"
audio_reference_table = "generations"
audio_reference_column = "mp3_path"
"""
RADIO_TOML = """
[app.radio]
compose_project = "radio"
db_service = "postgres"
dump = "pg_dump_custom"
db_user = "radio"
db_name = "radio"
postgres_major = 16
volume = "audiofiles"
[app.radio.restore_test]
count_table = "songs"
audio_reference_table = "generations"
audio_reference_column = "mp3_path"
"""
SQLITE_TOML = """
[app.presentator]
compose_project = "presentator"
dump = "sqlite_online_copy"
database_volume = "database"
database_file = "presentator.sqlite3"
[app.presentator.restore_test]
count_table = "users"
"""
SQLITE_COPY = b"SQLite rows=7"
# The real boundary, kept before the `machine` fixture swaps it: exits and files go through it.
REAL_HOST_RUN = host.run


@dataclass
class Machine:
    """Answers each fixed argv the way docker, restic and the throwaway postgres would."""

    audio: dict[str, bytes] = field(default_factory=lambda: dict(AUDIO))
    table_rows: dict[str, int] = field(default_factory=lambda: {"songs": 42, "realm": 2})
    """The rows the restored database holds, by table."""
    references: list[str] = field(default_factory=lambda: ["u1/one.mp3", "u1/two.mp3"])
    db_containers: list[str] = field(default_factory=lambda: [SONGMAKER_CONTAINER])
    volumes: list[str] = field(default_factory=lambda: ["songmaker_audiofiles"])
    other_db_containers: dict[str, list[str]] = field(
        default_factory=lambda: {"radio": [RADIO_CONTAINER], "edge": [KEYCLOAK_CONTAINER]}
    )
    """The database containers of every project but songmaker, by compose project."""
    other_volumes: dict[str, list[str]] = field(
        default_factory=lambda: {"radio": ["radio_audiofiles"]}
    )
    volume_files: dict[str, dict[str, bytes]] = field(default_factory=dict)
    """The files of a kept volume by Docker volume name; songmaker's audio volume holds `audio`."""
    volumes_by_label: dict[str, list[str]] = field(default_factory=dict)
    """What `docker volume ls` answers for a compose volume name, whatever the project."""
    unreadable_directories: set[str] = field(default_factory=set)
    """Directories of a kept volume the operator cannot traverse: a count entering one exits 1."""
    clock: "Clock" = field(default_factory=lambda: Clock())
    absent_polls: int = 0
    """How many `docker ps` polls find no database container before it appears."""
    source_bytes: int = 4_404_019
    """What restic's backup summary reports as `total_bytes_processed`."""
    backup_seconds: float = 0
    """How long restic's backup takes on the machine clock."""
    maintenance_seconds: float = 0
    """How long restic's forget and check each take on the machine clock."""
    prints_backup_summary: bool = True
    summary_without: set[str] = field(default_factory=set)
    """Fields restic's backup summary lacks."""
    hanging: set[str] = field(default_factory=set)
    """Labels of probes that never answer; only a timeout ends them."""
    leftover_servers: list[str] = field(default_factory=list)
    """Throwaway servers a killed restore test left behind; they carry the owner label."""
    created_servers: list[str] = field(default_factory=list)
    """Throwaway servers `docker run` created; they carry the owner label too."""
    foreign_server_name: bool = False
    """A container that is not edge-backup's already holds the throwaway server's name."""
    server_start_output: bytes = f"{RESTORE_SERVER_ID}\n".encode()
    """What `docker run` prints once it has created the throwaway server."""
    snapshot_without: set[str] = field(default_factory=set)
    """Staged files a snapshot lacks, as if they had vanished before restic's scan."""
    starting_server_polls: int = 1
    """How many pg_isready polls find the throwaway server still starting."""
    server_accepting: bool = False
    """pg_isready has said yes since the throwaway server started."""
    written_during_scan: dict[str, bytes] = field(default_factory=dict)
    """Audio that lands in the volume after the manifest's count, before restic's scan."""
    failing: dict[str, int | type[BaseException]] = field(default_factory=dict)
    restore_diagnostic: str = ""
    """What pg_restore would print to stderr when it fails, as postgres quotes row values."""
    snapshots: list[dict] = field(default_factory=list)
    calls: list[tuple[str, list[str]]] = field(default_factory=list)
    status_seen_during_backup: dict | None = None
    status_file: Path | None = None
    status_unwritable_after_backup: bool = False
    """The status directory turns read-only once restic has answered a backup."""
    lock_free_during: set[str] = field(default_factory=set)
    """Labels of commands that ran while the host lock was free."""
    missing_images: set[str] = field(default_factory=set)
    """Pinned images `docker image prune -a` removed."""
    unpullable_images: set[str] = field(default_factory=set)
    """Pinned images `docker pull` cannot fetch, as if the registry were unreachable."""
    daemon_down_polls: int = 0
    """How many `docker info` polls find the daemon not up yet; until then docker calls exit 1."""
    sqlite_copy: bytes | None = SQLITE_COPY
    """What the SQLite file copies to (`SQLite rows=N`); None: the file is missing."""
    sqlite_owner: bytes = b"1001:1001\n"
    sqlite_copy_fails: bool = False
    """The copy run fails although the owner answered, as when the volume turns unreadable."""
    sqlite_diagnostic: str = ""
    """What the script's Python would print to stderr when it fails, as it quotes paths and rows."""
    private_modes: dict[str, int] = field(default_factory=dict)
    """Modes of the staging and restore directories and files, seen while restic used them."""

    def run(
        self,
        argv: Sequence[str],
        *,
        label: str,
        stdin: Path | None = None,
        stdout: Path | None = None,
        timeout: timedelta | None = None,
        discard_stderr: bool = False,
    ) -> bytes:
        argv = list(argv)
        self.calls.append((label, argv))
        assert len(self.calls) < 10_000, "the runner never gives up"
        if label in self.hanging:
            assert timeout is not None, f"{label} would hang forever"
            self.clock.sleep(timeout.total_seconds())
            raise host.HostCommandError(label, "antwortete nicht")
        if self._host_lock_is_free():
            self.lock_free_during.add(label)
        if (failure := self.failing.get(label)) is not None:
            if isinstance(failure, int):
                return exit_with(label, failure)
            raise failure()
        answers = {
            "docker info": self._daemon,
            "docker image inspect": self._image,
            "docker pull": self._pull,
            "docker ps": self._containers,
            "docker inspect": self._state,
            "docker volume ls": self._volumes,
            "pg_dump": self._pg_dump,
            FILE_COUNT_LABEL: self._scan,
            SQLITE_OWNER_LABEL: self._sqlite_owner,
            SQLITE_COPY_LABEL: self._sqlite_copy,
            SQLITE_CHECK_LABEL: self._sqlite_check,
            "restic backup": self._backup,
            "restic snapshots": self._snapshots,
            "restic restore": self._restore,
            SERVER_START_LABEL: self._start_server,
            "pg_isready": self._pg_isready,
            "pg_restore --list": self._pg_restore,
            "pg_restore": self._pg_restore,
            "psql": self._psql,
            SERVER_REMOVAL_LABEL: self._silent,
            "restic init": self._silent,
            "restic forget": self._maintenance,
            "restic check": self._maintenance,
            "restic unlock": self._silent,
        }
        if label not in answers:
            pytest.fail(f"the scripted machine does not know {label!r}")
        answer = answers[label](argv, stdin=stdin, discard_stderr=discard_stderr)
        if stdout is None:
            return answer
        return REAL_HOST_RUN(["printf", "%s", answer.decode()], label=label, stdout=stdout)

    def labels(self) -> list[str]:
        return [label for label, _ in self.calls]

    def argv_of(self, label: str) -> list[str]:
        return next(argv for called, argv in self.calls if called == label)

    def _host_lock_is_free(self) -> bool:
        lock = self.status_file.with_name("backup.lock")
        if not lock.exists():
            return True
        with lock.open("rb") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            fcntl.flock(handle, fcntl.LOCK_UN)
            return True

    def _daemon(self, argv, **_) -> bytes:
        if self.daemon_down_polls:
            self.daemon_down_polls -= 1
            return exit_with("docker info", 1)
        return b"27.3.1\n"

    def _image(self, argv, *, discard_stderr, **_) -> bytes:
        if self.daemon_down_polls:
            return exit_with("docker image inspect", 1)
        if argv[-1] not in self.missing_images:
            return b"sha256:0"
        if not discard_stderr:
            sys.stderr.write(f"Error: No such image: {argv[-1]}\n")
        return exit_with("docker image inspect", 1)

    def _pull(self, argv, *, discard_stderr, **_) -> bytes:
        if argv[-1] in self.unpullable_images:
            if not discard_stderr:
                sys.stderr.write("Error response from daemon: Get registry: dial tcp\n")
            return exit_with("docker pull", 1)
        self.missing_images.discard(argv[-1])
        return b"sha256:0\n"

    def _containers(self, argv, **_) -> bytes:
        if any(RESTORE_SERVER in argument for argument in argv):
            ours = f"label={RESTORE_OWNER_LABEL}={RESTORE_OWNER_ROLE}" in argv
            foreign = [] if ours or not self.foreign_server_name else ["f0re1gn"]
            return "\n".join([*self._owned_servers(), *foreign]).encode()
        if self.absent_polls:
            self.absent_polls -= 1
            return b""
        project = label_value(argv, "com.docker.compose.project")
        found = self.db_containers if project == "songmaker" else self.other_db_containers[project]
        return "\n".join(found).encode()

    def _state(self, argv, **_) -> bytes:
        return b"running healthy\n"

    def _volumes(self, argv, **_) -> bytes:
        if (
            named := self.volumes_by_label.get(label_value(argv, "com.docker.compose.volume"))
        ) is not None:
            return "\n".join(named).encode()
        project = label_value(argv, "com.docker.compose.project")
        found = self.volumes if project == "songmaker" else self.other_volumes[project]
        return "\n".join(found).encode()

    def _pg_dump(self, argv, **_) -> bytes:
        return DUMP

    def _sqlite_owner(self, argv, *, discard_stderr, **_) -> bytes:
        if self.sqlite_copy is None:
            return self._sqlite_failure(
                SQLITE_OWNER_LABEL, sqlite_copy.VERDICT_EXIT, discard_stderr
            )
        return self.sqlite_owner

    def _sqlite_copy(self, argv, *, discard_stderr, **_) -> bytes:
        if self.sqlite_copy is None or self.sqlite_copy_fails:
            return self._sqlite_failure(SQLITE_COPY_LABEL, sqlite_copy.VERDICT_EXIT, discard_stderr)
        return self.sqlite_copy

    def _sqlite_check(self, argv, *, discard_stderr, **_) -> bytes:
        """The script's `check` over a staged or restored directory: rows, or its verdict exit."""
        copied = Path(mount_source(argv, "/data")) / Path(argv[-2]).name
        match re.fullmatch(rb"SQLite rows=(\d+)", copied.read_bytes()):
            case None:
                return self._sqlite_failure(
                    SQLITE_CHECK_LABEL, sqlite_copy.VERDICT_EXIT, discard_stderr
                )
            case found:
                return found[1] + b"\n"

    def _sqlite_failure(self, label: str, exit_code: int, discard_stderr: bool) -> bytes:
        if not discard_stderr:
            sys.stderr.write(f"{self.sqlite_diagnostic}\n")
        return exit_with(label, exit_code)

    def _scan(self, argv, **_) -> bytes:
        """`find <mount> [-mindepth 1 -name <skip> -prune -o] -type f -print0` over a live volume or
        a restored directory."""
        mount = mount_of(argv, "/scanned")
        skip = argv[argv.index("-name") + 1] if "-name" in argv else None
        if mount["type"] == "volume":
            names = self.volume_files.get(mount["source"], self.audio)
        else:
            root = Path(mount["source"])
            names = {
                str(path.relative_to(root)): b""
                for path in root.rglob("*")
                if path.is_file() and not path.is_symlink()
            }
        if skip is not None and "-mindepth" not in argv and fnmatch.fnmatchcase("scanned", skip):
            return b""
        kept = [name for name in names if not _skipped(name, skip)]
        if any(set(map(str, Path(name).parents)) & self.unreadable_directories for name in kept):
            return exit_with(FILE_COUNT_LABEL, 1)
        return b"".join(name.encode() + b"\0" for name in kept)

    def _backup(self, argv, **_) -> bytes:
        self.status_seen_during_backup = json.loads(self.status_file.read_text())
        app = re.search(r"target=/backup/([^/,]+)/db", " ".join(argv))[1]
        kept = self._kept_by_folder(argv, app)
        staging = Path(mount_source(argv, f"/backup/{app}/db"))
        self.private_modes["staging"] = mode_of(staging)
        self.private_modes |= {path.name: mode_of(path) for path in staging.iterdir()}
        snapshot_id = f"{len(self.snapshots) + 1:064x}"
        if self.status_unwritable_after_backup:
            self.status_file.parent.chmod(0o500)
        self.snapshots.append(
            {
                "id": snapshot_id,
                "app": app,
                "host": argv[argv.index("--hostname") + 1],
                "db": {
                    path.name: path.read_bytes()
                    for path in staging.iterdir()
                    if path.name not in self.snapshot_without
                },
                "audio": self.audio | self.written_during_scan if "audio" in kept else {},
                "volumes": {folder: files for folder, files in kept.items() if folder != "audio"},
            }
        )
        status = {"message_type": "status", "percent_done": 1}
        self.clock.sleep(self.backup_seconds)
        summary = {
            "message_type": "summary",
            "snapshot_id": snapshot_id,
            "total_bytes_processed": self.source_bytes,
        }
        summary = {key: value for key, value in summary.items() if key not in self.summary_without}
        lines = [status, *([summary] if self.prints_backup_summary else [])]
        return "".join(f"{json.dumps(line)}\n" for line in lines).encode()

    def _kept_by_folder(self, argv, app: str) -> dict[str, dict[str, bytes]]:
        """The volumes restic is told to keep beside `db/`, without what `--exclude` leaves out."""
        source = f"/backup/{app}/"
        excludes = [argv[i + 1] for i, a in enumerate(argv) if a == "--exclude"]
        kept = {}
        for argument in (argv[i + 1] for i, a in enumerate(argv) if a == "--mount"):
            mount = dict(part.split("=", 1) for part in argument.split(",") if "=" in part)
            folder = mount["target"].removeprefix(source)
            if not mount["target"].startswith(source) or folder == "db":
                continue
            skips = [
                e.rsplit("/", 1)[1] for e in excludes if e.startswith(f"{mount['target']}/**/")
            ]
            kept[folder] = {
                name: content
                for name, content in self.volume_files.get(mount["source"], self.audio).items()
                if not any(_skipped(name, skip) for skip in skips)
            }
        return kept

    def _snapshots(self, argv, **_) -> bytes:
        if "--json" in argv:
            tag = argv[argv.index("--tag") + 1]
            host_name = argv[argv.index("--host") + 1]
            tagged = [
                s
                for s in self.snapshots
                if s.get("app", "songmaker") == tag and s.get("host", RESTIC_HOSTNAME) == host_name
            ]
            listed = tagged[-1:] if "--latest" in argv else tagged
            return json.dumps([{"id": s["id"]} for s in listed]).encode()
        shown = [
            s
            for s in self.snapshots
            if "--host" not in argv
            or s.get("host", RESTIC_HOSTNAME) == argv[argv.index("--host") + 1]
        ]
        return "".join(f"{s['id']} {s.get('host', RESTIC_HOSTNAME)}\n" for s in shown).encode()

    def _restore(self, argv, **_) -> bytes:
        snapshot_id = argv[argv.index("restore") + 1].split(":")[0]
        snapshot = next(s for s in self.snapshots if s["id"] == snapshot_id)
        target = Path(mount_source(argv, "/restore"))
        self.private_modes["restored"] = mode_of(target)
        folders = {"db": snapshot["db"], "audio": snapshot["audio"]} | snapshot.get("volumes", {})
        for folder, files in folders.items():
            if folder in snapshot.get("volumes", {}):
                (target / folder).mkdir(parents=True, exist_ok=True)
            for name, content in files.items():
                (target / folder / name).parent.mkdir(parents=True, exist_ok=True)
                (target / folder / name).write_bytes(content)
        return b""

    def _silent(self, argv, **_) -> bytes:
        return b""

    def _maintenance(self, argv, **_) -> bytes:
        self.clock.sleep(self.maintenance_seconds)
        return b""

    def _start_server(self, argv, **_) -> bytes:
        if self.foreign_server_name or self._owned_servers():
            return exit_with(SERVER_START_LABEL, 125)
        self.server_accepting = False
        self.created_servers.append(RESTORE_SERVER_ID)
        return self.server_start_output

    def _owned_servers(self) -> list[str]:
        removed = set(removed_servers(self))
        return [s for s in [*self.leftover_servers, *self.created_servers] if s not in removed]

    def _pg_isready(self, argv, **_) -> bytes:
        assert argv[argv.index("pg_isready") + 1 :] == ["--host", "127.0.0.1", "--quiet"]
        if self.starting_server_polls:
            self.starting_server_polls -= 1
            return exit_with("pg_isready", 2)
        self.server_accepting = True
        return b""

    def _pg_restore(self, argv, *, stdin, discard_stderr, **_) -> bytes:
        assert self.server_accepting, "pg_restore before pg_isready said the server accepts"
        if self.restore_diagnostic:
            if not discard_stderr:
                sys.stderr.write(f"{self.restore_diagnostic}\n")
            return exit_with("pg_restore", 1)
        if not stdin.read_bytes().startswith(b"PGDMP"):
            return exit_with("pg_restore", 1)
        return b""

    def _psql(self, argv, **_) -> bytes:
        assert self.server_accepting, "psql before pg_isready said the server accepts"
        sql = argv[argv.index("--command") + 1]
        answers = {
            f'SELECT count(*) FROM "{table}"': f"{rows}\n".encode()  # noqa: S608 - the fake matches the SQL text its caller sends and runs none
            for table, rows in self.table_rows.items()
        } | {
            'SELECT "mp3_path" FROM "generations"'
            ' WHERE "mp3_path" IS NOT NULL AND "mp3_path" <> \'\'': b"".join(
                reference.encode() + b"\0" for reference in self.references
            ),
        }
        if sql not in answers:
            pytest.fail(f"the throwaway server was asked an unexpected query: {sql}")
        return answers[sql]


def _skipped(name: str, glob: str | None) -> bool:
    """`find -name <glob> -prune` and restic's `**/<glob>` both drop an entry whose own name, or
    one of its parents' below the root, matches."""
    return glob is not None and any(fnmatch.fnmatchcase(part, glob) for part in Path(name).parts)


def declare_apps(home: Path, toml: str) -> tuple[str, str]:
    """The `--apps` arguments that declare exactly these records."""
    declared = home / "declared-apps.toml"
    declared.write_text(toml)
    return "--apps", str(declared)


def declare_shipped_apps() -> tuple[str, str]:
    """The `--apps` arguments that declare what `backup/apps.toml` ships."""
    return "--apps", str(DEFAULT_APPS)


def declare_two_apps(home: Path) -> tuple[str, str]:
    """The `--apps` arguments that declare songmaker and radio."""
    return declare_apps(home, SONGMAKER_TOML + RADIO_TOML)


def schema_one_status(snapshot_id: str) -> dict:
    """What edge-backup wrote before the status kept history per app."""
    return {
        "schema": 1,
        "state": "ok",
        "phase": "check",
        "failing_phase": None,
        "exit_category": None,
        "last_attempt": "2026-10-11T03:00:00+00:00",
        "last_successful_backup": "2026-10-11T03:00:00+00:00",
        "last_successful_restore_test": "2026-10-04T03:00:00+00:00",
        "last_snapshot_id": snapshot_id,
    }


def app_history(status: dict, app: str = "songmaker") -> dict:
    """One app's entry of the status; an app with no success yet has none."""
    return status["apps"].get(app, {})


def label_value(argv: list[str], key: str) -> str:
    return next(a.split("=", 2)[2] for a in argv if a.startswith(f"label={key}="))


def exit_with(label: str, exit_code: int) -> bytes:
    """A real process exits with the code, so host.run decides what it means."""
    return REAL_HOST_RUN(["sh", "-c", f"exit {exit_code}"], label=label)


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def removed_servers(machine: Machine) -> list[str]:
    return [argv[-1] for label, argv in machine.calls if label == SERVER_REMOVAL_LABEL]


def no_restore_server_left(machine: Machine) -> bool:
    started = machine.labels().count(SERVER_START_LABEL)
    return started == removed_servers(machine).count(RESTORE_SERVER_ID)


def assert_the_restore_test_fails_verification(edge_backup, apps: list) -> None:
    outcome = edge_backup("restore", "--test", *apps)

    assert outcome.exit_code == 3
    assert (outcome.status["failing_phase"], outcome.status["exit_category"]) == (
        "verify",
        "verification-failed",
    )


def mount_of(argv: list[str], target: str) -> dict[str, str]:
    mounts = [argv[i + 1] for i, argument in enumerate(argv) if argument == "--mount"]
    return next(
        dict(part.split("=", 1) for part in mount.split(",") if "=" in part)
        for mount in mounts
        if f"target={target}," in mount + ","
    )


def mount_source(argv: list[str], target: str) -> str:
    return mount_of(argv, target)["source"]


@dataclass
class Clock:
    moment: datetime = datetime(2026, 10, 18, 3, 0, tzinfo=UTC)
    elapsed: float = 0.0
    wall_drift_per_sleep: timedelta = timedelta(0)
    """How far someone sets the wall clock while the runner sleeps (NTP, an operator)."""

    def now(self) -> datetime:
        return self.moment

    def monotonic(self) -> float:
        return self.elapsed

    def sleep(self, seconds: float) -> None:
        self.elapsed += seconds
        self.moment += timedelta(seconds=seconds) + self.wall_drift_per_sleep


@dataclass(frozen=True)
class Outcome:
    exit_code: int
    out: str
    err: str
    status: dict | None
