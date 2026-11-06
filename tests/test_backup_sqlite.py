"""The SQLite copy script against real database files, without Docker."""

import json
import os
import signal
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from support.backup_support import (
    SONGMAKER_TOML,
    SQLITE_COPY,
    SQLITE_TOML,
    STATUS_KEYS,
    Machine,
    app_history,
    assert_the_restore_test_fails_verification,
    declare_apps,
)

from hal.backup import sqlite_copy
from hal.backup.apps import AppsError, SqliteDatabase, parse_apps
from hal.backup.docker import (
    SERVER_START_LABEL,
    SQLITE_CHECK_LABEL,
    SQLITE_COPY_LABEL,
    SQLITE_OWNER_LABEL,
)
from hal.backup.settings import SQLITE_IMAGE
from hal.backup.verify import Manifest, VerificationError

WRITER = """
import sqlite3, sys
connection = sqlite3.connect(sys.argv[1], isolation_level=None)
connection.execute("PRAGMA journal_mode=WAL")
connection.execute("PRAGMA wal_autocheckpoint=8")
for _ in range(int(sys.argv[2])):
    connection.execute("BEGIN IMMEDIATE")
    connection.executemany("INSERT INTO users (name) VALUES (hex(randomblob(1000)))", [()] * 20)
    connection.execute("COMMIT")
"""


def _database(path: Path, rows: int = 3) -> Path:
    connection = sqlite3.connect(path, isolation_level=None)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
    connection.executemany("INSERT INTO users (name) VALUES (?)", [("secret-name",)] * rows)
    connection.close()
    return path


def _copied(source: Path, target: Path) -> Path:
    target.write_bytes(sqlite_copy.copy(source))
    return target


def test_a_copy_holds_the_rows_of_the_source_and_passes_the_check(tmp_path):
    """#461 A2: the copy holds the source's rows and passes the check."""
    copied = _copied(_database(tmp_path / "source.sqlite3", rows=5), tmp_path / "copy.sqlite3")

    assert sqlite_copy.check(copied, "users") == 5


def test_a_copy_taken_while_a_writer_commits_and_checkpoints_is_a_committed_prefix(tmp_path):
    """#461 A2 M7: a copy under a committing writer is a committed prefix."""
    source = _database(tmp_path / "source.sqlite3", rows=0)
    writer = subprocess.Popen([sys.executable, "-I", "-c", WRITER, str(source), "300"])
    counts = []
    try:
        while writer.poll() is None or not counts:
            counts.append(sqlite_copy.check(_copied(source, tmp_path / "copy.sqlite3"), "users"))
    finally:
        writer.kill()
        assert writer.wait() in (0, -signal.SIGKILL)

    assert all(count % 20 == 0 for count in counts)


def test_a_missing_database_fails_and_creates_nothing(tmp_path):
    """#461 A3 M8: a missing file fails the copy and creates nothing."""
    with pytest.raises(sqlite3.OperationalError):
        sqlite_copy.copy(tmp_path / "missing.sqlite3")

    assert list(tmp_path.iterdir()) == []


def test_a_copy_of_a_cleanly_closed_database_leaves_at_most_empty_sidecars_that_a_writer_removes(
    tmp_path,
):
    """#461 A9 M19: a clean database leaves at most empty sidecars."""
    volume = tmp_path / "volume"
    volume.mkdir()
    source = _database(volume / "source.sqlite3")
    assert sorted(path.name for path in volume.iterdir()) == ["source.sqlite3"]

    assert sqlite_copy.check(_copied(source, tmp_path / "copy.sqlite3"), "users") == 3

    base = source.stat()
    left = {path.name: path.stat() for path in volume.iterdir() if path != source}
    assert left.keys() <= {"source.sqlite3-wal", "source.sqlite3-shm"}
    assert all(
        sidecar.st_uid == base.st_uid
        and stat.S_IMODE(sidecar.st_mode) == stat.S_IMODE(base.st_mode)
        for sidecar in left.values()
    )
    assert left.get("source.sqlite3-wal") is None or left["source.sqlite3-wal"].st_size == 0
    writer = sqlite3.connect(source, isolation_level=None)
    writer.execute("INSERT INTO users (name) VALUES ('later')")
    writer.close()
    assert sorted(path.name for path in volume.iterdir()) == ["source.sqlite3"]


def test_the_owner_is_the_uid_and_gid_of_the_file(tmp_path):
    """#461 M5: the owner answers the file's uid:gid."""
    source = _database(tmp_path / "source.sqlite3")

    assert sqlite_copy.owner(source) == f"{os.getuid()}:{os.getgid()}"


def test_a_corrupt_copy_fails_the_check(tmp_path):
    """#461 A4 M9: a corrupt copy fails the integrity check."""
    copied = _copied(_database(tmp_path / "source.sqlite3", rows=500), tmp_path / "copy.sqlite3")
    data = bytearray(copied.read_bytes())
    data[len(data) // 2 : len(data) // 2 + 4096] = b"\xff" * 4096
    copied.write_bytes(data)

    with pytest.raises(sqlite3.DatabaseError):
        sqlite_copy.check(copied, "users")


def test_the_check_of_a_database_with_no_rows_answers_zero(tmp_path):
    """#461 M13: an empty table counts zero."""
    copied = _copied(_database(tmp_path / "source.sqlite3", rows=0), tmp_path / "copy.sqlite3")

    assert sqlite_copy.check(copied, "users") == 0


def test_the_check_never_modifies_the_copy(tmp_path):
    """#461 A9 M12: the check leaves the copy unmodified."""
    copied = _copied(_database(tmp_path / "source.sqlite3"), tmp_path / "copy.sqlite3")
    before = copied.read_bytes()

    sqlite_copy.check(copied, "users")

    assert copied.read_bytes() == before
    assert not [path for path in tmp_path.iterdir() if path.name.startswith("copy.sqlite3-")]


def _run_script(*arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-I", sqlite_copy.__file__, *arguments], capture_output=True, check=False
    )


def test_the_script_prints_a_count_and_nothing_else(tmp_path):
    """#461 M15: the check prints the count and no row value."""
    copied = _copied(_database(tmp_path / "source.sqlite3", rows=4), tmp_path / "copy.sqlite3")

    result = _run_script("check", str(copied), "users")

    assert (result.returncode, result.stdout) == (0, b"4\n")
    assert b"secret-name" not in result.stdout + result.stderr


def test_the_script_copies_the_bytes_to_stdout(tmp_path):
    """#461 A2: the script's copy arrives as bytes on stdout."""
    source = _database(tmp_path / "source.sqlite3", rows=2)

    result = _run_script("copy", str(source))

    assert result.returncode == 0
    copied = tmp_path / "copy.sqlite3"
    copied.write_bytes(result.stdout)
    assert sqlite_copy.check(copied, "users") == 2


def test_the_script_fails_quietly_on_a_missing_file(tmp_path):
    """#461 A3 M8 M15: a missing file exits with the verdict, silently."""
    result = _run_script("copy", str(tmp_path / "missing.sqlite3"))

    assert (result.returncode, result.stdout) == (sqlite_copy.VERDICT_EXIT, b"")
    assert list(tmp_path.iterdir()) == []


# The app record and the runner, through the scripted Docker host.

SQLITE_RECORD = SQLITE_TOML.strip().splitlines()


def _mounts(argv: list[str]) -> list[str]:
    return [argv[i + 1] for i, argument in enumerate(argv) if argument == "--mount"]


def _record_with(*extra_lines: str, without: str | None = None) -> str:
    lines = [line for line in SQLITE_RECORD if without is None or not line.startswith(without)]
    lines.insert(1, "\n".join(extra_lines))
    return "\n".join(lines)


def test_a_sqlite_record_parses_into_the_sqlite_variant():
    """#461 A1 M1: a SQLite record parses into its variant."""
    [app] = parse_apps(SQLITE_TOML)

    assert app.database == SqliteDatabase("database", "presentator.sqlite3")
    assert (app.name, app.compose_project, app.restore_test.count_table) == (
        "presentator",
        "presentator",
        "users",
    )


@pytest.mark.parametrize(
    "key_line",
    [
        'db_user = "presentator"',
        "postgres_major = 16",
        'volume = "audiofiles"',
        'db_service = "postgres"',
    ],
)
def test_a_sqlite_record_refuses_the_postgres_keys(key_line):
    """#461 A1 M2: a SQLite record refuses the Postgres keys."""
    toml = _record_with(key_line)

    with pytest.raises(AppsError, match="unknown key; only"):
        parse_apps(toml)


def test_a_sqlite_record_refuses_audio_references():
    """#461 A1 M2: a SQLite record refuses audio references."""
    toml = SQLITE_TOML + 'audio_reference_table = "generations"\n'

    with pytest.raises(AppsError, match="unknown key; only"):
        parse_apps(toml)


@pytest.mark.parametrize("missing", ["database_volume", "database_file"])
def test_a_sqlite_record_needs_its_volume_and_file(missing):
    """#461 A1: a SQLite record needs its volume and file."""
    toml = _record_with(without=missing)

    with pytest.raises(AppsError, match=missing):
        parse_apps(toml)


@pytest.mark.parametrize(
    "file_name",
    ["", "é.sqlite3", "a/b.sqlite3", "../db", ".hidden", "a?b", "a%2fb", "a#b", "x" * 129],
)
def test_a_sqlite_record_refuses_a_file_name_that_is_not_one_plain_segment(file_name):
    """#461 A1 M3: the file name is one plain segment."""
    toml = SQLITE_TOML.replace("presentator.sqlite3", file_name)

    with pytest.raises(AppsError, match="database_file must match"):
        parse_apps(toml)


def test_a_postgres_record_refuses_the_sqlite_keys():
    """#461 A1 M2: a Postgres record refuses the SQLite keys."""
    toml = SONGMAKER_TOML.replace("[app.songmaker]\n", '[app.songmaker]\ndatabase_file = "x"\n')

    with pytest.raises(AppsError, match="unknown key; only"):
        parse_apps(toml)


@pytest.fixture
def declared(machine, home):
    machine.other_volumes["presentator"] = ["presentator_database"]
    return declare_apps(home, SONGMAKER_TOML + SQLITE_TOML)


def _sqlite_apps(home) -> tuple[str, str]:
    return declare_apps(home, SQLITE_TOML)


def test_a_sqlite_backup_stages_the_copy_and_a_manifest_with_the_rows(
    edge_backup, machine, home, declared
):
    """#461 A5 M10: a backup stages the copy and a manifest with rows."""
    outcome = edge_backup("backup", *declared)

    assert outcome.exit_code == 0, outcome.err
    snapshot = next(s for s in machine.snapshots if s["app"] == "presentator")
    assert snapshot["db"]["db.sqlite3"] == SQLITE_COPY
    assert json.loads(snapshot["db"]["manifest.json"]) == {
        "schema": 1,
        "app": "presentator",
        "audio_files": None,
        "rows": 7,
    }
    assert snapshot["audio"] == {}
    assert app_history(outcome.status, "presentator")["last_snapshot_id"] == snapshot["id"]
    assert list((home / ".cache/edge-backup").iterdir()) == []


def test_the_copy_runs_hardened_as_the_database_owner_with_exactly_the_one_volume(
    edge_backup, machine, home
):
    """#461 A6 M5: the copy runs hardened with exactly the one volume."""
    machine.other_volumes["presentator"] = ["presentator_database"]
    edge_backup("backup", *_sqlite_apps(home))

    argv = machine.argv_of(SQLITE_COPY_LABEL)

    assert argv[:2] == ["docker", "run"]
    assert SQLITE_IMAGE in argv
    for flag, value in [
        ("--network", "none"),
        ("--user", "1001:1001"),
        ("--log-driver", "none"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges"),
    ]:
        assert argv[argv.index(flag) + 1] == value
    assert "--read-only" in argv
    assert [a for a in argv if a.startswith("type=volume")] == [
        "type=volume,source=presentator_database,target=/data"
    ]
    assert _mounts(argv)[0].endswith("target=/sqlite_copy.py,readonly")
    assert argv[argv.index(SQLITE_IMAGE) + 1 :] == [
        "-I",
        "/sqlite_copy.py",
        "copy",
        "/data/presentator.sqlite3",
    ]


def test_the_owner_is_read_through_a_read_only_mount_as_the_operator(edge_backup, machine, home):
    """#461 A6 M5: the owner is read through a read-only mount."""
    machine.other_volumes["presentator"] = ["presentator_database"]
    edge_backup("backup", *_sqlite_apps(home))

    argv = machine.argv_of(SQLITE_OWNER_LABEL)

    assert argv[argv.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    assert next(m for m in _mounts(argv) if "target=/data" in m).endswith(",readonly")


@pytest.mark.parametrize("owner", [b"0:0\n", b"garbage\n", b""])
def test_an_owner_that_is_root_or_unreadable_is_refused_before_any_copy(
    edge_backup, machine, home, owner
):
    """#461 M6: a root or unreadable owner fails that app before any copy."""
    machine.other_volumes["presentator"] = ["presentator_database"]
    machine.sqlite_owner = owner

    outcome = edge_backup("backup", *declare_apps(home, SQLITE_TOML + SONGMAKER_TOML))

    assert outcome.exit_code == 3
    assert SQLITE_COPY_LABEL not in machine.labels()
    assert [s["app"] for s in machine.snapshots] == ["songmaker"]
    assert (outcome.status["failing_app"], outcome.status["exit_category"]) == (
        "presentator",
        "configuration",
    )


@pytest.mark.parametrize("volumes", [[], ["presentator_database", "other_database"]])
def test_zero_or_two_matching_volumes_fail_that_app_and_the_others_still_back_up(
    edge_backup, machine, home, volumes
):
    """#461 M4: zero or two volumes fail only that app."""
    machine.other_volumes["presentator"] = volumes

    outcome = edge_backup("backup", *declare_apps(home, SONGMAKER_TOML + SQLITE_TOML))

    assert outcome.exit_code == 3
    assert [s["app"] for s in machine.snapshots] == ["songmaker"]
    assert outcome.status["failing_app"] == "presentator"
    assert outcome.status["exit_category"] == "configuration"
    assert SQLITE_COPY_LABEL not in machine.labels()


def test_a_missing_database_file_fails_that_app_and_the_others_still_back_up(
    edge_backup, machine, home, declared
):
    """#461 A3 M8: a missing file fails only that app."""
    machine.sqlite_copy = None

    outcome = edge_backup("backup", *declared)

    assert outcome.exit_code == 3
    assert [s["app"] for s in machine.snapshots] == ["songmaker"]
    assert (outcome.status["failing_app"], outcome.status["failing_phase"]) == (
        "presentator",
        "dump",
    )
    assert list((home / ".cache/edge-backup").iterdir()) == []


def test_a_staged_copy_that_fails_the_check_never_reaches_restic(edge_backup, machine, home):
    """#461 A4 M9: a failed check never reaches restic."""
    machine.other_volumes["presentator"] = ["presentator_database"]
    machine.sqlite_copy = b"torn"

    outcome = edge_backup("backup", *_sqlite_apps(home))

    assert outcome.exit_code == 3
    assert (outcome.status["failing_phase"], outcome.status["exit_category"]) == (
        "manifest",
        "verification-failed",
    )
    assert "restic backup" not in machine.labels()
    assert machine.snapshots == []


@pytest.mark.parametrize(
    "failure",
    [{"sqlite_copy": None}, {"sqlite_copy_fails": True}, {"sqlite_copy": b"torn"}],
    ids=["owner", "copy", "check"],
)
def test_a_failing_sqlite_run_shows_no_path_or_row_value_in_stderr(
    edge_backup, machine, home, failure
):
    """#461 M5 M15: the script's stderr is discarded, so no path or row value is shown."""
    machine.other_volumes["presentator"] = ["presentator_database"]
    machine.sqlite_diagnostic = "unable to open /data/presentator.sqlite3: row secret-name"
    for field_name, value in failure.items():
        setattr(machine, field_name, value)

    outcome = edge_backup("backup", *_sqlite_apps(home))

    assert outcome.exit_code == 3
    assert "/data/" not in outcome.err
    assert "secret-name" not in outcome.err


@pytest.fixture
def backed_up(edge_backup, machine, home):
    machine.other_volumes["presentator"] = ["presentator_database"]
    apps = _sqlite_apps(home)
    assert edge_backup("backup", *apps).exit_code == 0
    return apps


def test_the_restore_test_passes_on_the_manifests_count(edge_backup, machine, backed_up):
    """#461 A5 M11: the restore test passes on the manifest's count."""
    outcome = edge_backup("restore", "--test", *backed_up)

    assert outcome.exit_code == 0, outcome.err
    assert app_history(outcome.status, "presentator")["last_successful_restore_test"]


def test_the_restore_test_mounts_no_volume_and_the_restored_directory_read_only(
    edge_backup, machine, backed_up
):
    """#461 A6 M12: the restore test mounts no volume."""
    edge_backup("restore", "--test", *backed_up)

    argv = machine.argv_of(SQLITE_CHECK_LABEL)

    assert not [a for a in argv if a.startswith("type=volume")]
    assert next(m for m in _mounts(argv) if "target=/data" in m).endswith(",readonly")
    assert argv[argv.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    assert SERVER_START_LABEL not in machine.labels()


def _change_snapshot(machine: Machine, **replacements: bytes) -> None:
    machine.snapshots[-1]["db"].update(replacements)


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param(lambda m: _change_snapshot(m, **{"db.sqlite3": b"SQLite rows=8"}), id="count"),
        pytest.param(
            lambda m: _change_snapshot(
                m, **{"manifest.json": b'{"schema": 1, "app": "presentator", "audio_files": null}'}
            ),
            id="no-rows-in-the-manifest",
        ),
        pytest.param(lambda m: _change_snapshot(m, **{"db.sqlite3": b"torn"}), id="integrity"),
    ],
)
def test_the_restore_test_fails_on_a_different_count_a_missing_rows_or_a_bad_copy(
    edge_backup, machine, backed_up, tamper
):
    """#461 A5 M11: a different count, missing rows or a bad copy fail."""
    tamper(machine)

    assert_the_restore_test_fails_verification(edge_backup, backed_up)


@pytest.mark.parametrize(("require_rows", "exit_code"), [(False, 0), (True, 3)])
def test_an_empty_table_passes_unless_the_record_requires_rows(
    edge_backup, machine, home, require_rows, exit_code
):
    """#461 M13: an empty table passes unless rows are required."""
    machine.other_volumes["presentator"] = ["presentator_database"]
    machine.sqlite_copy = b"SQLite rows=0"
    toml = SQLITE_TOML + ("require_rows = true\n" if require_rows else "")
    apps = declare_apps(home, toml)
    assert edge_backup("backup", *apps).exit_code == 0

    assert edge_backup("restore", "--test", *apps).exit_code == exit_code


@pytest.mark.parametrize("exit_code", [1, 125])
def test_a_container_that_will_not_run_is_a_failed_command_not_a_verification(
    edge_backup, machine, backed_up, exit_code
):
    """#461 M11: only the script's verdict exit is a verification failure, not a crash."""
    machine.failing[SQLITE_CHECK_LABEL] = exit_code

    outcome = edge_backup("restore", "--test", *backed_up)

    assert outcome.status["exit_category"] == "command-failed"


def test_a_missing_database_file_is_named_without_a_path_or_a_row_value(edge_backup, machine, home):
    """The owner run's verdict exit says the configured file is missing."""
    machine.other_volumes["presentator"] = ["presentator_database"]
    machine.sqlite_copy = None
    machine.sqlite_diagnostic = "unable to open /data/presentator.sqlite3: row secret-name"

    outcome = edge_backup("backup", *_sqlite_apps(home))

    assert "presentator.sqlite3 is missing or unreadable" in outcome.out
    assert "/data/" not in outcome.out
    assert "secret-name" not in outcome.out
    assert (outcome.status["failing_phase"], outcome.status["exit_category"]) == (
        "dump",
        "command-failed",
    )


def test_an_owner_run_that_fails_for_another_reason_is_not_called_a_missing_file(
    edge_backup, machine, home
):
    """Docker failing to start the owner run says so."""
    machine.other_volumes["presentator"] = ["presentator_database"]
    machine.failing[SQLITE_OWNER_LABEL] = 125

    outcome = edge_backup("backup", *_sqlite_apps(home))

    assert f"{SQLITE_OWNER_LABEL} ended with exit 125" in outcome.out
    assert "is missing or unreadable" not in outcome.out
    assert (outcome.status["failing_phase"], outcome.status["exit_category"]) == (
        "dump",
        "command-failed",
    )


@pytest.mark.parametrize(
    ("toml", "pulled"),
    [
        (SONGMAKER_TOML, False),
        (SQLITE_TOML, True),
        (SONGMAKER_TOML + SQLITE_TOML, True),
    ],
)
def test_the_sqlite_image_is_checked_and_pulled_only_for_a_sqlite_app(
    edge_backup, machine, home, toml, pulled
):
    """#461 M14: the sqlite image is checked only for a SQLite app."""
    machine.missing_images = {SQLITE_IMAGE}
    machine.other_volumes["presentator"] = ["presentator_database"]

    edge_backup("backup", *declare_apps(home, toml))

    assert (
        SQLITE_IMAGE in {argv[-1] for label, argv in machine.calls if label == "docker pull"}
    ) is pulled


def test_the_status_of_a_sqlite_app_has_no_path_and_the_same_keys(edge_backup, machine, home):
    """#461 M15: the status file holds no path."""
    machine.other_volumes["presentator"] = ["presentator_database"]

    outcome = edge_backup("backup", *_sqlite_apps(home))

    assert outcome.status.keys() == STATUS_KEYS
    assert "sqlite3" not in json.dumps(outcome.status)


@pytest.mark.parametrize(
    "manifest",
    [
        '{"schema": 1, "app": "songmaker", "audio_files": 3}',
        '{"schema": 1, "app": "songmaker", "audio_files": null, "rows": 4}',
    ],
)
def test_a_schema_one_manifest_reads_with_or_without_rows(manifest):
    """#461 A7 M10: a schema-1 manifest reads with or without rows."""
    parsed = Manifest.from_json(manifest)

    assert Manifest.from_json(parsed.as_json()) == parsed


def test_a_manifest_of_another_schema_is_refused():
    """#461 M10: another manifest schema is refused."""
    with pytest.raises(VerificationError):
        Manifest.from_json('{"schema": 2, "app": "songmaker", "audio_files": null}')
