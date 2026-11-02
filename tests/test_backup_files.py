"""A SQLite app's files volume: its record, its read-only mount, its count and its restore test."""

import json
import os

import pytest
from support.backup_support import (
    SONGMAKER_TOML,
    SQLITE_TOML,
    STATUS_KEYS,
    Machine,
    app_history,
    assert_the_restore_test_fails_verification,
    declare_apps,
    mount_of,
)

from hal.backup.apps import AppsError, SqliteDatabase, SqliteFiles, parse_apps
from hal.backup.docker import FILE_COUNT_LABEL, SQLITE_OWNER_LABEL

BUILDS = {
    "run1/out/talk/index.html": b"x",
    "run1/out/deck.pdf": b"x",
    "run1/deck/slides.md": b"x",
    "run1/staged-talk/partial": b"x",
    "staged-top/partial": b"x",
}
DATABASE_LINE = 'database_file = "presentator.sqlite3"\n'


def _toml(*lines: str) -> str:
    return SQLITE_TOML.replace(
        DATABASE_LINE, DATABASE_LINE + "".join(line + "\n" for line in lines)
    )


FILES_TOML = _toml('files_volume = "builds"', 'files_skip = "staged-*"')


@pytest.fixture
def builds(machine) -> Machine:
    machine.volumes_by_label = {
        "database": ["presentator_database"],
        "builds": ["presentator_builds"],
    }
    machine.volume_files["presentator_builds"] = dict(BUILDS)
    return machine


def _backup(edge_backup, home, toml: str = FILES_TOML):
    apps = declare_apps(home, toml)
    return apps, edge_backup("backup", *apps)


def test_a_record_with_a_files_volume_parses_with_or_without_a_skip():
    """#468 M1."""
    [with_skip] = parse_apps(FILES_TOML)
    [without_skip] = parse_apps(_toml('files_volume = "builds"'))
    [plain] = parse_apps(SQLITE_TOML)

    assert with_skip.database == SqliteDatabase(
        "database", "presentator.sqlite3", SqliteFiles("builds", "staged-*")
    )
    assert without_skip.database.files == SqliteFiles("builds", None)
    assert plain.database.files is None


@pytest.mark.parametrize(
    ("toml", "message"),
    [
        pytest.param(
            SONGMAKER_TOML.replace("[app.songmaker]\n", '[app.songmaker]\nfiles_volume = "b"\n'),
            "unknown key; only",
            id="on-postgres",
        ),
        pytest.param(_toml('files_skip = "staged-*"'), "files_skip", id="skip-alone"),
    ],
)
def test_a_files_key_is_refused_where_it_has_no_meaning(toml, message):
    """#468 M2."""
    with pytest.raises(AppsError, match=message):
        parse_apps(toml)


@pytest.mark.parametrize(
    "volume",
    ["db", "database", "Builds", "a/b", ""],
    ids=["db", "database", "case", "path", "empty"],
)
def test_a_files_volume_is_a_plain_name_that_collides_with_nothing_in_the_snapshot(volume):
    """#468 M3."""
    toml = _toml(f'files_volume = "{volume}"')

    with pytest.raises(AppsError, match="files_volume"):
        parse_apps(toml)


@pytest.mark.parametrize("skip", ["*", "**", "a/b*", "a?*", "a", "*a", "é*", ""])
def test_a_files_skip_is_one_prefix_and_one_trailing_star(skip):
    """#468 M4."""
    toml = _toml('files_volume = "builds"', f'files_skip = "{skip}"')

    with pytest.raises(AppsError, match="files_skip"):
        parse_apps(toml)


def test_the_files_volume_is_mounted_read_only_with_one_anchored_exclude(edge_backup, builds, home):
    """#468 M5: the database volume never reaches restic."""
    _backup(edge_backup, home)

    argv = builds.argv_of("restic backup")

    assert (
        "type=volume,source=presentator_builds,target=/backup/presentator/builds,readonly" in argv
    )
    assert [a for a in argv if a.startswith("type=volume")] == [
        "type=volume,source=presentator_builds,target=/backup/presentator/builds,readonly"
    ]
    assert argv.count("--exclude") == 1
    assert argv[argv.index("--exclude") + 1] == "/backup/presentator/builds/**/staged-*"


def test_without_a_skip_restic_gets_no_exclude(edge_backup, builds, home):
    """#468 M5."""
    _backup(edge_backup, home, _toml('files_volume = "builds"'))

    assert "--exclude" not in builds.argv_of("restic backup")


def test_the_count_runs_hardened_read_only_with_the_skip_pruned_at_every_depth(
    edge_backup, builds, home
):
    """#468 M6: the backup's count and the restore test's count share one tail."""
    apps, _ = _backup(edge_backup, home)
    edge_backup("restore", "--test", *apps)

    scans = [argv for label, argv in builds.calls if label == FILE_COUNT_LABEL]

    assert [mount_of(argv, "/scanned")["type"] for argv in scans] == ["volume", "bind"]
    assert len({tuple(argv[argv.index("--entrypoint") :]) for argv in scans}) == 1
    tail = scans[0][scans[0].index("/scanned") :]
    assert tail == ["/scanned", "-mindepth", "1", "-name", "staged-*", "-prune", "-o",
                    "-type", "f", "-print0"]  # fmt: skip
    for flag in ("--network", "--read-only", "--cap-drop"):
        assert flag in scans[0]
    assert scans[0][scans[0].index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    assert all(mount_of(argv, "/scanned")["source"] for argv in scans)
    assert all(any(m.endswith("target=/scanned,readonly") for m in argv) for argv in scans)


@pytest.mark.parametrize("volumes", [[], ["presentator_builds", "other_builds"]], ids=["0", "2"])
def test_a_files_volume_that_matches_no_single_volume_fails_that_app_in_readiness(
    edge_backup, builds, home, volumes
):
    """#468 M7: the other apps back up and nothing is staged for the failing one."""
    builds.volumes_by_label["builds"] = volumes
    apps = declare_apps(home, SONGMAKER_TOML + FILES_TOML)

    outcome = edge_backup("backup", *apps)

    assert (outcome.status["failing_app"], outcome.status["failing_phase"]) == (
        "presentator",
        "readiness",
    )
    assert outcome.status["exit_category"] == "configuration"
    assert [s["app"] for s in builds.snapshots] == ["songmaker"]


def test_the_manifest_counts_the_files_beside_the_rows(edge_backup, builds, home):
    """#468 M8: the skipped staged entries are not counted."""
    _, outcome = _backup(edge_backup, home)

    assert outcome.exit_code == 0, outcome.err
    snapshot = builds.snapshots[-1]
    assert json.loads(snapshot["db"]["manifest.json"]) == {
        "schema": 1,
        "app": "presentator",
        "audio_files": None,
        "rows": 7,
        "files": 3,
    }
    assert sorted(snapshot["volumes"]["builds"]) == [
        "run1/deck/slides.md",
        "run1/out/deck.pdf",
        "run1/out/talk/index.html",
    ]


def test_a_manifest_without_a_files_volume_has_no_files_key(edge_backup, builds, home):
    """#468 M8."""
    _backup(edge_backup, home, SQLITE_TOML)

    assert "files" not in json.loads(builds.snapshots[-1]["db"]["manifest.json"])


@pytest.fixture
def backed_up(edge_backup, builds, home):
    apps, outcome = _backup(edge_backup, home)
    assert outcome.exit_code == 0, outcome.err
    return apps


def test_the_restore_test_passes_when_the_restored_count_equals_the_manifests(
    edge_backup, backed_up
):
    """#468 M9."""
    outcome = edge_backup("restore", "--test", *backed_up)

    assert outcome.exit_code == 0, outcome.err


def _add_a_file(machine: Machine) -> None:
    machine.snapshots[-1]["volumes"]["builds"]["run2/out/deck.pdf"] = b"x"


def _lose_the_manifests_count(machine: Machine) -> None:
    machine.snapshots[-1]["db"]["manifest.json"] = json.dumps(
        {"schema": 1, "app": "presentator", "audio_files": None, "rows": 7}
    ).encode()


def _lose_the_folder(machine: Machine) -> None:
    del machine.snapshots[-1]["volumes"]["builds"]


@pytest.mark.parametrize(
    "tamper", [_add_a_file, _lose_the_manifests_count, _lose_the_folder], ids=lambda f: f.__name__
)
def test_the_restore_test_fails_on_a_different_count_a_manifest_without_files_or_no_folder(
    edge_backup, builds, backed_up, tamper
):
    """#468 M9."""
    tamper(builds)

    assert_the_restore_test_fails_verification(edge_backup, backed_up)


def test_the_restore_test_mounts_no_volume_for_the_files_count(edge_backup, builds, backed_up):
    """#468 M10."""
    edge_backup("restore", "--test", *backed_up)

    argv = [argv for label, argv in builds.calls if label == FILE_COUNT_LABEL][-1]

    assert mount_of(argv, "/scanned")["type"] == "bind"
    assert not [a for a in argv if a.startswith("type=volume")]


def test_an_unreadable_entry_fails_the_app_in_manifest_and_backs_up_nothing(
    edge_backup, builds, home
):
    """#468 M11: the other apps back up, and the last good snapshot stays."""
    apps = declare_apps(home, SONGMAKER_TOML + FILES_TOML)
    first = edge_backup("backup", *apps)
    assert first.exit_code == 0
    before = app_history(first.status, "presentator")["last_snapshot_id"]
    builds.unreadable_directories = {"run2/out"}
    builds.volume_files["presentator_builds"] |= {"run2/out/deck.pdf": b"x"}
    builds.snapshots.clear()

    outcome = edge_backup("backup", *apps)

    assert (outcome.status["failing_app"], outcome.status["failing_phase"]) == (
        "presentator",
        "manifest",
    )
    assert outcome.status["exit_category"] == "command-failed"
    assert [s["app"] for s in builds.snapshots] == ["songmaker"]
    assert app_history(outcome.status, "presentator")["last_snapshot_id"] == before


def test_an_unreadable_directory_the_skip_matches_does_not_fail_the_backup(
    edge_backup, builds, home
):
    """#468 A3: a directory the skip leaves out is never entered."""
    builds.unreadable_directories = {"staged-top", "run1/staged-talk"}

    _, outcome = _backup(edge_backup, home)

    assert outcome.exit_code == 0, outcome.err


def test_a_skip_that_is_a_prefix_of_a_plain_name_leaves_out_only_what_it_matches(
    edge_backup, builds, home
):
    """#468 M17: `s*` never prunes the root, so the count is not 0."""
    builds.volume_files["presentator_builds"] = {"run1/out/a": b"x", "run1/skipped": b"x"}

    _, outcome = _backup(edge_backup, home, _toml('files_volume = "builds"', 'files_skip = "s*"'))

    assert outcome.exit_code == 0, outcome.err
    assert json.loads(builds.snapshots[-1]["db"]["manifest.json"])["files"] == 1
    assert sorted(builds.snapshots[-1]["volumes"]["builds"]) == ["run1/out/a"]


def test_no_file_name_of_the_volume_reaches_stdout_or_the_status(edge_backup, builds, home):
    """#468 M13."""
    _, outcome = _backup(edge_backup, home)

    assert "index.html" not in outcome.out + outcome.err
    assert "index.html" not in json.dumps(outcome.status)
    assert set(outcome.status) == STATUS_KEYS
    assert outcome.status["schema"] == 2


def test_a_missing_database_file_is_named_without_a_path_or_a_row_value(edge_backup, machine, home):
    """#468 M16: the owner run's verdict exit says the configured file is missing."""
    machine.other_volumes["presentator"] = ["presentator_database"]
    machine.sqlite_copy = None
    machine.sqlite_diagnostic = "unable to open /data/presentator.sqlite3: row secret-name"

    outcome = edge_backup("backup", *declare_apps(home, SQLITE_TOML))

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
    """#468 M16: docker failing to start the owner run says so."""
    machine.other_volumes["presentator"] = ["presentator_database"]
    machine.failing[SQLITE_OWNER_LABEL] = 125

    outcome = edge_backup("backup", *declare_apps(home, SQLITE_TOML))

    assert f"{SQLITE_OWNER_LABEL} ended with exit 125" in outcome.out
    assert "is missing or unreadable" not in outcome.out
    assert (outcome.status["failing_phase"], outcome.status["exit_category"]) == (
        "dump",
        "command-failed",
    )
