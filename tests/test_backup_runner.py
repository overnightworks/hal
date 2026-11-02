"""`hal backup` and `hal restore` driven through hal, with a scripted Docker host in place of
docker and restic."""

import itertools
import json
import re
import tempfile
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from support.backup_support import (
    APP_HISTORY_KEYS,
    AUDIO,
    CANARY_PASSWORD,
    DUMP,
    RADIO_TOML,
    RESTORE_SERVER_ID,
    SONGMAKER_CONTAINER,
    STATUS_KEYS,
    Machine,
    app_history,
    declare_apps,
    declare_shipped_apps,
    declare_two_apps,
    mode_of,
    mount_of,
    mount_source,
    no_restore_server_left,
    removed_servers,
)

from hal.backup import cli, docker, host
from hal.backup.apps import AppsError, PostgresMajor, parse_apps
from hal.backup.docker import RESTORE_OWNER_LABEL, RESTORE_OWNER_ROLE
from hal.backup.runner import RUN_MARK_SUFFIX, STAGING_PREFIX
from hal.backup.settings import RESTIC_IMAGE, RESTORE_IMAGES


def test_backup_puts_dump_manifest_and_audio_into_one_snapshot(edge_backup, machine, home):
    outcome = edge_backup("backup")

    assert outcome.exit_code == 0, outcome.err
    [snapshot] = machine.snapshots
    assert snapshot["db"] == {"db.dump": DUMP, "manifest.json": snapshot["db"]["manifest.json"]}
    assert json.loads(snapshot["db"]["manifest.json"]) == {
        "schema": 1,
        "app": "songmaker",
        "audio_files": len(AUDIO),
    }
    assert snapshot["audio"] == AUDIO
    assert outcome.status["state"] == "ok"
    assert app_history(outcome.status)["last_snapshot_id"] == snapshot["id"]
    assert app_history(outcome.status)["last_successful_backup"] == "2026-10-18T03:00:00+00:00"
    assert list((home / ".cache/edge-backup").iterdir()) == []


def test_backup_forgets_by_host_and_app_tag_then_checks(edge_backup, machine):
    edge_backup("backup")

    assert machine.labels()[-2:] == ["restic forget", "restic check"]
    forget = machine.argv_of("restic forget")
    expected_scope = ["--host", "hal", "--tag", "songmaker", "--group-by", "host,tags"]
    assert forget[forget.index("forget") + 1 :] == [
        *expected_scope,
        *["--keep-weekly", "4", "--keep-monthly", "3", "--keep-tag", "pre-apply", "--prune"],
    ]
    assert "--retry-lock" in forget
    assert "--no-lock" not in forget


def test_backup_of_one_app_touches_only_that_app(edge_backup, machine, home):
    """#238 matrix cell 1."""
    outcome = edge_backup(*declare_two_apps(home), "backup", "radio")

    assert outcome.exit_code == 0, outcome.err
    assert [snapshot["app"] for snapshot in machine.snapshots] == ["radio"]
    assert machine.labels().count("pg_dump") == 1
    assert machine.argv_of("restic forget")[
        machine.argv_of("restic forget").index("--tag") + 1
    ] == ("radio")
    assert list(outcome.status["apps"]) == ["radio"]


def test_restore_test_of_one_app_keeps_the_other_apps_status_and_reads_no_data(
    edge_backup, machine, home
):
    """#238 matrix cell 2."""
    two_apps = declare_two_apps(home)
    edge_backup(*two_apps, "backup")
    songmaker_before = app_history(edge_backup(*two_apps, "restore", "--list").status)
    machine.calls.clear()

    outcome = edge_backup(*two_apps, "restore", "--test", "radio")

    assert outcome.exit_code == 0, outcome.err
    assert machine.labels().count("restic restore") == 1
    [check] = [argv for label, argv in machine.calls if label == "restic check"]
    assert check[check.index("check") + 1 :] == []
    assert app_history(outcome.status, "radio")["last_successful_restore_test"] is not None
    assert app_history(outcome.status) == songmaker_before


def test_restore_test_with_a_snapshot_tests_that_one_not_the_one_the_status_names(
    edge_backup, machine, home
):
    """#242: a backup in between must not swap the snapshot under test."""
    two_apps = declare_two_apps(home)
    edge_backup(*two_apps, "backup", "radio", "--pre-apply")
    chosen = machine.snapshots[-1]["id"]
    edge_backup(*two_apps, "backup", "radio")
    machine.calls.clear()

    outcome = edge_backup(*two_apps, "restore", "--test", "radio", "--snapshot", chosen)

    assert outcome.exit_code == 0, outcome.err
    assert machine.argv_of("restic restore")[-3].split(":")[0] == chosen
    assert chosen != machine.snapshots[-1]["id"]


def test_pre_apply_backup_tags_the_snapshot_prints_its_id_and_thins_only_pre_apply(
    edge_backup, machine, home
):
    """#238 matrix cell 3 and ruling R1."""
    outcome = edge_backup(*declare_two_apps(home), "backup", "radio", "--pre-apply")

    assert outcome.exit_code == 0, outcome.err
    assert f"{machine.snapshots[-1]['id'][:8]} · 4.2 MiB · <1s" in outcome.out.splitlines()[0]
    backup = machine.argv_of("restic backup")
    assert backup[backup.index("--tag") + 1] == "radio,pre-apply"
    forget = machine.argv_of("restic forget")
    assert forget[forget.index("forget") + 1 :] == [
        *["--host", "hal", "--tag", "radio,pre-apply", "--group-by", "host,tags"],
        *["--keep-last", "10", "--prune"],
    ]


def test_an_app_named_like_the_pre_apply_tag_is_refused_before_anything_runs(
    edge_backup, machine, home
):
    """Its tag scope would select every app's pre-apply snapshots under `forget`."""
    pre_apply_app = RADIO_TOML.replace("app.radio", "app.pre-apply")

    outcome = edge_backup(*declare_apps(home, pre_apply_app), "backup", "pre-apply")

    assert (outcome.exit_code, machine.calls) == (3, [])
    assert "taken by the restic tag pre-apply" in outcome.err
    assert outcome.status is None


def test_dump_runs_fixed_pg_dump_in_the_container_found_by_compose_labels(edge_backup, machine):
    edge_backup("backup")

    assert machine.argv_of("docker ps") == [
        "docker", "ps", "--all", "--quiet", "--no-trunc",
        "--filter", "label=com.docker.compose.project=songmaker",
        "--filter", "label=com.docker.compose.service=postgres",
        "--filter", "label=com.docker.compose.oneoff=False",
    ]  # fmt: skip
    assert machine.argv_of("pg_dump") == [
        "docker", "exec", "-i", SONGMAKER_CONTAINER, "pg_dump",
        "--username", "songmaker", "--format=custom", "--dbname", "songmaker",
    ]  # fmt: skip


def test_every_container_runs_a_digest_pinned_image(edge_backup, machine):
    shipped = declare_shipped_apps()
    edge_backup(*shipped, "backup")
    edge_backup(*shipped, "restore", "--test")

    images = {argument for _, argv in machine.calls for argument in argv if "@sha256:" in argument}
    docker_runs = [argv for _, argv in machine.calls if argv[:2] == ["docker", "run"]]
    assert images == {RESTIC_IMAGE, *RESTORE_IMAGES.values()}
    assert all(any(image in argv for image in images) for argv in docker_runs)


def test_status_says_running_while_the_backup_runs(edge_backup, machine):
    edge_backup("backup")

    assert machine.status_seen_during_backup["state"] == "running"
    assert machine.status_seen_during_backup["phase"] == "backup"


def test_restore_test_restores_loads_and_verifies_the_latest_snapshot(edge_backup, machine, home):
    edge_backup("backup")
    backed_up = app_history(edge_backup("backup").status)["last_successful_backup"]

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 0, outcome.err
    assert outcome.status["state"] == "ok"
    # The throwaway server answered the second pg_isready poll, one second in.
    assert (
        app_history(outcome.status)["last_successful_restore_test"] == "2026-10-18T03:00:01+00:00"
    )
    assert app_history(outcome.status)["last_successful_backup"] == backed_up
    restore = machine.argv_of("restic restore")
    assert f"{machine.snapshots[-1]['id']}:/backup/songmaker" in restore
    assert machine.argv_of("pg_restore") == [
        "docker", "exec", "-i", RESTORE_SERVER_ID, "pg_restore", "--exit-on-error",
        "--single-transaction", "--no-owner", "--no-privileges",
        "--username", "postgres", "--dbname", "restore_test",
    ]  # fmt: skip
    assert machine.labels()[-1] == "restic check"
    assert machine.labels().count("pg_isready") == 2
    assert no_restore_server_left(machine)
    assert list((home / ".cache/edge-backup").iterdir()) == []


def test_the_restored_audio_is_counted_by_the_manifests_own_rule(edge_backup, machine):
    edge_backup("backup")
    edge_backup("restore", "--test")

    scans = [argv for label, argv in machine.calls if label == docker.FILE_COUNT_LABEL]
    assert [mount_of(argv, "/scanned")["type"] for argv in scans] == ["volume", "bind"]
    assert len({tuple(argv[argv.index("--entrypoint") :]) for argv in scans}) == 1
    assert all(any(m.endswith("target=/scanned,readonly") for m in argv) for argv in scans)


def test_restore_test_removes_only_throwaway_servers_it_owns_by_id(edge_backup, machine):
    machine.leftover_servers = ["1eft0ver"]
    edge_backup("backup")

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 0, outcome.err
    assert removed_servers(machine) == ["1eft0ver", RESTORE_SERVER_ID]
    start = machine.argv_of(docker.SERVER_START_LABEL)
    assert start[start.index("--label") + 1] == f"{RESTORE_OWNER_LABEL}={RESTORE_OWNER_ROLE}"


def test_restore_test_never_removes_a_foreign_container_holding_the_name(edge_backup, machine):
    machine.foreign_server_name = True
    edge_backup("backup")

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 3
    assert f"{docker.SERVER_START_LABEL} ended with exit 125" in outcome.out
    assert removed_servers(machine) == []


@pytest.mark.parametrize(
    ("output", "complaint"),
    [
        (b"", "docker run reported no container id"),
        (f"WARNING: platform mismatch\n{RESTORE_SERVER_ID}\n".encode(), "no container id"),
        (b"not-a-container-id\n", "docker run reported no container id"),
        (b"\xff\xfe\n", "docker printed output that is not UTF-8"),
    ],
)
def test_a_started_throwaway_server_is_removed_even_when_its_id_is_unreadable(
    edge_backup, machine, output, complaint
):
    machine.server_start_output = output
    edge_backup("backup")

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 3
    assert complaint in outcome.out
    assert removed_servers(machine) == [RESTORE_SERVER_ID]


def test_monthly_check_reads_a_tenth_of_the_data(edge_backup, machine):
    edge_backup("backup")
    edge_backup("restore", "--test")

    checks = [argv for label, argv in machine.calls if label == "restic check"]
    assert [argv[argv.index("check") + 1 :] for argv in checks] == [
        [],
        ["--read-data-subset=10%"],
    ]


def test_the_throwaway_server_has_no_network_and_never_touches_live_data(edge_backup, machine):
    edge_backup("backup")
    edge_backup("restore", "--test")

    start = machine.argv_of(docker.SERVER_START_LABEL)
    assert start[start.index("--network") + 1] == "none"
    assert not any("--mount" in argv or "-v" in argv for argv in [start])
    # #107 T10: the server keeps no log and logs no error, so no row value reaches one.
    assert start[start.index("--log-driver") + 1] == "none"
    assert start[-4:] == [
        "-c", "log_min_messages=panic", "-c", "log_min_error_statement=panic",
    ]  # fmt: skip
    restore_test_calls = machine.calls[machine.labels().index("restic snapshots") :]
    assert not any(SONGMAKER_CONTAINER in argv for _, argv in restore_test_calls)
    assert not any("songmaker_audiofiles" in " ".join(argv) for _, argv in restore_test_calls)


@pytest.mark.parametrize(
    ("failing_label", "exit_code", "phase", "backup_counts"),
    [
        ("pg_dump", 1, "dump", False),
        (docker.FILE_COUNT_LABEL, 1, "manifest", False),
        ("restic backup", 3, "backup", False),
        ("restic backup", 1, "backup", False),
        ("restic forget", 1, "forget", True),
        ("restic check", 1, "check", True),
    ],
)
def test_a_failed_backup_step_fails_loud_and_never_counts_as_success(
    edge_backup, machine, home, failing_label, exit_code, phase, backup_counts
):
    machine.failing[failing_label] = exit_code

    outcome = edge_backup("backup")

    assert outcome.exit_code == 3
    assert outcome.err.startswith("error: ")
    assert f"{failing_label} ended with exit {exit_code}" in outcome.out + outcome.err
    assert outcome.status["state"] == "failed"
    assert outcome.status["failing_phase"] == phase
    assert outcome.status["exit_category"] == "command-failed"
    assert ("last_successful_backup" in app_history(outcome.status)) is backup_counts
    if not backup_counts:
        assert "restic forget" not in machine.labels()
    assert list((home / ".cache/edge-backup").iterdir()) == []


@pytest.mark.parametrize(
    "command",
    [
        ("backup", "--init"),
        ("backup",),
        ("restore", "--test"),
        ("restore", "--list"),
        ("backup", "--unlock"),
        ("restore", "songmaker", "--target", "restored"),
    ],
    ids=" ".join,
)
def test_every_repository_command_holds_the_host_lock(
    edge_backup, machine, home, monkeypatch, command
):
    monkeypatch.chdir(home)
    edge_backup("backup")
    machine.calls.clear()

    outcome = edge_backup(*command)

    assert outcome.exit_code == 0, outcome.err
    assert machine.calls
    assert machine.lock_free_during == set()


def test_staging_and_restore_directories_and_their_files_are_private(edge_backup, machine):
    edge_backup("backup")
    edge_backup("restore", "--test")

    assert machine.private_modes == {
        "staging": 0o700,
        "db.dump": 0o600,
        "manifest.json": 0o600,
        "restored": 0o700,
    }


@pytest.mark.parametrize(
    ("argv", "exit_code", "message"),
    [
        (["sh", "-c", "exit 3"], 3, "probe ended with exit 3"),
        (["sh", "-c", "exit 1"], 1, "probe ended with exit 1"),
        (["edge-backup-no-such-binary"], None, "probe is not installed"),
    ],
)
def test_host_run_fails_on_every_nonzero_exit_and_a_missing_binary(argv, exit_code, message):
    with pytest.raises(host.HostCommandError, match=message) as raised:
        host.run(argv, label="probe")

    assert raised.value.exit_code == exit_code


def test_host_run_kills_a_command_that_outlasts_its_timeout():
    timeout = timedelta(milliseconds=50)

    with pytest.raises(
        host.HostCommandError, match=re.escape("probe did not answer within 0.05 s")
    ):
        host.run(["sleep", "5"], label="probe", timeout=timeout)


def test_host_run_returns_stdout_or_writes_it_into_a_new_private_file(tmp_path):
    target = tmp_path / "out"

    assert host.run(["printf", "piped"], label="probe") == b"piped"
    host.run(["printf", "filed"], label="probe", stdout=target)

    assert (target.read_bytes(), mode_of(target)) == (b"filed", 0o600)
    with pytest.raises(FileExistsError):
        host.run(["printf", "again"], label="probe", stdout=target)
    assert target.read_bytes() == b"filed"


def _fail_radio_readiness(machine: Machine) -> None:
    machine.other_db_containers["radio"] = ["beef01", "beef02"]


def test_an_app_that_fails_to_back_up_keeps_the_others_and_every_earlier_success(
    edge_backup, machine, home
):
    """#71 rule 3: a failed app keeps its own history and the other apps still back up."""
    two_apps = declare_two_apps(home)
    first = edge_backup(*two_apps, "backup")
    assert first.exit_code == 0, first.err
    assert first.status["failing_app"] is None
    machine.calls.clear()
    _fail_radio_readiness(machine)
    machine.clock.moment += timedelta(days=7)

    outcome = edge_backup(*two_apps, "backup")

    assert outcome.exit_code == 3
    assert (outcome.status["failing_app"], outcome.status["failing_phase"]) == (
        "radio",
        "readiness",
    )
    assert app_history(outcome.status, "radio") == app_history(first.status, "radio")
    songmaker = app_history(outcome.status)
    assert songmaker["last_snapshot_id"] == machine.snapshots[-1]["id"]
    assert songmaker["last_successful_backup"] > app_history(first.status)["last_successful_backup"]
    assert "restic forget" not in machine.labels()


def test_backup_continues_with_the_next_app_after_one_failed(edge_backup, machine, home):
    """#71 rule 3: the next app is backed up after one failed."""
    two_apps = declare_two_apps(home)
    machine.db_containers = ["c0ffee", "c0ffee2"]

    outcome = edge_backup(*two_apps, "backup")

    assert outcome.status["failing_app"] == "songmaker"
    assert list(outcome.status["apps"]) == ["radio"]
    assert [snapshot["app"] for snapshot in machine.snapshots] == ["radio"]


@pytest.mark.parametrize("repository_exit_code", [10, 11, 12])
def test_a_repository_failure_stops_the_run_before_the_next_app(
    edge_backup, machine, home, repository_exit_code
):
    """#71 rule 3: a shared repository failure aborts the run and belongs to no app."""
    machine.failing["restic backup"] = repository_exit_code

    outcome = edge_backup(*declare_two_apps(home), "backup")

    assert outcome.exit_code == 3
    assert (outcome.status["state"], outcome.status["failing_app"]) == ("failed", None)
    assert machine.labels().count("pg_dump") == 1
    assert "restic forget" not in machine.labels()


@pytest.mark.parametrize("restic_like_exit_code", [10, 11, 12])
def test_an_app_command_that_exits_like_restic_fails_only_its_app(
    edge_backup, machine, home, restic_like_exit_code
):
    """#71 rule 3: only restic's exit codes mean the repository; an app's own dump fails the app."""
    machine.failing["pg_dump"] = restic_like_exit_code

    outcome = edge_backup(*declare_two_apps(home), "backup")

    assert outcome.exit_code == 3
    assert (outcome.status["state"], outcome.status["failing_app"]) == ("failed", "songmaker")
    assert machine.labels().count("pg_dump") == 2


def test_a_status_write_failure_stops_the_run_before_the_next_app(edge_backup, machine, home):
    """#71 rule 3: a status failure aborts the run at once."""
    arguments = declare_two_apps(home)
    machine.status_unwritable_after_backup = True

    outcome = edge_backup(*arguments, "backup")

    assert outcome.err == "error: unexpected error (PermissionError)\n"

    assert machine.labels().count("pg_dump") == 1
    assert "restic forget" not in machine.labels()


def test_an_app_removed_from_apps_toml_keeps_its_entry(edge_backup, machine, home):
    """#71 rule 8: an app removed from apps.toml keeps its entry unchanged."""
    radio = app_history(edge_backup(*declare_two_apps(home), "backup").status, "radio")

    outcome = edge_backup("backup")

    assert outcome.exit_code == 0, outcome.err
    assert app_history(outcome.status, "radio") == radio


def test_a_failed_check_keeps_the_last_successful_backup(edge_backup, machine):
    machine.failing["restic check"] = 1

    outcome = edge_backup("backup")

    assert outcome.status["state"] == "failed"
    assert app_history(outcome.status)["last_snapshot_id"] == machine.snapshots[-1]["id"]


def test_backup_waits_for_the_database_container_to_appear(edge_backup, machine):
    machine.absent_polls = 3

    outcome = edge_backup("backup")

    assert outcome.exit_code == 0, outcome.err
    assert outcome.status["last_attempt"] == "2026-10-18T03:00:00+00:00"
    assert machine.labels().count("docker ps") == 4


def _never_start_the_database(machine: Machine) -> None:
    machine.absent_polls = 10_000


def _set_the_wall_clock_back_while_waiting(machine: Machine) -> None:
    _never_start_the_database(machine)
    machine.clock.wall_drift_per_sleep = timedelta(hours=-1)


def _hang(label: str) -> Callable[[Machine], None]:
    return lambda machine: machine.hanging.add(label)


@pytest.mark.parametrize(
    ("command", "stall"),
    [
        ("backup", _never_start_the_database),
        ("backup", _set_the_wall_clock_back_while_waiting),
        ("backup", _hang("docker ps")),
        ("restore --test", _hang("docker info")),
    ],
    ids=["database-absent", "wall-clock-set-back", "docker-ps-hangs", "docker-info-hangs"],
)
def test_readiness_gives_up_after_ten_minutes(edge_backup, machine, command, stall):
    stall(machine)

    outcome = edge_backup(*command.split())

    assert outcome.exit_code == 3
    assert "after 10 min" in outcome.out + outcome.err
    assert outcome.status["failing_phase"] == "readiness"
    assert outcome.status["exit_category"] == "not-ready"
    assert not {"pg_dump", "restic restore"} & set(machine.labels())


@pytest.mark.parametrize(
    ("ambiguity", "message"),
    [
        ({"db_containers": ["c0ffee", "c0ffee2"]}, "2 database containers"),
        ({"volumes": []}, "0 volumes audiofiles"),
        ({"volumes": ["a_audiofiles", "b_audiofiles"]}, "2 volumes audiofiles"),
    ],
)
def test_backup_refuses_when_labels_name_more_or_less_than_one_target(
    edge_backup, machine, ambiguity, message
):
    for name, value in ambiguity.items():
        setattr(machine, name, value)

    outcome = edge_backup("backup")

    assert outcome.exit_code == 3
    assert message in outcome.out
    assert outcome.status["exit_category"] == "configuration"
    assert "pg_dump" not in machine.labels()


def _lose_a_file_written_during_the_scan(machine: Machine) -> None:
    machine.written_during_scan = {"u3/new.mp3": b"ID3 new"}


def _reference_a_missing_file(machine: Machine) -> None:
    machine.references = [*machine.references, "u9/gone.mp3"]


def _reference_an_empty_file(machine: Machine) -> None:
    machine.audio = machine.audio | {"u1/half.mp3": b""}
    machine.references = [*machine.references, "u1/half.mp3"]


def _reference_outside_the_audio_volume(machine: Machine) -> None:
    machine.references = [*machine.references, "../db/db.dump"]


def _corrupt_the_dump(machine: Machine) -> None:
    machine.failing["pg_restore"] = 1


def _lose_the_dump(machine: Machine) -> None:
    machine.snapshot_without = {"db.dump"}


def _lose_the_manifest(machine: Machine) -> None:
    machine.snapshot_without = {"manifest.json"}


@pytest.mark.parametrize(
    ("break_backup", "message"),
    [
        (_lose_a_file_written_during_the_scan, "4 audio files restored"),
        (_reference_a_missing_file, "1 of 3 referenced audio files are missing"),
        (_reference_an_empty_file, "1 of 3 referenced audio files are missing"),
        (_reference_outside_the_audio_volume, "1 of 3 referenced audio files are missing"),
        (_corrupt_the_dump, "pg_restore ended with exit 1"),
        (_lose_the_dump, "the snapshot holds no database dump"),
        (_lose_the_manifest, "the snapshot holds no manifest"),
    ],
)
def test_restore_test_fails_when_the_copy_is_not_what_was_backed_up(
    edge_backup, machine, home, break_backup, message
):
    break_backup(machine)
    edge_backup("backup")

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 3
    assert message in outcome.out
    assert outcome.status["state"] == "failed"
    assert outcome.status["failing_phase"] == "verify"
    assert outcome.status["exit_category"] == "verification-failed"
    assert app_history(outcome.status)["last_successful_restore_test"] is None
    assert no_restore_server_left(machine)
    assert list((home / ".cache/edge-backup").iterdir()) == []


@pytest.mark.parametrize(
    "failing_label",
    [docker.FILE_COUNT_LABEL, docker.SERVER_START_LABEL, docker.SERVER_REMOVAL_LABEL],
)
def test_restore_test_counts_a_container_that_will_not_run_as_a_failed_command(
    edge_backup, machine, failing_label
):
    edge_backup("backup")
    machine.failing[failing_label] = 125

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 3
    assert f"{failing_label} ended with exit 125" in outcome.out
    assert outcome.status["failing_phase"] == "verify"
    assert outcome.status["exit_category"] == "command-failed"


def test_restore_test_without_a_snapshot_fails(edge_backup):
    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 3
    assert "no successful backup of songmaker recorded" in outcome.out
    assert outcome.status["failing_phase"] == "restore"


def test_an_interrupted_run_is_failed_and_cleans_up(edge_backup, machine, home):
    edge_backup("backup")
    machine.failing["pg_restore"] = KeyboardInterrupt

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 130
    assert "testing the restore of songmaker\nnext: hal restore --test\n" in outcome.err
    assert outcome.status["state"] == "failed"
    assert outcome.status["exit_category"] == "interrupted"
    assert no_restore_server_left(machine)
    assert list((home / ".cache/edge-backup").iterdir()) == []


def _back_up_once(edge_backup, machine) -> None:
    edge_backup("backup")


def _arrange_nothing(edge_backup, machine) -> None:
    pass


def _make_the_database_ambiguous(edge_backup, machine) -> None:
    machine.db_containers = ["c0ffee", "c0ffee2"]


def _corrupt_the_status_file(edge_backup, machine) -> None:
    machine.status_file.parent.mkdir(parents=True)
    machine.status_file.write_text("{not json")


def _forbid_reading_the_status_file(edge_backup, machine) -> None:
    machine.status_file.parent.mkdir(parents=True)
    machine.status_file.write_text("{}")
    machine.status_file.chmod(0o000)


def _write_undecodable_status(edge_backup, machine) -> None:
    machine.status_file.parent.mkdir(parents=True)
    machine.status_file.write_bytes(b"\xff\xfe{}")


@pytest.mark.parametrize(
    ("arguments", "arrange", "exit_code"),
    [
        (("backup",), _back_up_once, 0),
        (("restore", "--test"), _back_up_once, 0),
        (("backup",), _make_the_database_ambiguous, 3),
        (("restore", "--test"), _arrange_nothing, 3),
        (("--apps", "/nonexistent/apps.toml", "backup"), _arrange_nothing, 3),
        (("--apps", "/nonexistent/apps.toml", "restore", "--test"), _arrange_nothing, 3),
        (("backup",), _corrupt_the_status_file, 3),
        (("backup",), _forbid_reading_the_status_file, 3),
        (("backup",), _write_undecodable_status, 3),
    ],
    ids=[
        "backup-succeeds",
        "restore-test-succeeds",
        "backup-with-an-ambiguous-database",
        "restore-test-without-a-snapshot",
        "backup-without-apps",
        "restore-test-without-apps",
        "backup-with-a-corrupt-status",
        "backup-with-a-status-it-may-not-read",
        "backup-with-a-status-that-is-not-utf-8",
    ],
)
def test_a_run_sweeps_only_the_plaintext_a_killed_run_left_behind(
    edge_backup, machine, home, arguments, arrange, exit_code
):
    arrange(edge_backup, machine)
    work_dir = home / ".cache/edge-backup"
    killed_run = _leave_killed_run_staging(work_dir)
    unmarked = (work_dir / f"{STAGING_PREFIX}foreign", work_dir / "manual")
    for copy in (killed_run, *unmarked):
        (copy / "db").mkdir(parents=True, exist_ok=True)
        (copy / "db/db.dump").write_bytes(DUMP)

    outcome = edge_backup(*arguments)

    assert outcome.exit_code == exit_code, outcome.err
    assert set(work_dir.iterdir()) == set(unmarked)


def _leave_killed_run_staging(work_dir: Path) -> Path:
    """What a run killed outright leaves: its staging and the mark that proves it made it."""
    staging = work_dir / f"{STAGING_PREFIX}killed"
    staging.mkdir(parents=True)
    staging.with_name(staging.name + RUN_MARK_SUFFIX).touch()
    return staging


@pytest.mark.parametrize("command", ["backup", "restore --test"])
def test_a_run_whose_staging_name_is_taken_leaves_that_directory_alone(
    edge_backup, machine, home, monkeypatch, command
):
    _back_up_once(edge_backup, machine)
    work_dir = home / ".cache/edge-backup"
    taken = work_dir / f"{STAGING_PREFIX}taken"
    (taken / "db").mkdir(parents=True)
    (taken / "db/db.dump").write_bytes(DUMP)
    # The first random name every temporary file or directory draws is the one already taken.
    random_names = tempfile._get_candidate_names
    monkeypatch.setattr(
        tempfile, "_get_candidate_names", lambda: itertools.chain(["taken"], random_names())
    )

    outcome = edge_backup(*command.split())

    assert outcome.exit_code == 0, outcome.err
    assert (taken / "db/db.dump").read_bytes() == DUMP
    assert set(work_dir.iterdir()) == {taken}


def test_an_unexpected_error_marks_the_run_failed_and_surfaces(edge_backup, machine):
    machine.failing["restic backup"] = RuntimeError

    outcome = edge_backup("backup")

    assert (outcome.exit_code, outcome.err) == (3, "error: unexpected error (RuntimeError)\n")
    status = json.loads(machine.status_file.read_text())
    assert (status["state"], status["exit_category"]) == ("failed", "internal")


@pytest.fixture
def undeletable_leftover(home) -> Iterator[Path]:
    """A killed run's staging that `rmtree` cannot remove: a read-only directory holding a file."""
    locked = _leave_killed_run_staging(home / ".cache/edge-backup") / "audio/locked"
    locked.mkdir(parents=True)
    (locked / "one.mp3").write_bytes(AUDIO["u1/one.mp3"])
    locked.chmod(0o500)
    yield locked
    locked.chmod(0o700)


@pytest.mark.parametrize("command", ["backup", "restore --test"])
def test_a_sweep_that_cannot_remove_a_leftover_fails_the_run_with_one_line(
    edge_backup, machine, undeletable_leftover, command
):
    outcome = edge_backup(*command.split())

    assert outcome.exit_code == 3
    [line, *_] = outcome.err.splitlines()
    assert "the plaintext of an aborted run cannot be removed" in line
    assert (outcome.status["state"], outcome.status["exit_category"]) == ("failed", "internal")
    assert machine.calls == []


def _remove_password_file(home: Path) -> None:
    (home / ".secrets/restic/password").unlink()


def _make_password_file_readable_by_others(home: Path) -> None:
    (home / ".secrets/restic/password").chmod(0o644)


def _remove_repository(home: Path) -> None:
    (home / "backups/restic/config").unlink()


def _corrupt_apps_toml(home: Path) -> None:
    (home / "apps.toml").write_text("[app.songmaker]\ncompose_project = 1\n")


@pytest.mark.parametrize(
    ("break_setup", "message"),
    [
        (_remove_password_file, "the password file is missing"),
        (_make_password_file_readable_by_others, "mode 600"),
        (_remove_repository, "not initialised"),
        (_corrupt_apps_toml, "apps.toml [app.songmaker]"),
    ],
)
@pytest.mark.parametrize("command", ["backup", "restore --test"])
def test_a_broken_setup_fails_before_touching_docker(
    edge_backup, machine, home, break_setup, message, command
):
    (home / "apps.toml").write_text(cli.DEFAULT_APPS.read_text())
    break_setup(home)

    outcome = edge_backup("--apps", str(home / "apps.toml"), *command.split())

    assert outcome.exit_code == 3
    assert message in outcome.err
    assert outcome.status["state"] == "failed"
    assert outcome.status["exit_category"] == "configuration"
    assert machine.calls == []


def _write_unknown_schema_status(edge_backup, machine) -> None:
    machine.status_file.parent.mkdir(parents=True)
    machine.status_file.write_text(json.dumps({"schema": 3, "state": "ok"}))


def _identity_of(path: Path) -> tuple[int, int, int, int]:
    """Inode, mtime, size and mode: a rewrite or replacement changes at least one."""
    seen = path.stat()
    return seen.st_ino, seen.st_mtime_ns, seen.st_size, seen.st_mode


@pytest.mark.parametrize(
    "break_status",
    [
        _corrupt_the_status_file,
        _forbid_reading_the_status_file,
        _write_undecodable_status,
        _write_unknown_schema_status,
    ],
)
@pytest.mark.parametrize(
    "command",
    [("backup",), ("restore", "--test"), ("restore", "songmaker", "--target", "restored")],
    ids=" ".join,
)
def test_an_unreadable_status_file_is_never_overwritten(
    edge_backup, machine, home, monkeypatch, command, break_status
):
    monkeypatch.chdir(home)
    break_status(edge_backup, machine)
    before = _identity_of(machine.status_file)

    outcome = edge_backup(*command)

    assert outcome.exit_code == 3
    [line, *_] = outcome.err.splitlines()
    assert "status file is unreadable" in line
    assert _identity_of(machine.status_file) == before
    assert machine.calls == []


def test_status_holds_the_contract_keys_and_no_paths_or_output(edge_backup, machine, home):
    machine.failing["restic check"] = 1
    edge_backup(*declare_two_apps(home), "backup")
    status_text = machine.status_file.read_text()
    status = json.loads(status_text)

    assert set(status) == STATUS_KEYS
    assert list(status["apps"]) == ["radio", "songmaker"]
    assert all(set(history) == APP_HISTORY_KEYS for history in status["apps"].values())
    assert str(home) not in status_text
    assert "u1/" not in status_text
    assert "docker" not in status_text


def test_the_password_never_appears_in_argv_output_status_or_errors(edge_backup, machine, home):
    two_apps = declare_two_apps(home)
    edge_backup(*two_apps, "backup")
    edge_backup(*two_apps, "restore", "--test")
    machine.failing["restic backup"] = 3
    failed = edge_backup(*two_apps, "backup")

    every_argv = " ".join(argument for _, argv in machine.calls for argument in argv)
    assert CANARY_PASSWORD not in every_argv
    assert CANARY_PASSWORD not in failed.out + failed.err
    assert CANARY_PASSWORD not in machine.status_file.read_text()
    restic_runs = [argv for label, argv in machine.calls if label.startswith("restic")]
    assert all(
        mount_source(argv, "/run/secrets/restic-password").endswith(".secrets/restic/password")
        and argv[argv.index("--password-file") + 1] == "/run/secrets/restic-password"
        for argv in restic_runs
    )
    assert all(
        any(m.endswith("target=/run/secrets/restic-password,readonly") for m in argv)
        for argv in restic_runs
    )


def test_restic_runs_without_network_privileges_or_a_writable_root(edge_backup, machine):
    edge_backup("backup")

    backup = machine.argv_of("restic backup")
    assert backup[backup.index("--network") + 1] == "none"
    assert backup[backup.index("--hostname") + 1] == "hal"
    assert {"--read-only", "--rm"} <= set(backup)
    assert backup[backup.index("--cap-drop") + 1] == "ALL"
    assert any(m.endswith("target=/backup/songmaker/audio,readonly") for m in backup)


def test_restore_puts_the_last_successful_snapshot_into_a_new_directory(edge_backup, machine, home):
    edge_backup("backup")
    target = home / "restored"

    outcome = edge_backup("restore", "songmaker", "--target", str(target))

    assert outcome.exit_code == 0, outcome.err
    assert (target / "db/db.dump").read_bytes() == DUMP
    assert (target / "audio/u1/one.mp3").read_bytes() == AUDIO["u1/one.mp3"]
    assert edge_backup("restore", "songmaker", "--target", str(target)).exit_code == 3


@pytest.mark.parametrize("target", [f"{STAGING_PREFIX}manual", "manual"])
def test_restore_refuses_a_target_in_the_directory_runs_sweep(edge_backup, machine, home, target):
    edge_backup("backup")
    work_dir = home / ".cache/edge-backup"

    outcome = edge_backup("restore", "songmaker", "--target", str(work_dir / target))

    assert outcome.exit_code == 3
    assert "work directory" in outcome.err
    assert list(work_dir.iterdir()) == []


def test_init_creates_a_private_repository_directory(edge_backup, machine, home):
    (home / "backups/restic/config").unlink()
    (home / "backups/restic").rmdir()

    outcome = edge_backup("backup", "--init")

    assert outcome.exit_code == 0, outcome.err
    assert (home / "backups/restic").stat().st_mode & 0o777 == 0o700
    assert machine.labels() == ["restic init"]


def test_the_projects_apps_toml_parses():
    """#107 T1: the shipped records load through the same parser a scenario text does."""
    assert parse_apps(cli.DEFAULT_APPS.read_text())


@pytest.mark.parametrize(
    "dropped",
    [
        pytest.param(["volume"], id="references-without-a-volume"),
        pytest.param(["audio_reference_table", "audio_reference_column"], id="volume-alone"),
        pytest.param(["audio_reference_column"], id="a-table-without-its-column"),
    ],
)
def test_apps_toml_refuses_audio_that_is_not_declared_whole(dropped):
    """#107 T2: a reference table without a volume (or the reverse) is refused at load."""
    text = "\n".join(
        line
        for line in cli.DEFAULT_APPS.read_text().splitlines()
        if not any(line.startswith(f"{key} =") for key in dropped)
    )

    with pytest.raises(AppsError, match="audio needs volume and audio_reference_table"):
        parse_apps(text)


@pytest.mark.parametrize("major", ["15", "[17]", "true", '"17"'])
def test_apps_toml_refuses_a_postgres_major_without_a_restore_image(major):
    """#107 rule 2: a major that is no pinned plain integer is refused at load."""
    text = cli.DEFAULT_APPS.read_text().replace("postgres_major = 17", f"postgres_major = {major}")

    with pytest.raises(AppsError, match="postgres_major must be one of"):
        parse_apps(text)


def test_the_restore_image_of_major_17_is_the_pin_of_composes_keycloak_db():
    """#107 T9: the major-17 restore pin equals compose.yaml's keycloak-db pin."""
    compose = (cli.DEFAULT_APPS.parents[1] / "compose.yaml").read_text()
    [pinned] = re.findall(r"^  keycloak-db:\n(?:(?!  \S).*\n)*?    image: (\S+)", compose, re.M)

    assert RESTORE_IMAGES[PostgresMajor.SEVENTEEN] == pinned


def test_a_backup_run_saves_the_keycloak_dump_without_any_audio_volume(edge_backup, machine):
    """#107 T3: both dumps are in the repository and keycloak mounts no volume."""
    outcome = edge_backup(*declare_shipped_apps(), "backup")

    assert outcome.exit_code == 0, outcome.err
    keycloak = next(s for s in machine.snapshots if s["app"] == "keycloak")
    assert keycloak["db"].keys() == {"db.dump", "manifest.json"}
    assert json.loads(keycloak["db"]["manifest.json"]) == {
        "schema": 1,
        "app": "keycloak",
        "audio_files": None,
    }
    assert keycloak["audio"] == {}
    assert app_history(outcome.status, "keycloak")["last_snapshot_id"] == keycloak["id"]
    keycloak_backup = next(
        argv for label, argv in machine.calls if label == "restic backup" and "keycloak" in argv
    )
    assert not any("/audio" in argument for argument in keycloak_backup)
    assert machine.labels().count("docker volume ls") == 1


def test_the_restore_test_loads_keycloaks_dump_into_a_postgres_of_its_own_major(
    edge_backup, machine
):
    """#107 T4: keycloak's dump loads into a throwaway postgres of its own major."""
    shipped = declare_shipped_apps()
    edge_backup(*shipped, "backup")

    outcome = edge_backup(*shipped, "restore", "--test")

    assert outcome.exit_code == 0, outcome.err
    servers = [argv[-5] for label, argv in machine.calls if label == docker.SERVER_START_LABEL]
    assert servers == [RESTORE_IMAGES[major] for major in PostgresMajor]
    assert app_history(outcome.status, "keycloak")["last_successful_restore_test"] is not None


def test_a_restored_table_without_rows_fails_the_restore_test(edge_backup, machine):
    """#107 T4: a keycloak `realm` table without rows fails the restore test."""
    shipped = declare_shipped_apps()
    edge_backup(*shipped, "backup")
    machine.table_rows["realm"] = 0

    outcome = edge_backup(*shipped, "restore", "--test")

    assert outcome.exit_code == 3
    assert "the restored table realm is empty" in outcome.out
    assert outcome.status["failing_app"] == "keycloak"
    assert outcome.status["exit_category"] == "verification-failed"


def test_songmaker_without_songs_still_passes_the_restore_test(edge_backup, machine):
    """#107 T5: songmaker's verification is unchanged; only keycloak requires rows (rule 3)."""
    machine.table_rows["songs"] = 0
    edge_backup("backup")

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 0, outcome.err
    assert app_history(outcome.status)["last_successful_restore_test"] is not None


def test_apps_toml_refuses_require_rows_that_is_not_a_boolean():
    """#107 rule 3: require_rows is a declared yes or no."""
    text = cli.DEFAULT_APPS.read_text().replace("require_rows = true", 'require_rows = "yes"')

    with pytest.raises(AppsError, match="require_rows must be true or false"):
        parse_apps(text)


def test_a_failing_restore_shows_no_row_value_of_the_dump(edge_backup, machine, home):
    """#107 T10: pg_restore's diagnostic quotes rows; only the step and exit code are shown."""
    marker = "SECRET-ROW-VALUE-4711"
    edge_backup("backup")
    machine.restore_diagnostic = f'COPY credential, line 1: "{marker}"'

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 3
    assert "pg_restore ended with exit 1" in outcome.out
    shown = outcome.out + outcome.err + machine.status_file.read_text()
    assert marker not in shown
    assert no_restore_server_left(machine)
    assert list((home / ".cache/edge-backup").iterdir()) == []


def test_an_app_never_backed_up_is_named_so_by_restore_and_restore_test(edge_backup, machine, home):
    """#107 T6: an app never backed up is named so by restore and restore-test."""
    edge_backup("backup")
    shipped = declare_shipped_apps()

    restored = edge_backup(*shipped, "restore", "keycloak", "--target", str(home / "restored"))
    tested = edge_backup(*shipped, "restore", "--test")

    expected = "no successful backup of keycloak recorded"
    assert expected in restored.err
    assert expected in tested.out
    assert not (home / "restored").exists()


def test_keycloak_reported_failed_while_songmaker_is_still_backed_up_when_keycloak_db_is_down(
    edge_backup, machine
):
    """#107 T7: keycloak is recorded failed, songmaker is still backed up."""
    machine.other_db_containers["edge"] = []

    outcome = edge_backup(*declare_shipped_apps(), "backup")

    assert outcome.exit_code == 3
    assert "no database container" in outcome.out
    assert (outcome.status["failing_app"], outcome.status["exit_category"]) == (
        "keycloak",
        "not-ready",
    )
    assert [s["app"] for s in machine.snapshots] == ["songmaker"]
    assert app_history(outcome.status)["last_snapshot_id"] == machine.snapshots[0]["id"]


def test_no_run_stops_or_starts_an_edge_service(edge_backup, machine):
    """#107 T8: no run stops or starts an edge service."""
    shipped = declare_shipped_apps()
    edge_backup(*shipped, "backup")
    edge_backup(*shipped, "restore", "--test")

    docker_verbs = {argv[1] for _, argv in machine.calls if argv[0] == "docker"}
    assert docker_verbs.isdisjoint({"stop", "start", "restart", "kill", "pause", "compose", "up"})


def test_no_output_or_status_holds_the_dump(edge_backup, machine):
    """#107 T10: no output or status holds dump content."""
    shipped = declare_shipped_apps()
    runs = [edge_backup(*shipped, "backup"), edge_backup(*shipped, "restore", "--test")]

    shown = "".join(run.out + run.err for run in runs) + machine.status_file.read_text()
    assert DUMP.decode() not in shown


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (("dump", '"sh -c pg_dump"'), "dump must be one of"),
        (("volume", '"audio files"'), "volume must match"),
        (("hook", '"rm -rf /"'), "unknown key ['hook']"),
        (("db_name", '"x; DROP TABLE songs"'), "db_name must match"),
    ],
)
def test_apps_toml_accepts_only_validated_records(change, message):
    key, value = change
    lines = [
        line
        for line in cli.DEFAULT_APPS.read_text().splitlines()
        if not line.startswith(f"{key} =")
    ]
    lines.insert(lines.index("[app.songmaker]") + 1, f"{key} = {value}")
    text = "\n".join(lines)

    with pytest.raises(AppsError, match=re.escape(message)):
        parse_apps(text)


def test_apps_toml_rejects_an_unsafe_sql_identifier():
    text = cli.DEFAULT_APPS.read_text().replace('"songs"', '"songs\\"; --"')

    with pytest.raises(AppsError, match="count_table must match"):
        parse_apps(text)
