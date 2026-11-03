"""What a restore may take, and what a run must check before it stages anything."""

import json

import pytest
from support.backup_support import (
    DUMP,
    Machine,
    app_history,
    declare_shipped_apps,
    declare_two_apps,
    schema_one_status,
)

from hal.backup.settings import RESTIC_IMAGE, RESTORE_IMAGES, Settings


def _leave_a_partial_snapshot(machine: Machine) -> str:
    """A failed run's restic exit 3 leaves a snapshot that no successful backup recorded."""
    partial = {"id": "a973e990" * 8, "db": {"db.dump": b"partial"}, "audio": {}}
    machine.snapshots.append(partial)
    return partial["id"]


def test_restore_takes_the_last_successful_backups_snapshot_not_a_newer_partial_one(
    edge_backup, machine, home
):
    edge_backup("backup")
    good = machine.snapshots[-1]["id"]
    _leave_a_partial_snapshot(machine)
    target = home / "restored"

    outcome = edge_backup("restore", "songmaker", "--target", str(target))

    assert outcome.exit_code == 0, outcome.err
    assert good[:8] in outcome.out
    assert (target / "db/db.dump").read_bytes() == DUMP


def _forget_the_recorded_snapshot(machine: Machine) -> None:
    machine.snapshots.pop()


def _lose_the_status(machine: Machine) -> None:
    machine.status_file.unlink()


@pytest.mark.parametrize(
    ("break_history", "refusal"),
    [
        (_forget_the_recorded_snapshot, "is missing from the repository"),
        (_lose_the_status, "no successful backup of songmaker recorded"),
    ],
)
def test_restore_refuses_without_the_last_successful_snapshot_and_names_the_newest(
    edge_backup, machine, home, break_history, refusal
):
    edge_backup("backup")
    edge_backup("backup")
    break_history(machine)
    target = home / "restored"

    outcome = edge_backup("restore", "songmaker", "--target", str(target))

    assert outcome.exit_code == 3
    [line] = outcome.err.splitlines()
    assert refusal in line
    assert f"the newest snapshot is {machine.snapshots[-1]['id'][:8]}" in line
    assert not target.exists()


@pytest.mark.parametrize(
    "image",
    [RESTIC_IMAGE, *RESTORE_IMAGES.values()],
    ids=["restic", *(f"postgres-{major}" for major in RESTORE_IMAGES)],
)
@pytest.mark.parametrize("command", ["backup", "restore --test"])
def test_a_pruned_pinned_image_is_pulled_by_its_digest_and_the_run_goes_on(
    edge_backup, machine, command, image
):
    shipped = declare_shipped_apps()
    edge_backup(*shipped, "backup")
    machine.missing_images = {image}

    outcome = edge_backup(*shipped, *command.split())

    assert outcome.exit_code == 0, outcome.err
    pulls = [argv for label, argv in machine.calls if label == "docker pull"]
    assert [argv[-1] for argv in pulls] == [image]
    assert "@sha256:" in image


@pytest.mark.parametrize("command", ["backup", "restore --test"])
def test_a_pinned_image_that_cannot_be_pulled_fails_early_naming_it(
    edge_backup, machine, home, command
):
    machine.missing_images = {RESTIC_IMAGE}
    machine.unpullable_images = {RESTIC_IMAGE}

    outcome = edge_backup(*command.split())

    assert outcome.exit_code == 3
    [line, *_] = outcome.err.splitlines()
    assert RESTIC_IMAGE in line
    assert set(machine.labels()) == {"docker info", "docker image inspect", "docker pull"}
    assert outcome.status["exit_category"] == "configuration"
    assert (
        not Settings.for_home(home, 0, 0).work_dir.exists()
        or list(Settings.for_home(home, 0, 0).work_dir.iterdir()) == []
    )


@pytest.mark.parametrize("command", ["backup", "restore --test"])
def test_a_daemon_that_is_still_starting_is_waited_for_before_the_images_are_checked(
    edge_backup, machine, command
):
    edge_backup("backup")
    polls_before = machine.labels().count("docker info")
    machine.daemon_down_polls = 3

    outcome = edge_backup(*command.split())

    assert outcome.exit_code == 0, outcome.err
    assert outcome.status["state"] == "ok"
    assert machine.labels().count("docker info") - polls_before == 4


def test_restore_names_how_to_choose_the_newest_snapshot_when_none_is_recorded(
    edge_backup, machine, home
):
    edge_backup("backup")
    _lose_the_status(machine)

    outcome = edge_backup("restore", "songmaker", "--target", str(home / "restored"))

    assert "--snapshot" in outcome.err


def test_restore_takes_the_named_snapshot_on_a_machine_without_a_status_file(
    edge_backup, machine, home
):
    edge_backup("backup")
    chosen = machine.snapshots[-1]["id"]
    _lose_the_status(machine)
    target = home / "restored"

    outcome = edge_backup("restore", "songmaker", "--snapshot", chosen, "--target", str(target))

    assert outcome.exit_code == 0, outcome.err
    assert chosen[:8] in outcome.out
    assert (target / "db/db.dump").read_bytes() == DUMP


@pytest.mark.parametrize("prefix_length", [64, 8], ids=["full-id", "short-prefix"])
def test_restore_takes_an_older_snapshot_when_a_newer_one_exists(
    edge_backup, machine, home, prefix_length
):
    edge_backup("backup")
    edge_backup("backup")
    older, newer = machine.snapshots
    older["id"] = "b0b0b0b0" * 8
    older["db"]["db.dump"] = b"older contents"
    target = home / "restored"

    outcome = edge_backup(
        "restore", "songmaker", "--snapshot", older["id"][:prefix_length], "--target", str(target)
    )

    assert outcome.exit_code == 0, outcome.err
    assert (target / "db/db.dump").read_bytes() == b"older contents"
    assert newer["db"]["db.dump"] == DUMP


@pytest.mark.parametrize(
    "snapshot", ["f" * 64, "0" * 7, "00000000"], ids=["unknown", "too-short", "ambiguous"]
)
def test_restore_refuses_a_snapshot_that_is_not_one_single_snapshot_of_the_app(
    edge_backup, machine, home, snapshot
):
    edge_backup("backup")
    edge_backup("backup")
    target = home / "restored"

    outcome = edge_backup("restore", "songmaker", "--snapshot", snapshot, "--target", str(target))

    assert outcome.exit_code == 3
    [line] = outcome.err.splitlines()
    assert "names no single snapshot" in line
    assert not target.exists()


def test_restore_refuses_the_snapshot_of_another_app(edge_backup, machine, home):
    edge_backup("backup")
    machine.snapshots[-1]["app"] = "other"
    target = home / "restored"

    outcome = edge_backup(
        "restore", "songmaker", "--snapshot", machine.snapshots[-1]["id"], "--target", str(target)
    )

    assert outcome.exit_code == 3
    [line] = outcome.err.splitlines()
    assert "names no single snapshot" in line
    assert not target.exists()


def test_restore_test_verifies_the_last_successful_snapshot_not_a_newer_partial_one(
    edge_backup, machine
):
    edge_backup("backup")
    _leave_a_partial_snapshot(machine)

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 0, outcome.err


def test_restore_test_refuses_without_a_recorded_successful_snapshot(edge_backup, machine):
    edge_backup("backup")
    _lose_the_status(machine)

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 3
    assert "no successful backup of songmaker recorded" in outcome.out


def test_restore_takes_each_apps_own_last_successful_snapshot(edge_backup, machine, home):
    """#71 rule 4: restore takes the app's own last successful snapshot."""
    two_apps = declare_two_apps(home)
    edge_backup(*two_apps, "backup")
    edge_backup(*two_apps, "backup")
    songmaker_snapshot = app_history(json.loads(machine.status_file.read_text()))[
        "last_snapshot_id"
    ]

    first = edge_backup(*two_apps, "restore", "songmaker", "--target", str(home / "first"))
    second = edge_backup(*two_apps, "restore", "radio", "--target", str(home / "second"))

    assert (first.exit_code, second.exit_code) == (0, 0)
    assert songmaker_snapshot[:8] in first.out
    assert machine.snapshots[-1]["id"][:8] in second.out


def test_restore_test_verifies_each_app_against_its_own_snapshot(edge_backup, machine, home):
    """#71 rule 5: the restore test verifies each app against its own snapshot."""
    two_apps = declare_two_apps(home)
    edge_backup(*two_apps, "backup")

    outcome = edge_backup(*two_apps, "restore", "--test")

    assert outcome.exit_code == 0, outcome.err
    restored = [argv for label, argv in machine.calls if label == "restic restore"]
    assert [snapshot["id"] for snapshot in machine.snapshots] == [
        argv[argv.index("restore") + 1].split(":")[0] for argv in restored
    ]
    assert all(
        app_history(outcome.status, app)["last_successful_restore_test"] is not None
        for app in ("songmaker", "radio")
    )


def test_an_app_that_fails_its_restore_test_does_not_cost_the_others_their_time(
    edge_backup, machine, home
):
    """#71 rule 5: a failed restore test costs the other apps nothing."""
    two_apps = declare_two_apps(home)
    edge_backup(*two_apps, "backup")
    del machine.snapshots[-1]["db"]["db.dump"]

    outcome = edge_backup(*two_apps, "restore", "--test")

    assert outcome.exit_code == 3
    assert (outcome.status["failing_app"], outcome.status["failing_phase"]) == ("radio", "verify")
    assert app_history(outcome.status)["last_successful_restore_test"] is not None
    assert app_history(outcome.status, "radio")["last_successful_restore_test"] is None


def test_a_failed_read_data_check_gives_no_app_a_new_restore_test_time(edge_backup, machine, home):
    """#71 rule 5: a failed read-data check stamps no app."""
    two_apps = declare_two_apps(home)
    edge_backup(*two_apps, "backup")
    machine.failing["restic check"] = 1

    outcome = edge_backup(*two_apps, "restore", "--test")

    assert outcome.status["failing_phase"] == "check"
    assert all(
        app_history(outcome.status, app)["last_successful_restore_test"] is None
        for app in ("songmaker", "radio")
    )


def _write_schema_one_status(machine: Machine, snapshot_id: str) -> bytes:
    machine.status_file.write_text(json.dumps(schema_one_status(snapshot_id)))
    return machine.status_file.read_bytes()


@pytest.mark.parametrize(
    ("two_declared", "recorded_snapshot_exists", "attributed"),
    [
        (False, True, True),
        (False, False, False),
        (True, True, False),
    ],
    ids=["one app, confirmed", "one app, not confirmed", "two apps"],
)
def test_schema_one_evidence_moves_to_an_app_only_with_restic_evidence(
    edge_backup, machine, home, two_declared, recorded_snapshot_exists, attributed
):
    """#71 rule 2: schema-1 evidence moves to an app only with restic evidence."""
    declared = declare_two_apps(home) if two_declared else ()
    edge_backup(*declared, "backup")
    legacy_id = machine.snapshots[0]["id"] if recorded_snapshot_exists else "f" * 64
    legacy_file = _write_schema_one_status(machine, legacy_id)
    target = home / "restored"

    restored = edge_backup(*declared, "restore", "songmaker", "--target", str(target))

    assert (restored.exit_code == 0) is attributed
    if not attributed:
        assert "no successful backup of songmaker recorded" in restored.err
    assert machine.status_file.read_bytes() == legacy_file

    migrated = edge_backup(*declared, "restore", "--test")

    assert migrated.status["schema"] == 2
    assert "last_successful_backup" not in migrated.status
    if attributed:
        assert app_history(migrated.status)["last_snapshot_id"] == legacy_id
        assert "unattributed" not in migrated.status
    else:
        assert migrated.status["unattributed"]["last_snapshot_id"] == legacy_id
        assert app_history(migrated.status).get("last_snapshot_id") != legacy_id


OLD_HOST = "edge-backup"


def _hand_over_to_the_old_host(snapshot: dict) -> None:
    snapshot["host"] = OLD_HOST


def test_restore_refuses_a_recorded_snapshot_of_the_old_host_without_naming_it_as_newest(
    edge_backup, machine, home
):
    """#414 sentence 4 (E3): a recorded old-host snapshot is refused like a missing one."""

    edge_backup("backup")
    _hand_over_to_the_old_host(machine.snapshots[-1])
    target = home / "restored"

    outcome = edge_backup("restore", "songmaker", "--target", str(target))

    assert outcome.exit_code == 3
    [line] = outcome.err.splitlines()
    assert "is missing from the repository" in line
    assert "the newest snapshot" not in line
    assert not target.exists()


def test_restore_names_the_newest_snapshot_of_the_new_host_never_an_old_one(
    edge_backup, machine, home
):
    """#414 sentence 4 (E3): the newest snapshot named is always one of host hal."""

    edge_backup("backup")
    edge_backup("backup")
    _hand_over_to_the_old_host(machine.snapshots[-1])

    outcome = edge_backup("restore", "songmaker", "--target", str(home / "restored"))

    assert outcome.exit_code == 3
    assert f"the newest snapshot is {machine.snapshots[0]['id'][:8]}" in outcome.err


@pytest.mark.parametrize(
    ("command", "stream"), [(["restore"], "err"), (["restore", "--test"], "out")]
)
def test_an_old_host_snapshot_given_as_snapshot_is_refused_like_an_unknown_one(
    edge_backup, machine, home, command, stream
):
    """#414 sentence 4 (E3): an old-host ID given to --snapshot is refused like an unknown one."""

    edge_backup("backup")
    edge_backup("backup")
    _hand_over_to_the_old_host(machine.snapshots[0])
    target = ["--target", str(home / "restored")] if command == ["restore"] else []

    outcome = edge_backup(*command, "songmaker", "--snapshot", machine.snapshots[0]["id"], *target)

    assert outcome.exit_code == 3
    assert "names no single snapshot" in getattr(outcome, stream)
    assert not (home / "restored").exists()


def test_the_restore_test_takes_the_new_hosts_snapshot_after_one_backup_on_it(edge_backup, machine):
    """#414 sentence 4 (E3): after one hal backup the restore test takes the new snapshot."""

    edge_backup("backup")
    _hand_over_to_the_old_host(machine.snapshots[-1])
    edge_backup("backup")

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 0, outcome.err


def test_no_restic_command_names_the_old_host(edge_backup, machine, home):
    """#414 sentence 1: no restic argv names edge-backup, and every --host is hal."""

    edge_backup("backup")
    edge_backup("restore", "--test")
    edge_backup(
        "restore",
        "songmaker",
        "--snapshot",
        machine.snapshots[-1]["id"],
        "--target",
        str(home / "restored"),
    )

    restic_calls = [argv for label, argv in machine.calls if label.startswith("restic ")]
    assert restic_calls
    assert not [argv for argv in restic_calls if OLD_HOST in argv]
    assert all(argv[argv.index("--host") + 1] == "hal" for argv in restic_calls if "--host" in argv)


def test_an_old_host_snapshot_does_not_appear_in_the_restore_list(edge_backup, machine):
    """#414 ruling 1 (head, 26.10.2026): the restore list shows only host hal."""

    edge_backup("backup")
    edge_backup("backup")
    _hand_over_to_the_old_host(machine.snapshots[0])

    outcome = edge_backup("restore", "--list")

    assert outcome.exit_code == 0, outcome.err
    assert machine.snapshots[0]["id"] not in outcome.out
    assert machine.snapshots[1]["id"] in outcome.out
