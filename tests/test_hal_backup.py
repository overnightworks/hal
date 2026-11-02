"""The grammar of `hal backup` and `hal restore` on the scripted Docker host: what each flag
combination does, how a failed step and SIGTERM end, and what the realm step reads."""

import json
import os
import signal
import sys
from datetime import UTC, datetime, timedelta

import pytest
from support.backup_support import declare_shipped_apps, declare_two_apps, no_restore_server_left


@pytest.mark.parametrize(
    "command",
    [("backup",), ("restore", "--test"), ("backup", "--unlock"), ("restore", "--list")],
    ids=" ".join,
)
def test_no_backup_command_reads_stdin(edge_backup, monkeypatch, command):
    class Forbidden:
        def __getattr__(self, name):
            raise AssertionError(f"read stdin ({name})")

    edge_backup("backup")
    monkeypatch.setattr(sys, "stdin", Forbidden())

    assert edge_backup(*command).exit_code == 0


def test_pre_apply_json_answers_one_object_naming_the_snapshot(edge_backup, machine, home):
    outcome = edge_backup(*declare_two_apps(home), "backup", "radio", "--pre-apply", "--json")

    assert outcome.exit_code == 0, outcome.err
    assert json.loads(outcome.out) == {"snapshot": machine.snapshots[-1]["id"]}
    assert outcome.out.count("\n") == 1


@pytest.mark.parametrize(
    ("arguments", "error_lines"),
    [
        (("backup", "nobody"), ["error: nobody is not declared", "next: hal backup"]),
        (
            ("restore", "--test", "nobody"),
            ["error: nobody is not declared", "next: hal restore --test"],
        ),
    ],
)
def test_an_undeclared_app_runs_nothing_and_writes_no_status(
    edge_backup, machine, arguments, error_lines
):
    """#238 matrix cell 7."""
    outcome = edge_backup(*arguments)

    assert (outcome.exit_code, outcome.err.splitlines()) == (3, error_lines)
    assert machine.calls == []
    assert outcome.status is None


TARGETLESS = "--test restores to a throwaway, so --target does not apply"
STANDALONE = "--init and --unlock stand alone, without an app, --pre-apply or --json"


@pytest.mark.parametrize(
    ("arguments", "complaint"),
    [
        (("backup", "--pre-apply"), "--pre-apply needs the name of an app"),
        (("backup", "--json"), "--json needs --pre-apply"),
        (("backup", "radio", "--json"), "--json needs --pre-apply"),
        (
            ("backup", "--init", "radio"),
            STANDALONE,
        ),
        (
            ("backup", "--init", "--unlock"),
            STANDALONE,
        ),
        (
            ("backup", "--unlock", "--pre-apply", "radio"),
            STANDALONE,
        ),
        (
            ("backup", "--init", "--json"),
            STANDALONE,
        ),
        (("restore", "--test", "--snapshot", "0" * 12), "--snapshot needs the name of an app"),
        (("restore", "--test", "--snapshot", ""), "--snapshot needs the name of an app"),
        (
            ("restore", "--test", "--target", "somewhere"),
            TARGETLESS,
        ),
        (("restore", "--list", "radio"), "--list stands alone"),
        (("restore", "--list", "--test"), "--list stands alone"),
        (("restore", "--list", "--snapshot", ""), "--list stands alone"),
        (("restore", "--list", "--target", ""), "--list stands alone"),
        (("restore",), "restore needs the name of an app and --target"),
        (("restore", "radio"), "restore needs the name of an app and --target"),
        (("restore", "--target", "somewhere"), "restore needs the name of an app and --target"),
    ],
)
def test_a_wrong_flag_combination_is_a_usage_error_that_runs_nothing(
    edge_backup, machine, arguments, complaint
):
    outcome = edge_backup(*arguments)

    program = f"hal {arguments[0]}"
    assert outcome.exit_code == 2
    assert outcome.err.splitlines() == [f"error: {complaint}", f"next: {program} --help"]
    assert machine.calls == []
    assert outcome.status is None


def _terminated_by_systemd():
    """What `systemctl stop` does to the run: SIGTERM, which must reach the run as Ctrl-C."""
    assert signal.getsignal(signal.SIGTERM) is signal.default_int_handler, "SIGTERM would kill"
    os.kill(os.getpid(), signal.SIGTERM)


@pytest.mark.parametrize(
    ("command", "label"),
    [
        (("backup",), "pg_dump"),
        (("backup", "radio", "--pre-apply", "--json"), "restic backup"),
    ],
    ids=" ".join,
)
def test_a_failed_backup_exits_3_with_an_error_line_and_a_next_line_and_frees_the_lock(
    edge_backup, machine, home, monkeypatch, command, label
):
    monkeypatch.chdir(home)
    edge_backup(*declare_two_apps(home), "backup")
    machine.failing[label] = 1

    outcome = edge_backup(*declare_two_apps(home), *command)

    assert outcome.exit_code == 3
    [error, next_step] = outcome.err.splitlines()
    assert error.startswith("error: ")
    assert "failed" not in error
    assert next_step.startswith("next: hal backup")
    assert machine._host_lock_is_free()


@pytest.mark.parametrize(
    ("command", "label"),
    [
        (("backup", "--init"), "restic init"),
        (("backup", "--unlock"), "restic unlock"),
        (("restore", "--list"), "restic snapshots"),
        (("restore", "radio", "--target", "restored"), "restic restore"),
    ],
    ids=" ".join,
)
def test_a_failed_maintenance_or_restore_step_exits_3_with_one_error_line_and_frees_the_lock(
    edge_backup, machine, home, monkeypatch, command, label
):
    monkeypatch.chdir(home)
    edge_backup(*declare_two_apps(home), "backup")
    machine.failing[label] = 1
    snapshot = machine.snapshots[-1]["id"]
    command = [snapshot if part == "latest" else part for part in command]

    outcome = edge_backup(*declare_two_apps(home), *command)

    assert outcome.exit_code == 3
    [line] = outcome.err.splitlines()
    assert line.startswith(f"error: hal {command[0]}: failed: ")
    assert machine._host_lock_is_free()


def test_a_good_backup_prints_a_row_per_app_the_repository_row_and_the_verdict(
    edge_backup, machine, home
):
    outcome = edge_backup(*declare_two_apps(home), "backup")

    first, second = (snapshot["id"][:8] for snapshot in machine.snapshots[-2:])
    assert (outcome.exit_code, outcome.err) == (0, "")
    assert outcome.out.splitlines() == [
        f"  ✓ songmaker       backed up      {first} · 4.2 MiB · <1s",
        f"  ✓ radio           backed up      {second} · 4.2 MiB · <1s",
        "  ✓ repository      pruned         checked · <1s",
        "✓ backup done · 2 apps · <1s",
    ]


def test_the_backed_up_row_shows_the_source_size_and_the_apps_span_including_readiness(
    edge_backup, machine, home
):
    machine.source_bytes = 2_254_857_830
    machine.backup_seconds = 100
    machine.absent_polls = 3
    machine.clock.wall_drift_per_sleep = timedelta(hours=-1)

    outcome = edge_backup(*declare_two_apps(home), "backup", "radio")

    snapshot = machine.snapshots[-1]["id"][:8]
    assert outcome.out.splitlines()[0] == (
        f"  ✓ radio           backed up      {snapshot} · 2.1 GiB · 2m25s"
    )


def test_a_backup_row_counts_only_its_own_apps_time(edge_backup, machine, home):
    machine.backup_seconds = 65

    outcome = edge_backup(*declare_two_apps(home), "backup")

    rows = outcome.out.splitlines()
    assert rows[0].endswith(" · 1m05s")
    assert rows[1].endswith(" · 1m05s")
    assert rows[2] == "  ✓ repository      pruned         checked · <1s"


@pytest.mark.parametrize(
    "machine_settings",
    [
        {"prints_backup_summary": False},
        {"summary_without": {"total_bytes_processed"}},
        {"source_bytes": True},
        {"source_bytes": -1},
    ],
    ids=["no summary", "no size", "boolean size", "negative size"],
)
def test_an_unreadable_backup_summary_fails_the_app_as_not_backed_up(
    edge_backup, machine, home, machine_settings
):
    for name, value in machine_settings.items():
        setattr(machine, name, value)

    outcome = edge_backup(*declare_two_apps(home), "backup", "radio")

    assert outcome.exit_code == 3
    assert outcome.out.splitlines()[0] == (
        "  ✗ radio           not backed up  backup: restic backup summary is unreadable"
    )


def test_a_failed_app_has_its_row_while_the_others_are_backed_up_and_the_repository_is_not_pruned(
    edge_backup, machine
):
    machine.other_db_containers["edge"] = []

    outcome = edge_backup(*declare_shipped_apps(), "backup")

    rows = outcome.out.splitlines()
    assert outcome.exit_code == 3
    assert rows == [
        f"  ✓ songmaker       backed up      {machine.snapshots[-1]['id'][:8]} · 4.2 MiB · <1s",
        "  ✗ keycloak        not backed up  no database container after 10 min",
        "  · repository      not pruned     a backup failed",
    ]
    assert outcome.err.splitlines() == [
        "error: 1 of 2 apps not backed up · keycloak has no good backup recorded",
        "next: hal backup keycloak",
    ]
    assert "restic forget" not in machine.labels()


def test_a_single_failed_app_is_named_on_the_error_line(edge_backup, machine):
    machine.other_db_containers["edge"] = []

    outcome = edge_backup(*declare_shipped_apps(), "backup", "keycloak")

    assert outcome.exit_code == 3
    assert outcome.err.splitlines() == [
        "error: keycloak not backed up · no good backup recorded",
        "next: hal backup keycloak",
    ]


def _fail_keycloak_after_a_good_run(edge_backup, machine, *arguments):
    edge_backup(*declare_shipped_apps(), "backup")
    machine.other_db_containers["edge"] = []
    return edge_backup(*declare_shipped_apps(), "backup", *arguments)


@pytest.mark.parametrize(
    ("arguments", "error_line"),
    [
        (
            (),
            "error: 1 of 2 apps not backed up · keycloak's last good backup 18.10. 05:00",
        ),
        (
            ("keycloak",),
            "error: keycloak not backed up · last good backup 18.10. 05:00",
        ),
    ],
    ids=["several apps", "one app"],
)
def test_the_error_line_names_the_failed_apps_last_good_backup_in_local_time(
    edge_backup, machine, berlin_time, arguments, error_line
):
    outcome = _fail_keycloak_after_a_good_run(edge_backup, machine, *arguments)

    assert outcome.exit_code == 3
    assert outcome.err.splitlines()[0] == error_line


def test_the_error_line_shows_the_year_of_a_last_good_backup_from_another_year(
    edge_backup, machine, berlin_time
):
    edge_backup(*declare_shipped_apps(), "backup")
    machine.clock.moment = datetime(2027, 1, 5, 9, 0, tzinfo=UTC)
    machine.other_db_containers["edge"] = []

    outcome = edge_backup(*declare_shipped_apps(), "backup", "keycloak")

    assert outcome.err.splitlines()[0] == (
        "error: keycloak not backed up · last good backup 18.10.2026 05:00"
    )


def test_the_pruned_row_shows_the_span_of_forget_and_check(edge_backup, machine, home):
    machine.maintenance_seconds = 20

    outcome = edge_backup(*declare_two_apps(home), "backup")

    assert outcome.out.splitlines()[2] == "  ✓ repository      pruned         checked · 1m00s"


def test_pre_apply_json_names_the_failed_apps_reason_on_the_error_line_and_prints_no_row(
    edge_backup, machine
):
    machine.other_db_containers["edge"] = []

    outcome = edge_backup(*declare_shipped_apps(), "backup", "keycloak", "--pre-apply", "--json")

    assert (outcome.exit_code, outcome.out) == (3, "")
    assert outcome.err.splitlines() == [
        "error: keycloak: no database container after 10 min",
        "next: hal backup keycloak",
    ]


def test_an_interrupted_backup_names_the_app_it_stopped_in(edge_backup, machine, home):
    machine.failing["pg_dump"] = _terminated_by_systemd

    outcome = edge_backup(*declare_two_apps(home), "backup")

    assert outcome.exit_code == 130
    assert outcome.err.splitlines() == [
        "error: interrupted while backing up songmaker · its state may be partial",
        "next: hal backup",
    ]


def test_a_backup_interrupted_outside_any_app_says_only_that_it_was_interrupted(
    edge_backup, machine, home
):
    machine.failing["restic forget"] = _terminated_by_systemd

    outcome = edge_backup(*declare_two_apps(home), "backup")

    assert outcome.exit_code == 130
    assert outcome.err.splitlines() == ["error: interrupted", "next: hal backup"]


def test_an_interrupted_unlock_keeps_its_plain_error_line_without_a_next_step(edge_backup, machine):
    machine.failing["restic unlock"] = _terminated_by_systemd

    outcome = edge_backup("backup", "--unlock")

    assert outcome.exit_code == 130
    assert outcome.err.splitlines() == ["error: hal backup: failed: interrupted"]


@pytest.mark.parametrize(
    ("command", "label"),
    [
        (("backup",), "pg_dump"),
        (("backup", "radio", "--pre-apply", "--json"), "pg_dump"),
        (("restore", "--test"), "pg_restore"),
        (("backup", "--init"), "restic init"),
        (("backup", "--unlock"), "restic unlock"),
        (("restore", "--list"), "restic snapshots"),
        (("restore", "songmaker", "--target", "restored"), "restic restore"),
    ],
    ids=" ".join,
)
def test_sigterm_ends_a_run_as_an_interruption_that_cleans_up_and_frees_the_lock(
    edge_backup, machine, home, monkeypatch, command, label
):
    monkeypatch.chdir(home)
    edge_backup(*declare_two_apps(home), "backup")
    sigterm_before = signal.getsignal(signal.SIGTERM)
    machine.failing[label] = _terminated_by_systemd

    outcome = edge_backup(*declare_two_apps(home), *command)

    assert outcome.exit_code == 130
    assert signal.getsignal(signal.SIGTERM) is sigterm_before
    assert machine._host_lock_is_free()
    assert no_restore_server_left(machine)
    assert list((home / ".cache/edge-backup").iterdir()) == []
    if label in {"pg_dump", "pg_restore"}:  # the verbs that record their outcome
        assert outcome.status["state"] == "failed"
        assert outcome.status["exit_category"] == "interrupted"
        if command[0] == "restore":
            assert outcome.err.splitlines() == [
                "error: interrupted while testing the restore of songmaker",
                "next: hal restore --test",
            ]


def test_a_good_restore_test_prints_a_row_per_app_the_repository_row_and_the_verdict(
    edge_backup, machine, home
):
    edge_backup(*declare_two_apps(home), "backup")

    outcome = edge_backup(*declare_two_apps(home), "restore", "--test")

    first, second = (snapshot["id"][:8] for snapshot in machine.snapshots[-2:])
    assert (outcome.exit_code, outcome.err) == (0, "")
    assert outcome.out.splitlines() == [
        f"  ✓ songmaker       restore proven {first}",
        f"  ✓ radio           restore proven {second}",
        "  ✓ repository      checked",
        "✓ restore test done · 2 apps · 1s",
    ]


def test_a_failed_app_has_its_row_while_the_others_are_proven_and_the_repository_is_checked(
    edge_backup, machine
):
    edge_backup("backup")

    outcome = edge_backup(*declare_shipped_apps(), "restore", "--test")

    assert outcome.exit_code == 3
    assert outcome.out.splitlines() == [
        f"  ✓ songmaker       restore proven {machine.snapshots[-1]['id'][:8]}",
        "  ✗ keycloak        not proven     no successful backup of keycloak recorded",
        "  ✓ repository      checked",
    ]
    assert outcome.err.splitlines() == [
        "error: 1 of 2 apps not proven",
        "next: hal restore --test keycloak",
    ]


def test_a_failed_restore_test_of_one_snapshot_keeps_its_reason_in_the_error_line(
    edge_backup, machine
):
    edge_backup("backup")

    outcome = edge_backup(
        *declare_shipped_apps(), "restore", "--test", "keycloak", "--snapshot", "0" * 12
    )

    assert outcome.exit_code == 3
    assert outcome.err.splitlines() == [
        "error: keycloak: 000000000000 names no single snapshot of keycloak "
        "(at least 8 characters of an ID from `hal restore --list`)",
        "next: hal restore --test keycloak",
    ]


def test_a_failed_check_after_the_failed_app_of_one_snapshot_still_names_the_app_in_the_error_line(
    edge_backup, machine
):
    edge_backup("backup")
    machine.failing["restic check"] = 1

    outcome = edge_backup(
        *declare_shipped_apps(), "restore", "--test", "keycloak", "--snapshot", "0" * 12
    )

    assert outcome.exit_code == 3
    assert outcome.err.splitlines()[0].startswith("error: keycloak: 000000000000 names no")
    assert outcome.err.splitlines()[1] == "next: hal restore --test keycloak"


def test_a_restore_test_that_cannot_start_prints_only_the_error_pair(edge_backup, machine, home):
    edge_backup(*declare_two_apps(home), "backup")
    (home / ".secrets/restic/password").unlink()

    outcome = edge_backup(*declare_two_apps(home), "restore", "--test")

    assert (outcome.exit_code, outcome.out) == (3, "")
    assert outcome.err.splitlines() == [
        "error: the password file is missing (docs/backup.md: Setup)",
        "next: hal restore --test",
    ]


def test_an_interrupted_restore_test_names_the_app_it_stopped_in(
    edge_backup, machine, home, monkeypatch
):
    monkeypatch.chdir(home)
    edge_backup(*declare_two_apps(home), "backup")
    machine.failing["pg_restore"] = _terminated_by_systemd

    outcome = edge_backup(*declare_two_apps(home), "restore", "--test")

    assert outcome.exit_code == 130
    assert outcome.err.splitlines() == [
        "error: interrupted while testing the restore of songmaker",
        "next: hal restore --test",
    ]


def test_a_repository_that_fails_its_check_after_a_failed_app_has_its_row_and_the_app_count(
    edge_backup, machine
):
    edge_backup("backup")
    machine.failing["restic check"] = 1

    outcome = edge_backup(*declare_shipped_apps(), "restore", "--test")

    rows = outcome.out.splitlines()
    assert outcome.exit_code == 3
    assert rows[-1].startswith("  ✗ repository      not checked    ")
    assert outcome.err.splitlines() == [
        "error: 1 of 2 apps not proven",
        "next: hal restore --test keycloak",
    ]


def test_a_repository_that_fails_its_check_while_every_app_is_proven_has_its_row(
    edge_backup, machine
):
    edge_backup("backup")
    machine.failing["restic check"] = 1

    outcome = edge_backup("restore", "--test")

    rows = outcome.out.splitlines()
    assert outcome.exit_code == 3
    assert rows[-1].startswith("  ✗ repository      not checked ")
    assert outcome.err.splitlines()[0].startswith("error: check: restic check ended with exit 1")


def test_a_restore_test_interrupted_outside_any_app_says_only_that_it_was_interrupted(
    edge_backup, machine, home, monkeypatch
):
    monkeypatch.chdir(home)
    edge_backup(*declare_two_apps(home), "backup")
    machine.failing["restic check"] = _terminated_by_systemd

    outcome = edge_backup(*declare_two_apps(home), "restore", "--test")

    assert outcome.exit_code == 130
    assert outcome.err.splitlines() == ["error: interrupted", "next: hal restore --test"]


def test_init_says_the_repository_was_created(edge_backup):
    outcome = edge_backup("backup", "--init")

    assert (outcome.exit_code, outcome.out) == (0, "hal backup: repository created\n")


def test_restore_says_which_snapshot_of_which_app_was_restored_into_the_target(
    edge_backup, machine, home
):
    edge_backup("backup")
    target = home / "restored"

    outcome = edge_backup("restore", "songmaker", "--target", str(target))

    snapshot = machine.snapshots[-1]["id"][:8]
    assert outcome.exit_code == 0, outcome.err
    assert outcome.out == f"hal restore: snapshot {snapshot} of songmaker restored into {target}\n"


def test_a_single_app_that_is_not_proven_is_named_on_the_error_line(edge_backup, machine):
    edge_backup("backup")

    outcome = edge_backup(*declare_shipped_apps(), "restore", "--test", "keycloak")

    assert outcome.exit_code == 3
    assert outcome.err.splitlines() == [
        "error: keycloak not proven",
        "next: hal restore --test keycloak",
    ]
