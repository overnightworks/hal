"""What `hal backup` forgets on the scripted Docker host: every pre-apply snapshot past the age
bound, and only the apps that backed up, whatever another app did (#969 C1, C2)."""

from datetime import datetime, timedelta, timezone

import pytest
from support.backup_support import (
    Machine,
    app_history,
    declare_songmaker_and_keycloak,
    declare_two_apps,
)

from hal.backup.restic import PRE_APPLY_MAX_AGE, REPOSITORY_EXIT_CODES

SECOND = timedelta(seconds=1)


def _bound(machine: Machine) -> datetime:
    """The instant a pre-apply snapshot must not be older than, on the run's clock."""
    return machine.clock.now() - PRE_APPLY_MAX_AGE


def _fail_radio_readiness(machine: Machine) -> None:
    machine.other_db_containers[("radio", "postgres")] = ["beef01", "beef02"]


@pytest.mark.parametrize("arguments", [(), ("--pre-apply",)], ids=["weekly", "pre-apply"])
def test_a_forget_drops_by_full_id_only_the_apps_pre_apply_snapshots_older_than_the_bound(
    edge_backup, machine, home, arguments
):
    bound = _bound(machine)
    older = machine.plant("songmaker", bound - SECOND)
    machine.plant("songmaker", bound)
    machine.plant("songmaker", bound + SECOND)
    machine.plant("songmaker", machine.clock.now() + PRE_APPLY_MAX_AGE)
    machine.plant("songmaker", bound - SECOND, pre_apply=False)
    machine.plant("songmaker", bound - SECOND, hostname="another-host")
    machine.plant("radio", bound - SECOND)

    outcome = edge_backup(*declare_two_apps(home), "backup", "songmaker", *arguments)

    assert outcome.exit_code == 0, outcome.err
    assert machine.forgotten == [older]
    by_id = [argv for label, argv in machine.calls if label == "restic forget"][-1]
    assert by_id[by_id.index("forget") + 1 :] == [older, "--prune", "--max-unused", "0"]


def test_a_time_with_nanoseconds_and_an_offset_counts_as_the_instant_it_names(edge_backup, machine):
    berlin_summer = timezone(timedelta(hours=2))
    older = machine.plant("songmaker", _bound(machine))
    a_second_before = (_bound(machine) - SECOND).astimezone(berlin_summer)
    machine.snapshots[-1]["time"] = f"{a_second_before:%Y-%m-%dT%H:%M:%S}.999999999+02:00"

    outcome = edge_backup("backup")

    assert outcome.exit_code == 0, outcome.err
    assert machine.forgotten == [older]


@pytest.mark.parametrize("arguments", [("backup",), ("backup", "songmaker", "--pre-apply")])
def test_no_forget_by_id_runs_when_no_pre_apply_snapshot_is_past_the_bound(
    edge_backup, machine, arguments
):
    machine.plant("songmaker", _bound(machine))

    outcome = edge_backup(*arguments)

    assert outcome.exit_code == 0, outcome.err
    assert machine.labels().count("restic forget") == 1
    assert machine.forgotten == []


def _assert_forget_failed_unreadable_and_forgot_nothing(outcome, machine):
    assert outcome.exit_code == 3
    assert outcome.status["failing_phase"] == "forget"
    assert outcome.out.splitlines()[-1] == (
        "  ✗ repository      not pruned     forget: restic snapshots output is unreadable"
    )
    assert machine.forgotten == []


@pytest.mark.parametrize(
    ("field", "value"),
    [("time", None), ("time", "18.07.2026"), ("time", "2026-07-18T03:00:00"), ("id", "1a2b3c4d")],
    ids=["no time", "no ISO time", "time without offset", "short id"],
)
def test_an_unreadable_pre_apply_listing_fails_the_forget_and_forgets_nothing_by_id(
    edge_backup, machine, field, value
):
    machine.plant("songmaker", _bound(machine) - SECOND)
    machine.snapshots[-1][field] = value

    outcome = edge_backup("backup")

    _assert_forget_failed_unreadable_and_forgot_nothing(outcome, machine)


@pytest.mark.parametrize("answer", [b"{}", b'""', b"null"], ids=["object", "string", "null"])
def test_a_pre_apply_listing_that_is_no_array_fails_the_forget_and_forgets_nothing_by_id(
    edge_backup, machine, answer
):
    machine.plant("songmaker", _bound(machine) - SECOND)
    machine.snapshot_listing = answer

    outcome = edge_backup("backup")

    _assert_forget_failed_unreadable_and_forgot_nothing(outcome, machine)


def test_an_expired_entry_followed_by_an_unreadable_one_forgets_nothing_by_id(edge_backup, machine):
    machine.plant("songmaker", _bound(machine) - SECOND)
    machine.plant("songmaker", _bound(machine) - SECOND)
    machine.snapshots[-1]["time"] = None

    outcome = edge_backup("backup")

    _assert_forget_failed_unreadable_and_forgot_nothing(outcome, machine)


def test_every_app_that_backed_up_is_forgotten_and_the_repository_checked(
    edge_backup, machine, home
):
    outcome = edge_backup(*declare_two_apps(home), "backup")

    assert outcome.exit_code == 0, outcome.err
    assert machine.forget_scopes() == ["songmaker", "radio"]
    assert machine.labels()[-1] == "restic check"
    assert outcome.out.splitlines()[2] == "  ✓ repository      pruned         checked · <1s"


def test_a_failed_app_is_not_pruned_while_the_others_are_forgotten_and_checked(
    edge_backup, machine, home
):
    two_apps = declare_two_apps(home)
    first = edge_backup(*two_apps, "backup")
    songmaker_past = machine.plant("songmaker", _bound(machine) - SECOND)
    machine.plant("radio", _bound(machine) - SECOND)
    _fail_radio_readiness(machine)
    machine.calls.clear()

    outcome = edge_backup(*two_apps, "backup")

    assert outcome.exit_code == 3
    assert outcome.out.splitlines()[1:] == [
        "  ✗ radio           not backed up  2 database containers for radio instead of exactly one",
        "  · radio           not pruned     its backup failed",
        "  ✓ repository      pruned         checked · <1s",
    ]
    assert machine.forget_scopes() == ["songmaker"]
    assert machine.forgotten == [songmaker_past]
    assert machine.labels()[-1] == "restic check"
    assert (outcome.status["failing_app"], outcome.status["failing_phase"]) == (
        "radio",
        "readiness",
    )
    assert app_history(outcome.status, "radio") == app_history(first.status, "radio")


@pytest.mark.parametrize(
    ("arguments", "rows", "error_line"),
    [
        (
            (),
            [
                "  ✗ songmaker       not backed up  "
                "2 database containers for songmaker instead of exactly one",
                "  ✗ keycloak        not backed up  no database container after 10 min",
                "  · songmaker       not pruned     its backup failed",
                "  · keycloak        not pruned     its backup failed",
            ],
            "error: 2 of 2 apps not backed up · songmaker has no good backup recorded",
        ),
        (
            ("keycloak",),
            [
                "  ✗ keycloak        not backed up  no database container after 10 min",
                "  · keycloak        not pruned     its backup failed",
            ],
            "error: keycloak not backed up · no good backup recorded",
        ),
        (
            ("keycloak", "--pre-apply", "--json"),
            [],
            "error: keycloak: no database container after 10 min",
        ),
    ],
    ids=["every app", "one app", "one app before apply"],
)
def test_a_run_whose_every_app_failed_forgets_and_checks_nothing_and_prints_no_repository_row(
    edge_backup, machine, home, arguments, rows, error_line
):
    machine.db_containers = ["c0ffee", "c0ffee2"]
    machine.lose_keycloak_database()

    outcome = edge_backup(*declare_songmaker_and_keycloak(home), "backup", *arguments)

    assert outcome.exit_code == 3
    assert outcome.out.splitlines() == rows
    assert outcome.err.splitlines()[0] == error_line
    assert not {"restic forget", "restic snapshots", "restic check"} & set(machine.labels())


@pytest.mark.parametrize(
    "radio_fails", [False, True], ids=["apps backed up", "after an app failed"]
)
@pytest.mark.parametrize("failing_label", ["restic forget", "restic snapshots"])
def test_a_failed_forget_stops_the_maintenance_and_is_the_verdict(
    edge_backup, machine, home, radio_fails, failing_label
):
    if radio_fails:
        _fail_radio_readiness(machine)
    machine.failing[failing_label] = 1

    outcome = edge_backup(*declare_two_apps(home), "backup")

    assert outcome.exit_code == 3
    reason = f"forget: {failing_label} ended with exit 1"
    assert outcome.out.splitlines()[-1] == f"  ✗ repository      not pruned     {reason}"
    assert outcome.err.splitlines() == [f"error: {reason}", "next: hal backup"]
    assert (outcome.status["failing_app"], outcome.status["failing_phase"]) == (None, "forget")
    assert machine.forget_scopes() == ["songmaker"]
    assert "restic check" not in machine.labels()


@pytest.mark.parametrize(
    "radio_fails", [False, True], ids=["apps backed up", "after an app failed"]
)
def test_a_failed_check_is_the_verdict_also_after_an_app_failure(
    edge_backup, machine, home, radio_fails
):
    if radio_fails:
        _fail_radio_readiness(machine)
    machine.failing["restic check"] = 1

    outcome = edge_backup(*declare_two_apps(home), "backup")

    assert outcome.exit_code == 3
    reason = "check: restic check ended with exit 1"
    assert outcome.out.splitlines()[-1] == f"  ✗ repository      not checked    {reason}"
    assert outcome.err.splitlines() == [f"error: {reason}", "next: hal backup"]
    assert (outcome.status["failing_app"], outcome.status["failing_phase"]) == (None, "check")


@pytest.mark.parametrize(
    ("failing_label", "phase"), [("restic forget", "forget"), ("restic check", "check")]
)
def test_a_repository_failure_in_the_maintenance_ends_the_run_with_the_rows_printed_so_far(
    edge_backup, machine, home, failing_label, phase
):
    machine.failing[failing_label] = min(REPOSITORY_EXIT_CODES)

    outcome = edge_backup(*declare_two_apps(home), "backup")

    assert outcome.exit_code == 3
    assert [line.split()[1] for line in outcome.out.splitlines()] == ["songmaker", "radio"]
    assert (outcome.status["failing_app"], outcome.status["failing_phase"]) == (None, phase)
