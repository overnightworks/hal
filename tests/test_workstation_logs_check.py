"""`hal check`'s logs check (overnightworks/edge#167 cells C1 and C2) against fake docker and journalctl."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from hal.workstation import logs_check
from hal.workstation.system_step import LOG_RETENTION_DAYS

NOW = datetime(2026, 10, 22, 12, 0)


def boots_json(*first_entries: datetime) -> str:
    return json.dumps([{"index": -i, "first_entry": int(entry.timestamp() * 1_000_000)} for i, entry in enumerate(first_entries)])


class FakeMachine:
    """Answers the three tools the check reads; an answer of None is a tool that cannot run."""

    def __init__(self) -> None:
        self.containers: list[tuple[str, str, str]] = []  # name, log driver, compose project
        self.default_driver: str | None = "journald"
        self.failing_docker_commands: set[str] = set()
        self.removed_containers: set[str] = set()
        self.uninspectable_containers: set[str] = set()  # still listed, but `docker inspect` fails
        self.listings = 0
        self.boots: str | None = boots_json(NOW - timedelta(days=3))
        self.system_boots: str | None = self.boots

    def __call__(self, argv: Sequence[str]) -> str | None:
        if argv[0] == "journalctl":
            return self.system_boots if "--system" in argv else self.boots
        if argv[1] in self.failing_docker_commands:
            return None
        if argv[1] == "ps":
            self.listings += 1
            gone = self.removed_containers if self.listings > 1 else set()
            return "".join(f"id{i}\n" for i, (name, _, _) in enumerate(self.containers) if name not in gone)
        if argv[1] == "info":
            return None if self.default_driver is None else self.default_driver + "\n"
        name, driver, project = self.containers[int(argv[-1].removeprefix("id"))]
        return None if name in self.removed_containers | self.uninspectable_containers else f"/{name}\t{driver}\t{project}\n"


@pytest.fixture
def machine() -> FakeMachine:
    return FakeMachine()


@pytest.fixture
def log_directory(tmp_path: Path) -> Path:
    directory = tmp_path / "var-log"
    directory.mkdir()
    return directory


def findings(machine: FakeMachine, log_directory: Path) -> dict[tuple[str, str], str]:
    found, _report = logs_check.inspect(machine, NOW, log_directory)
    return {(f.rule, f.subject): f.detail for f in found}


def test_a_machine_whose_logs_all_go_to_the_journal_has_no_findings(machine, log_directory) -> None:
    machine.containers = [("app-web-1", "journald", "app"), ("one-off", "none", "")]

    assert findings(machine, log_directory) == {}


def test_a_json_file_container_is_a_finding_naming_it_and_its_project(machine, log_directory) -> None:
    machine.containers = [("songmaker-api-1", "json-file", "songmaker"), ("edge-ca-1", "journald", "edge"), ("lonely", "json-file", "")]

    found = findings(machine, log_directory)

    assert set(found) == {("container-json-file", "songmaker-api-1"), ("container-json-file", "lonely")}
    assert "songmaker" in found[("container-json-file", "songmaker-api-1")]
    assert "Compose" in found[("container-json-file", "lonely")]


def test_a_default_driver_other_than_journald_is_a_finding(machine, log_directory) -> None:
    machine.default_driver = "json-file"

    assert set(findings(machine, log_directory)) == {("docker-default-driver", "json-file")}


@pytest.mark.parametrize(("days_old", "is_finding"), [(LOG_RETENTION_DAYS, False), (LOG_RETENTION_DAYS + 1, True)])
def test_a_journal_entry_older_than_the_retention_is_a_finding(machine, log_directory, days_old, is_finding) -> None:
    machine.boots = boots_json(NOW - timedelta(days=3), NOW - timedelta(days=days_old), NOW - timedelta(days=10))

    assert (("journal-age", "journal") in findings(machine, log_directory)) is is_finding


def test_the_report_states_the_journal_age_and_the_default_driver_without_a_finding(machine, log_directory) -> None:
    _found, report = logs_check.inspect(machine, NOW, log_directory)

    assert "3 days old" in report
    assert "Docker default driver: journald" in report
    assert (NOW - timedelta(days=3)).astimezone().strftime("%Y-%m-%d") in report


def test_an_rsyslog_file_and_its_archives_are_findings_by_name(machine, log_directory) -> None:
    for name in ["syslog", "syslog.1", "auth.log.2.gz", "dpkg.log"]:
        (log_directory / name).write_text("content that is never read")

    assert {subject for rule, subject in findings(machine, log_directory) if rule == "rsyslog-file"} == {
        str(log_directory / name) for name in ["syslog", "syslog.1", "auth.log.2.gz"]
    }


@pytest.mark.parametrize("unreadable", ["no output", "not json", "wrong shape", "no boots"])
def test_a_journal_that_cannot_be_read_is_a_finding_of_its_own(machine, log_directory, unreadable) -> None:
    machine.boots = machine.system_boots = {"no output": None, "not json": "denied", "wrong shape": '[{"index": 0}]', "no boots": "[]"}[unreadable]

    assert set(findings(machine, log_directory)) == {("journal-unreadable", "journal")}


@pytest.mark.parametrize("failing", [{"ps", "inspect", "info"}, {"info"}, {"inspect"}])
def test_a_docker_that_cannot_be_run_is_one_finding_not_a_pass(machine, log_directory, failing) -> None:
    machine.containers = [("app-web-1", "journald", "app")]
    machine.failing_docker_commands = failing

    assert set(findings(machine, log_directory)) == {("docker-unreadable", "docker")}


def test_a_missing_log_directory_has_no_rsyslog_files(machine, tmp_path) -> None:
    assert findings(machine, tmp_path / "absent") == {}


def test_a_container_removed_between_listing_and_inspection_is_gone_not_a_docker_failure(machine, log_directory) -> None:
    machine.containers = [("probe-1", "json-file", "probe"), ("app-web-1", "json-file", "app")]
    machine.removed_containers = {"probe-1"}

    assert set(findings(machine, log_directory)) == {("container-json-file", "app-web-1")}


def test_the_findings_of_inspected_containers_stay_next_to_the_one_that_cannot_be_inspected(machine, log_directory) -> None:
    machine.containers = [("app-web-1", "json-file", "app"), ("app-db-1", "journald", "app")]
    machine.uninspectable_containers = {"app-db-1"}

    assert set(findings(machine, log_directory)) == {("container-json-file", "app-web-1"), ("docker-unreadable", "docker")}


def test_a_system_journal_that_cannot_be_read_is_named_while_the_merged_age_still_counts(machine, log_directory) -> None:
    machine.system_boots = None
    machine.boots = boots_json(NOW - timedelta(days=LOG_RETENTION_DAYS + 1))

    found = findings(machine, log_directory)

    assert set(found) == {("journal-unreadable", "journal"), ("journal-age", "journal")}
    assert "partial view" in found[("journal-unreadable", "journal")]


def test_the_age_counts_the_hour_the_autumn_clock_change_adds(machine, log_directory, berlin_time) -> None:
    berlin = ZoneInfo("Europe/Berlin")
    oldest = datetime(2026, 9, 26, 12, 30, tzinfo=berlin)  # 29 days 23:30 on the wall clock, 30 days 00:30 in fact
    machine.boots = machine.system_boots = boots_json(oldest)

    found, _report = logs_check.inspect(machine, datetime(2026, 10, 26, 12, 0), log_directory)

    assert [(f.rule, f.subject) for f in found] == [("journal-age", "journal")]
