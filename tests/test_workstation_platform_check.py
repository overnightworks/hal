"""`hal check`'s platform check (overnightworks/edge#340 C1-C3, C6, S1, S4, R1, Z2, Z3; #460 D1-D4; #466 S-1..S-7) against a fake docker, a reboot flag file and a fake disk."""

from __future__ import annotations

import os
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

import pytest
from support.workstation_support import ALLOWED_PLATFORM_INSPECT_FORMAT, CANARY_INSPECT_LINE, INSPECT_CANARY, FakeDisk, unit_listing_matching

from hal.workstation import platform_check

NOW = datetime(2026, 10, 23, 12, 0)


class FakeDocker:
    """Answers `docker ps`, `docker inspect` and the failed-unit listing of systemctl; an inspect with any format but the allowed one answers the canary line."""

    def __init__(self) -> None:
        self.containers: list[tuple[str, str, str, int, str]] = []  # name, status, health, exit code, compose project (empty: none)
        self.unreadable = False
        self.failed_units: str | None = ""  # what `systemctl --user list-units --state=failed` prints; None: systemctl fails
        self.removed_while_inspected: list[str] = []  # each inspect call takes one name: it fails and that container is gone
        self.inspect_calls: list[list[str]] = []

    def add(self, name: str, status: str = "running", health: str = "", exit_code: int = 0, project: str = "edge") -> None:
        self.containers.append((name, status, health, exit_code, project))

    def __call__(self, argv: Sequence[str]) -> str | None:
        if argv[0] == "systemctl":
            return unit_listing_matching(self.failed_units, argv[-1])
        if self.unreadable:
            return None
        if argv[:2] == ["docker", "ps"]:
            return "".join(f"{container[0]}\n" for container in self.containers)
        self.inspect_calls.append(list(argv))
        if argv[3] != ALLOWED_PLATFORM_INSPECT_FORMAT:
            return CANARY_INSPECT_LINE
        if self.removed_while_inspected:
            gone = self.removed_while_inspected.pop(0)
            self.containers = [container for container in self.containers if container[0] != gone]
            return None
        listed = [container for container in self.containers if container[0] in argv[4:]]
        return "".join(f"/{n}\t{s}\t{h}\t{c}\t{p}\n" for n, s, h, c, p in listed)


@pytest.fixture
def docker() -> FakeDocker:
    return FakeDocker()


@pytest.fixture
def reboot_file(tmp_path: Path) -> Path:
    return tmp_path / "reboot-required"


def rules_found(docker: FakeDocker, reboot_file: Path, disk: FakeDisk, switched_off: frozenset[str] = frozenset()) -> set[tuple[str, str]]:
    findings, _report = platform_check.inspect(docker, NOW, reboot_file, disk, switched_off)
    return {(f.rule, f.subject) for f in findings}


@pytest.mark.parametrize(
    ("status", "health", "exit_code", "rule"),
    [
        ("running", "unhealthy", 0, "container-unhealthy"),
        ("restarting", "", 1, "container-restarting"),
        ("dead", "", 0, "container-dead"),
        ("exited", "", 137, "container-exited"),
        ("exited", "", 1, "container-exited"),
    ],
)
def test_a_broken_compose_container_is_a_finding_named_by_its_state(docker, reboot_file, fake_disk, status, health, exit_code, rule) -> None:
    docker.add("edge-step-ca-1", status, health, exit_code)

    assert rules_found(docker, reboot_file, fake_disk) == {(rule, "edge")}


@pytest.mark.parametrize(
    ("status", "health", "exit_code", "project"),
    [
        ("running", "healthy", 0, "edge"),
        ("running", "starting", 0, "edge"),
        ("running", "", 0, "edge"),
        ("exited", "", 0, "edge"),
        ("exited", "unhealthy", 0, "edge"),
        ("created", "", 0, "edge"),
        ("exited", "", 1, ""),
        ("running", "unhealthy", 0, ""),
    ],
)
def test_a_container_that_is_fine_or_outside_compose_is_no_finding(docker, reboot_file, fake_disk, status, health, exit_code, project) -> None:
    docker.add("some-container", status, health, exit_code, project)

    assert rules_found(docker, reboot_file, fake_disk) == set()


def test_a_machine_without_containers_is_clean(docker, reboot_file, fake_disk) -> None:
    assert rules_found(docker, reboot_file, fake_disk) == set()


def test_docker_that_cannot_be_read_is_a_finding_never_a_pass(docker, reboot_file, fake_disk) -> None:
    docker.unreadable = True

    assert rules_found(docker, reboot_file, fake_disk) == {("docker-unreadable", "docker")}


def test_a_container_removed_during_the_inspection_is_no_finding_and_the_rest_is_still_judged(docker, reboot_file, fake_disk) -> None:
    docker.add("edge-job-1", "exited", "", 1)
    docker.add("edge-broken-1", "running", "unhealthy")
    docker.removed_while_inspected = ["edge-job-1"]

    assert rules_found(docker, reboot_file, fake_disk) == {("container-unhealthy", "edge")}


def test_the_only_container_removed_during_the_inspection_leaves_a_clean_machine(docker, reboot_file, fake_disk) -> None:
    docker.add("edge-job-1", "exited", "", 1)
    docker.removed_while_inspected = ["edge-job-1"]

    assert rules_found(docker, reboot_file, fake_disk) == set()


def test_two_failed_inspections_in_a_row_are_docker_unreadable(docker, reboot_file, fake_disk) -> None:
    docker.add("edge-first-1")
    docker.add("edge-second-1")
    docker.removed_while_inspected = ["edge-first-1", "edge-second-1"]

    assert rules_found(docker, reboot_file, fake_disk) == {("docker-unreadable", "docker")}


def test_many_containers_are_inspected_in_one_call_and_healthy_ones_appear_only_as_a_count(docker, reboot_file, fake_disk) -> None:
    for number in range(5):
        docker.add(f"edge-service-{number}-1", "running", "healthy")
    docker.add("edge-broken-1", "running", "unhealthy")

    findings, report = platform_check.inspect(docker, NOW, reboot_file, fake_disk, frozenset())

    assert len(docker.inspect_calls) == 1
    assert [f.subject for f in findings] == ["edge"]
    assert "edge-service-0-1" not in report
    assert "davon in Ordnung 5" in report


def test_a_wider_projection_than_the_named_fields_would_show_in_the_report_and_the_allowed_one_keeps_it_out(docker, reboot_file, fake_disk) -> None:
    docker.add("edge-step-ca-1", "running", "unhealthy")

    findings, report = platform_check.inspect(docker, NOW, reboot_file, fake_disk, frozenset())

    assert docker.inspect_calls[0][3] == ALLOWED_PLATFORM_INSPECT_FORMAT
    assert [f.subject for f in findings] == ["edge"]
    assert INSPECT_CANARY not in report


def test_the_retry_after_a_failed_inspection_asks_for_the_same_named_fields_only(docker, reboot_file, fake_disk) -> None:
    docker.add("edge-job-1", "exited", "", 1)
    docker.add("edge-step-ca-1", "running", "unhealthy")
    docker.removed_while_inspected = ["edge-job-1"]

    _findings, report = platform_check.inspect(docker, NOW, reboot_file, fake_disk, frozenset())

    assert [call[3] for call in docker.inspect_calls] == [ALLOWED_PLATFORM_INSPECT_FORMAT] * 2
    assert INSPECT_CANARY not in report


def test_a_pending_reboot_is_a_finding_with_the_date_the_flag_appeared(docker, reboot_file, fake_disk) -> None:
    reboot_file.write_text(INSPECT_CANARY)
    flagged = datetime(2026, 10, 16, 8, 0).timestamp()
    os.utime(reboot_file, (flagged, flagged))

    findings, report = platform_check.inspect(docker, NOW, reboot_file, fake_disk, frozenset())

    assert [(f.rule, f.subject) for f in findings] == [("reboot-pending", "reboot")]
    assert "seit 16.10.2026" in findings[0].detail
    assert INSPECT_CANARY not in report


def test_the_reboot_finding_keeps_its_identity_as_the_flag_ages(docker, reboot_file, fake_disk) -> None:
    reboot_file.touch()
    first, _ = platform_check.inspect(docker, NOW, reboot_file, fake_disk, frozenset())
    os.utime(reboot_file, (1.0, 1.0))
    later, _ = platform_check.inspect(docker, NOW, reboot_file, fake_disk, frozenset())

    assert [f.identity for f in first] == [f.identity for f in later]


@pytest.mark.parametrize("free_share", [0.09, 0.0], ids=["9 percent", "none left"])
def test_less_than_a_tenth_free_on_the_root_disk_is_a_finding_and_only_the_root_disk_is_asked(docker, reboot_file, fake_disk, free_share) -> None:
    """#460 D1, D4: under a tenth free is a finding, and only the root disk is asked."""
    fake_disk.free_share = free_share

    assert rules_found(docker, reboot_file, fake_disk) == {("disk-low", "/")}
    assert fake_disk.asked == [Path("/")]


@pytest.mark.parametrize("free_share", [0.10, 0.25], ids=["exactly 10 percent", "25 percent"])
def test_a_tenth_free_or_more_is_no_finding(docker, reboot_file, fake_disk, free_share) -> None:
    """#460 D1: a tenth free or more is no finding."""
    fake_disk.free_share = free_share

    assert rules_found(docker, reboot_file, fake_disk) == set()


def test_the_report_carries_the_free_and_total_gigabytes_and_the_share(docker, reboot_file, fake_disk) -> None:
    """#460 D3: the report carries the free and total gigabytes and the share."""
    fake_disk.free_share = 0.19
    _findings, quiet_report = platform_check.inspect(docker, NOW, reboot_file, fake_disk, frozenset())
    fake_disk.free_share = 0.08
    findings, report = platform_check.inspect(docker, NOW, reboot_file, fake_disk, frozenset())

    assert "- Festplatte /: 190 GB von 1000 GB frei (19 %)" in quiet_report
    assert "- Festplatte /: 80 GB von 1000 GB frei (8 %)" in report
    assert "| disk-low | / | 80 GB von 1000 GB frei (8 %) |" in report
    assert [f.subject for f in findings] == ["/"]


def test_the_disk_finding_keeps_its_identity_as_the_free_space_shrinks(docker, reboot_file, fake_disk) -> None:
    """#460 D1 (#340 I1): the finding keeps its identity as the free space shrinks."""
    fake_disk.free_share = 0.09
    first, _ = platform_check.inspect(docker, NOW, reboot_file, fake_disk, frozenset())
    fake_disk.free_share = 0.07
    later, _ = platform_check.inspect(docker, NOW, reboot_file, fake_disk, frozenset())

    assert [f.identity for f in first] == [f.identity for f in later]


def test_the_share_prints_rounded_down_without_a_floating_point_error(docker, reboot_file, fake_disk) -> None:
    """#460 D3: 29 GB free of 100 GB reads 29 %, never 28 %."""
    fake_disk.free_share = 0.29

    _findings, report = platform_check.inspect(docker, NOW, reboot_file, fake_disk, frozenset())

    assert "- Festplatte /: 290 GB von 1000 GB frei (29 %)" in report


def test_the_real_disk_reader_reports_a_total_and_a_free_figure_in_bytes(tmp_path) -> None:
    """#460 D1: the reader behind the finding answers for a real path; only its shape is asserted, never how full this disk is."""
    space = platform_check.read_disk_space(tmp_path)

    assert 0 <= space.free <= space.total
    assert space.total > 0


HOPIN_OFF = frozenset({"hopin"})


def test_a_switched_off_apps_exited_container_is_no_finding_and_the_report_names_the_switch_without_counting_it_as_fine(docker, reboot_file, fake_disk) -> None:
    """#466 S-1 (#415 Z8): a container of an app switched off with hal stop is no finding; the report stays honest."""
    docker.add("hopin-web-1", "exited", "", 143, "hopin")
    docker.add("edge-step-ca-1", "running", "healthy")

    findings, report = platform_check.inspect(docker, NOW, reboot_file, fake_disk, HOPIN_OFF)

    assert findings == []
    assert "Container mit Compose-Projekt: 2, davon in Ordnung 1" in report
    assert "Mit hal stop abgeschaltet: hopin" in report


@pytest.mark.parametrize("exit_code", [137, 1, 2])
def test_a_switched_off_apps_exited_container_is_no_finding_whatever_its_code(docker, reboot_file, fake_disk, exit_code) -> None:
    """#466 S-2: Z8 judges the switch, not the code the app's signal handling ends with."""
    docker.add("hopin-web-1", "exited", "", exit_code, "hopin")

    assert rules_found(docker, reboot_file, fake_disk, HOPIN_OFF) == set()


def test_the_same_exit_without_a_switch_is_a_finding(docker, reboot_file, fake_disk) -> None:
    """#466 S-3: the Z8 counterexample."""
    docker.add("hopin-web-1", "exited", "", 143, "hopin")

    assert rules_found(docker, reboot_file, fake_disk) == {("container-exited", "hopin")}


def test_another_apps_exit_is_a_finding_while_one_app_is_switched_off(docker, reboot_file, fake_disk) -> None:
    """#466 S-4."""
    docker.add("presentator-web-1", "exited", "", 1, "presentator")

    assert rules_found(docker, reboot_file, fake_disk, HOPIN_OFF) == {("container-exited", "presentator")}


@pytest.mark.parametrize(
    ("status", "health", "rule"),
    [("restarting", "", "container-restarting"), ("dead", "", "container-dead"), ("running", "unhealthy", "container-unhealthy")],
)
def test_a_switched_off_app_that_broke_after_being_started_again_is_still_a_finding(docker, reboot_file, fake_disk, status, health, rule) -> None:
    """#466 S-5: a stop ends in exited, so these states mean the app was started again under the switch."""
    docker.add("hopin-web-1", status, health, 0, "hopin")

    assert rules_found(docker, reboot_file, fake_disk, HOPIN_OFF) == {(rule, "hopin")}


def test_only_compose_project_names_in_the_switch_directory_are_switches(tmp_path) -> None:
    """#466 S-6: a half-written temporary and a foreign name are no switch."""
    directory = tmp_path / platform_check.SWITCHES_DIRECTORY
    directory.mkdir(parents=True)
    for name in (".hopin.k3x9", "Bad Name", "hopin", "other-app"):
        (directory / name).write_text("2026-10-27T09:00:00+01:00")

    assert platform_check.read_switched_off(tmp_path) == {"hopin", "other-app"}


def test_a_missing_switch_directory_means_no_switch_and_the_report_has_no_switch_line(docker, reboot_file, fake_disk, tmp_path) -> None:
    """#466 S-7."""
    switched_off = platform_check.read_switched_off(tmp_path)
    _findings, report = platform_check.inspect(docker, NOW, reboot_file, fake_disk, switched_off)

    assert switched_off == frozenset()
    assert "abgeschaltet" not in report


FAILED_UNIT_LINE = "{name} loaded failed failed {description}\n"


def failed_listing(*names: str, description: str = "A hal job") -> str:
    return "".join(FAILED_UNIT_LINE.format(name=name, description=description) for name in names)


@pytest.mark.parametrize("name", ["hal-backup.service", "hal-backup-restore-test.service", "hal-check.timer"])
def test_a_failed_hal_unit_is_a_job_failed_finding_named_by_the_unit(docker, reboot_file, fake_disk, name) -> None:
    docker.failed_units = failed_listing(name)

    assert rules_found(docker, reboot_file, fake_disk) == {("job-failed", name)}


def test_a_failed_unit_that_is_not_a_hal_unit_is_ignored(docker, reboot_file, fake_disk) -> None:
    docker.failed_units = failed_listing("other-fail.service", "hal-x.service")

    assert rules_found(docker, reboot_file, fake_disk) == {("job-failed", "hal-x.service")}


def test_several_failed_hal_units_are_one_finding_each(docker, reboot_file, fake_disk) -> None:
    docker.failed_units = failed_listing("hal-backup.service", "hal-check.service")

    assert rules_found(docker, reboot_file, fake_disk) == {("job-failed", "hal-backup.service"), ("job-failed", "hal-check.service")}


def test_systemd_that_cannot_be_read_is_a_finding_and_the_containers_are_still_judged(docker, reboot_file, fake_disk) -> None:
    docker.failed_units = None
    docker.add("edge-broken-1", "running", "unhealthy")

    assert rules_found(docker, reboot_file, fake_disk) == {("systemd-unreadable", "systemd"), ("container-unhealthy", "edge")}


@pytest.mark.parametrize("first_token", ["hal backup.service", "hal-Backup.service", "hal-backup.mount", "hal$(touch PWNED).service", "hal_x.service"])
def test_a_first_column_that_breaks_the_naming_form_is_unreadable(docker, reboot_file, fake_disk, first_token) -> None:
    docker.failed_units = f"{first_token} loaded failed failed x\n"

    assert ("systemd-unreadable", "systemd") in rules_found(docker, reboot_file, fake_disk)


def test_no_column_but_the_unit_name_reaches_the_findings_or_the_report(docker, reboot_file, fake_disk) -> None:
    docker.failed_units = failed_listing("hal-backup.service", description="CANARY-DESC")

    findings, report = platform_check.inspect(docker, NOW, reboot_file, fake_disk, frozenset())

    assert "CANARY" not in report + repr(findings)
    assert "hal-backup.service" in report
