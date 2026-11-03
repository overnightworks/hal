"""`hal check`'s logs check: reports the age and the driver of every log store the 30-day bound covers.

It reads the container log drivers, Docker's default driver, the journal's oldest entry and the rsyslog files, and
changes nothing. No message text is read: the journal's age comes from the boot list's timestamps. A store it cannot
read is a finding of its own, never a pass.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hal.workstation.report import Finding, render_findings_report
from hal.workstation.system_step import DOCKER_DEFAULT_DRIVER, DOCKER_LOG_DRIVER, LOG_RETENTION_DAYS, RSYSLOG_FILE_NAMES
from hal.workstation.layout import CommandRunner

LOG_DIRECTORY = Path("/var/log")
JSON_FILE_DRIVER = "json-file"
MICROSECONDS_PER_SECOND = 1_000_000

DOCKER_CONTAINER_IDS = ["docker", "ps", "-aq"]
INSPECT_FORMAT = '{{.Name}}\t{{.HostConfig.LogConfig.Type}}\t{{index .Config.Labels "com.docker.compose.project"}}'
JOURNAL_BOOTS = ["journalctl", "--list-boots", "-o", "json"]
SYSTEM_JOURNAL_BOOTS = ["journalctl", "--system", "--list-boots", "-o", "json"]


@dataclass(frozen=True)
class LogReading:
    """What the check saw of the stores; the findings and the lines that state each store's driver or age."""

    findings: list[Finding]
    status_lines: list[str]


def _container_findings(run: CommandRunner) -> LogReading:
    identifiers = run(DOCKER_CONTAINER_IDS)
    if identifiers is None:
        return LogReading([Finding("docker-unreadable", "docker", "`docker ps -a` lässt sich nicht ausführen")], [])
    findings = []
    inspected = 0
    failed_inspections = []
    for identifier in identifiers.split():
        listing = run(["docker", "inspect", "--format", INSPECT_FORMAT, identifier])
        if listing is None:
            failed_inspections.append(identifier)
            continue
        inspected += 1
        name, driver, project = listing.rstrip("\n").split("\t")
        if driver == JSON_FILE_DRIVER:
            where = f"Projekt {project}" if project else "ohne Compose-Projekt"
            findings.append(Finding("container-json-file", name.removeprefix("/"), f"Treiber {JSON_FILE_DRIVER}, {where}"))
    if failed_inspections:
        still_listed = run(DOCKER_CONTAINER_IDS)  # an id that is gone from a second listing was removed; any other failure is unread
        if still_listed is None or set(failed_inspections) & set(still_listed.split()):
            findings.append(Finding("docker-unreadable", "docker", "`docker inspect` lässt sich nicht ausführen"))
            return LogReading(findings, [])
    return LogReading(findings, [f"Container: {inspected}, davon {len(findings)} mit {JSON_FILE_DRIVER}"])


def _default_driver_findings(run: CommandRunner) -> LogReading:
    output = run(DOCKER_DEFAULT_DRIVER)
    if output is None:
        return LogReading([Finding("docker-unreadable", "docker", "`docker info` lässt sich nicht ausführen")], [])
    driver = output.strip()
    status_lines = [f"Docker-Standardtreiber: {driver}"]
    if driver == DOCKER_LOG_DRIVER:
        return LogReading([], status_lines)
    return LogReading([Finding("docker-default-driver", driver, f"Standardtreiber ist {driver}, erwartet {DOCKER_LOG_DRIVER}")], status_lines)


def _oldest_journal_entry(boots_json: str) -> datetime | None:
    """The earliest `first_entry` (microseconds since the epoch) of any boot, as a local time; None when no boot is listed."""
    boots = json.loads(boots_json)
    oldest = min((boot["first_entry"] for boot in boots), default=None)
    return None if oldest is None else datetime.fromtimestamp(oldest / MICROSECONDS_PER_SECOND, tz=UTC).astimezone()


def _oldest_entry_or_none(output: str | None) -> datetime | None:
    try:
        return None if output is None else _oldest_journal_entry(output)
    except (ValueError, KeyError, TypeError):
        return None


def _journal_findings(run: CommandRunner, now: datetime) -> LogReading:
    oldest = _oldest_entry_or_none(run(JOURNAL_BOOTS))
    if oldest is None:
        return LogReading([Finding("journal-unreadable", "journal", "`journalctl --list-boots` liefert kein lesbares Ergebnis")], [])
    findings = []
    if _oldest_entry_or_none(run(SYSTEM_JOURNAL_BOOTS)) is None:
        findings.append(Finding("journal-unreadable", "journal", "Systemjournal nicht lesbar, nur Teilansicht"))
    age = now.astimezone() - oldest
    status_lines = [f"Journal: ältester Eintrag {oldest:%d.%m.%Y}, {age.days} Tage alt"]
    if age > timedelta(days=LOG_RETENTION_DAYS):
        detail = f"ältester Eintrag {oldest:%d.%m.%Y}, {age.days} Tage alt, erlaubt {LOG_RETENTION_DAYS}"
        findings.append(Finding("journal-age", "journal", detail))
    return LogReading(findings, status_lines)


def _rsyslog_findings(log_directory: Path) -> LogReading:
    """A file is an rsyslog file by its name, or by its name plus a rotation suffix; its content is never opened."""
    found = sorted(
        path
        for path in (log_directory.iterdir() if log_directory.is_dir() else [])
        if any(path.name == name or path.name.startswith(f"{name}.") for name in RSYSLOG_FILE_NAMES)
    )
    findings = [Finding("rsyslog-file", str(path), "rsyslog schreibt hier mit; das Journal ist der einzige Speicher") for path in found]
    return LogReading(findings, [f"rsyslog-Dateien in {log_directory}: {len(found)}"])


def collect(run: CommandRunner, now: datetime, log_directory: Path) -> LogReading:
    readings = [_container_findings(run), _default_driver_findings(run), _journal_findings(run, now), _rsyslog_findings(log_directory)]
    findings: list[Finding] = []
    status_lines: list[str] = []
    for reading in readings:
        findings.extend(reading.findings)
        status_lines.extend(reading.status_lines)
    return LogReading(_without_repeats(findings), status_lines)


def _without_repeats(findings: list[Finding]) -> list[Finding]:
    """A tool that cannot run fails each of its reads alike; one finding says it once."""
    return list({finding.identity: finding for finding in findings}.values())


def inspect(run: CommandRunner, now: datetime, log_directory: Path) -> tuple[list[Finding], str]:
    """What `hal check` reads of the log stores; findings and their report."""
    reading = collect(run, now, log_directory)
    return reading.findings, render_findings_report("logs", now, reading.status_lines, reading.findings)
