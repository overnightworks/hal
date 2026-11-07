"""The timer jobs hal runs on this machine: the one place a job's unit name, command, schedule and
service settings are written. `hal setup` writes the units from these declarations.

This module holds no systemd text; the unit writer renders it.
"""

from __future__ import annotations

from dataclasses import dataclass

from hal.output import LogFormat
from hal.output.command import Verb, command

ALARM_JOB_NAME = "hal-alarm"
DEFAULT_ALARM_INTERVAL = 5


@dataclass(frozen=True)
class TimerJob:
    """One `hal` verb that a systemd timer runs on a calendar."""

    name: str
    service_description: str
    timer_description: str
    verb: Verb
    arguments: tuple[str, ...]
    timeout_start: str | None = None
    success_exit_statuses: tuple[int, ...] = ()
    documentation: str | None = None
    on_calendar: str | None = None
    """A calendar event; a job has this or `interval_minutes`."""
    interval_minutes: int | None = None
    """Minutes after boot and after each run, for a job whose repetition comes from the settings file."""
    log_format: LogFormat | None = None
    """The format the unit sets for the run's log; none leaves the variable unset."""


def alarm_job(interval: int) -> TimerJob:
    return TimerJob(
        name=ALARM_JOB_NAME,
        service_description=(
            f"{command(Verb.ALARM)}: mails a service or backup finding that several runs in a row"
            " reported, and one that went"
        ),
        timer_description=f"{command(Verb.ALARM)} every {interval} minutes",
        verb=Verb.ALARM,
        arguments=(),
        interval_minutes=interval,
    )


TIMER_JOBS: tuple[TimerJob, ...] = (
    TimerJob(
        name="hal-backup",
        service_description=f"{command(Verb.BACKUP)}: encrypted restic backup of the declared apps",
        timer_description=f"{command(Verb.BACKUP)} weekly, Sunday 03:00",
        # The checkout lives at ~/srv/hal and `uv sync` has built the .venv that ExecStart runs.
        verb=Verb.BACKUP,
        arguments=(),
        on_calendar="Sun *-*-* 03:00:00",
        timeout_start="6h",
        documentation="docs/backup.md",
        log_format=LogFormat.JSON,
    ),
    TimerJob(
        name="hal-backup-restore-test",
        service_description=f"{command(Verb.BACKUP)}: restore the latest snapshots and prove they are good",
        timer_description=f"{command(Verb.BACKUP)} restore test monthly, first Sunday 05:00",
        verb=Verb.RESTORE,
        arguments=("--test",),
        # Two hours after the weekly backup; the host lock serialises them if the backup runs long.
        on_calendar="Sun *-*-01..07 05:00:00",
        timeout_start="6h",
        documentation="docs/backup.md",
        log_format=LogFormat.JSON,
    ),
    TimerJob(
        name="hal-check",
        service_description=(
            f"{command(Verb.CHECK)}: reports what is wrong on this machine and in the secrets"
            " manifest; mails only when a finding appears or goes"
        ),
        timer_description=f"Daily {command(Verb.CHECK)}",
        verb=Verb.CHECK,
        arguments=(),
        on_calendar="*-*-* 09:00",
        # Exit 1 means "findings exist": news, not a failure. Exit 2 (invalid config) and 3
        # (unexpected error) still fail the unit.
        success_exit_statuses=(1,),
    ),
    TimerJob(
        name="hal-expire",
        service_description=(
            f"{command(Verb.EXPIRE)}: deletes what LiteLLM keeps per person, per tool or per label once unused"
            " for its retention period"
        ),
        timer_description=f"Daily {command(Verb.EXPIRE)}, 04:00",
        verb=Verb.EXPIRE,
        arguments=(),
        on_calendar="*-*-* 04:00:00",
        timeout_start="15min",
        documentation="docs/agent-service.md",
        log_format=LogFormat.JSON,
    ),
    alarm_job(DEFAULT_ALARM_INTERVAL),
)


def with_alarm_interval(declared: tuple[TimerJob, ...], interval: int) -> tuple[TimerJob, ...]:
    """The declared jobs with the alarm's repetition from the settings file."""
    return tuple(alarm_job(interval) if job.name == ALARM_JOB_NAME else job for job in declared)
