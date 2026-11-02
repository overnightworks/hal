"""The user-units step of `hal setup`: hal's timer jobs written as systemd units, then enabled.

Each declared job (`hal.workstation.jobs`) becomes a `.service` and a `.timer` file in the user's
unit directory, led by a marker line that says hal rewrites it. systemd reloads after a change and
each timer is enabled and running. The only entries hal replaces are its own marker files and the
links an earlier hal wrote into the live checkout's `systemd/` directory (and the `timers.target`
dependency links of those); every other same-name entry, a drop-in aside, is the person's: the
step refuses before it changes anything. Every replacement renames over the old entry, so a unit
name never has a moment without a unit. A failure after that check is `UnitsPartial`: a fresh run
classifies what is there and finishes. `systemctl --user` runs through the same command boundary as
the other steps' tools.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from hal.output import LOG_FORMAT_VARIABLE
from hal.output.command import Verb, command
from hal.workstation.jobs import TimerJob
from hal.workstation.layout import CommandRunner, Layout
from hal.workstation.system_step import Applied, CheckState, StepFailed

GENERATED_MARKER = (
    f"# Written by {command(Verb.SETUP)} from hal's job declaration; it rewrites this file."
    " Put your own changes in a drop-in."
)
SERVICE_SUFFIX = ".service"
TIMER_SUFFIX = ".timer"
TIMERS_WANTS_DIRECTORY = "timers.target.wants"
SHOWN_PROPERTIES = "NeedDaemonReload,UnitFileState,ActiveState"
DEPENDENCY_DIRECTORY_SUFFIXES = (".wants", ".requires")
UNIT_FILE_MODE = 0o644


class UnitsPartial(StepFailed):
    """The step failed after it had classified every entry, so some units may be written."""

    @classmethod
    def of(cls, error: OSError | StepFailed) -> UnitsPartial:
        if isinstance(error, StepFailed):
            return cls(str(error))
        return cls(f"{error.filename}: {error.strerror}")


@dataclass(frozen=True)
class LoadedUnit:
    """What systemd reports about one unit it knows."""

    needs_reload: bool
    enabled: bool
    active_state: str

    @classmethod
    def parse(cls, shown: str) -> LoadedUnit:
        lines = [line.partition("=") for line in shown.splitlines()]
        properties = {key: value for key, _, value in lines}
        return cls(
            needs_reload=properties.get("NeedDaemonReload") == "yes",
            enabled=properties.get("UnitFileState") == "enabled",
            active_state=properties.get("ActiveState", ""),
        )

    @property
    def active(self) -> bool:
        return self.active_state == "active"


@dataclass(frozen=True)
class UnitsApplied:
    """What `UserUnits.apply` did: the timers hal declares and whether systemd was reloaded."""

    timers: int
    reloaded: bool
    started: bool

    @property
    def applied(self) -> Applied:
        return Applied.CHANGED if self.reloaded or self.started else Applied.UNCHANGED

    @property
    def fact(self) -> str:
        """The one sentence the timers row shows; an unchanged row stays bare."""
        if self.applied is Applied.UNCHANGED:
            return ""
        return noun(self.timers, "timer") + (" · systemd reloaded" if self.reloaded else "")


@dataclass(frozen=True)
class Findings:
    """What the classification of the unit directory found to do."""

    to_write: tuple[str, ...]
    legacy_units: tuple[str, ...]
    legacy_wants_links: tuple[str, ...]

    @property
    def nothing_to_write(self) -> bool:
        return not (self.to_write or self.legacy_wants_links)


def noun(count: int, singular: str) -> str:
    return f"{count} {singular}" + ("" if count == 1 else "s")


class UserUnits:
    def __init__(
        self,
        layout: Layout,
        jobs: tuple[TimerJob, ...],
        run: CommandRunner,
        replace: Callable[[Path, Path], None] = os.replace,
    ) -> None:
        self.user_units = layout.home / ".config" / "systemd" / "user"
        self.legacy_directory = layout.live_checkout / "systemd"
        checkout_below_home = f"%h/{layout.live_checkout.relative_to(layout.home).as_posix()}"
        self.unit_texts = {
            name: text
            for job in jobs
            for name, text in (
                (job.name + SERVICE_SUFFIX, service_text(job, checkout_below_home)),
                (job.name + TIMER_SUFFIX, timer_text(job)),
            )
        }
        self.timer_names = [job.name + TIMER_SUFFIX for job in jobs]
        self.run = run
        self.replace = replace

    def verify(self) -> bool:
        """Every unit written, nothing to reload, every timer enabled and active, no legacy link.

        Raises when it cannot tell: an entry is not hal's, or systemctl fails.
        """
        findings = self.classify()
        if not findings.nothing_to_write:
            return False
        return all(self.is_settled(name) for name in self.unit_texts)

    def check(self) -> CheckState:
        return CheckState.UNCHANGED if self.verify() else CheckState.WOULD_CHANGE

    def open_fact(self) -> str:
        """What a dry run shows beside `will change`: the old links, only while some exist."""
        findings = self.classify()
        if not (findings.legacy_units or findings.legacy_wants_links):
            return ""
        return f"replaces {noun(len(self.unit_texts), 'link')} with {noun(len(self.timer_names), 'timer')}"

    def apply(self) -> UnitsApplied:
        findings = self.classify()
        try:
            return self.write_and_start(findings)
        except (OSError, StepFailed) as error:
            raise UnitsPartial.of(error) from error

    def write_and_start(self, findings: Findings) -> UnitsApplied:
        self.user_units.mkdir(parents=True, exist_ok=True)
        for name in findings.to_write:
            self.replace_through_temporary(
                self.user_units / name, lambda temporary, name=name: self.create_unit(temporary, name)
            )
        for name in findings.legacy_wants_links:
            self.replace_through_temporary(
                self.timers_wants_link(name),
                lambda temporary, name=name: temporary.symlink_to(self.user_units / name),
            )
        reloaded = not findings.nothing_to_write or any(
            self.show(name).needs_reload for name in self.unit_texts
        )
        if reloaded:
            self.systemctl("daemon-reload")
        started = self.start_idle_timers()
        self.verify_wants_links()
        return UnitsApplied(len(self.timer_names), reloaded, bool(started))

    def classify(self) -> Findings:
        """Sort every entry hal could touch into its own, the legacy links it migrates, and the
        person's, which it refuses before anything changes."""
        to_write: list[str] = []
        legacy_units: list[str] = []
        for name, text in self.unit_texts.items():
            entry = self.user_units / name
            if entry.is_symlink():
                if entry.readlink() != self.legacy_directory / name:
                    raise not_written_by_hal(name)
                legacy_units.append(name)
                to_write.append(name)
            elif os.path.lexists(entry):
                if not self.is_marker_file(entry):
                    raise not_written_by_hal(name)
                if entry.read_bytes() != text.encode():
                    to_write.append(name)
            else:
                to_write.append(name)
        return Findings(tuple(to_write), tuple(legacy_units), self.classify_dependency_entries())

    def classify_dependency_entries(self) -> tuple[str, ...]:
        """The legacy `timers.target.wants/` links to repoint; any other entry of a declared name in
        a dependency directory is refused, a generated wants link accepted as it is."""
        legacy_wants_links: list[str] = []
        for directory in self.dependency_directories():
            for entry in sorted(directory.iterdir()):
                if entry.name not in self.unit_texts:
                    continue
                if self.is_timer_link_into(directory, entry, self.user_units):
                    continue
                if not directory.is_symlink() and self.is_timer_link_into(
                    directory, entry, self.legacy_directory
                ):
                    legacy_wants_links.append(entry.name)
                    continue
                raise not_written_by_hal(entry.relative_to(self.user_units))
        return tuple(legacy_wants_links)

    def is_timer_link_into(self, directory: Path, entry: Path, units_directory: Path) -> bool:
        return (
            directory.name == TIMERS_WANTS_DIRECTORY
            and entry.name in self.timer_names
            and entry.is_symlink()
            and entry.readlink() == units_directory / entry.name
        )

    def dependency_directories(self) -> list[Path]:
        if not self.user_units.is_dir():
            return []
        return sorted(
            directory
            for directory in self.user_units.iterdir()
            if directory.suffix in DEPENDENCY_DIRECTORY_SUFFIXES
            and directory.is_dir()
        )

    @staticmethod
    def is_marker_file(entry: Path) -> bool:
        if not entry.is_file():
            return False
        return entry.read_text(errors="replace").splitlines()[:1] == [GENERATED_MARKER]

    def create_unit(self, path: Path, name: str) -> None:
        with path.open("x") as unit_file:
            unit_file.write(self.unit_texts[name])
        path.chmod(UNIT_FILE_MODE)

    def replace_through_temporary(self, destination: Path, create: Callable[[Path], None]) -> None:
        """Rename a fresh temporary entry over `destination`, so no moment lacks the entry. Creation
        is exclusive: an entry already at the temporary name is the person's and is never removed,
        while a temporary this call created is removed on any later failure."""
        temporary = destination.with_name(f".{destination.name}.tmp")
        try:
            create(temporary)
        except FileExistsError:
            raise
        except OSError:
            temporary.unlink(missing_ok=True)
            raise
        try:
            self.replace(temporary, destination)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise

    def start_idle_timers(self) -> list[str]:
        idle = [name for name in self.timer_names if not self.is_running_enabled(name)]
        for name in idle:
            self.systemctl("enable", "--now", name)
        not_running = [name for name in idle if not self.show(name).active]
        if not_running:
            raise StepFailed(
                f"{', '.join(not_running)} enabled but not active; see `systemctl --user status`"
            )
        return idle

    def verify_wants_links(self) -> None:
        for name in self.timer_names:
            link = self.timers_wants_link(name)
            if not link.is_symlink() or link.readlink() != self.user_units / name:
                raise StepFailed(f"{link} does not point at the generated {name}")

    def timers_wants_link(self, name: str) -> Path:
        return self.user_units / TIMERS_WANTS_DIRECTORY / name

    def is_running_enabled(self, name: str) -> bool:
        unit = self.show(name)
        return unit.enabled and unit.active

    def is_settled(self, name: str) -> bool:
        if self.show(name).needs_reload:
            return False
        return self.is_running_enabled(name) if name in self.timer_names else True

    def show(self, name: str) -> LoadedUnit:
        return LoadedUnit.parse(self.systemctl("show", name, f"--property={SHOWN_PROPERTIES}"))

    def systemctl(self, *arguments: str) -> str:
        output = self.run(["systemctl", "--user", *arguments])
        if output is None:
            raise StepFailed(f"systemctl {' '.join(arguments)} failed")
        return output


def not_written_by_hal(entry: Path | str) -> StepFailed:
    return StepFailed(f"{entry} was not written by hal · move or delete it, then rerun")


def service_text(job: TimerJob, checkout_below_home: str) -> str:
    lines = [GENERATED_MARKER, "[Unit]", f"Description={job.service_description}"]
    if job.documentation:
        lines.append(f"Documentation=file://{checkout_below_home}/{job.documentation}")
    lines += [
        "",
        "[Service]",
        "Type=oneshot",
    ]
    if job.log_format:
        lines.append(f"Environment={LOG_FORMAT_VARIABLE}={job.log_format}")
    lines += [
        f"ExecStart={checkout_below_home}/.venv/bin/{command(job.verb, *job.arguments)}",
    ]
    if job.timeout_start:
        lines.append(f"TimeoutStartSec={job.timeout_start}")
    if job.success_exit_statuses:
        lines.append(f"SuccessExitStatus={' '.join(map(str, job.success_exit_statuses))}")
    return "\n".join(lines) + "\n"


def timer_text(job: TimerJob) -> str:
    lines = [
        GENERATED_MARKER,
        "[Unit]",
        f"Description={job.timer_description}",
        "",
        "[Timer]",
        *schedule_lines(job),
        "",
        "[Install]",
        "WantedBy=timers.target",
    ]
    return "\n".join(lines) + "\n"


def schedule_lines(job: TimerJob) -> list[str]:
    if job.on_calendar:
        return [f"OnCalendar={job.on_calendar}", "Persistent=true"]
    return [f"OnBootSec={job.interval_minutes}min", f"OnUnitActiveSec={job.interval_minutes}min"]
