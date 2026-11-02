"""The status contract a Gatus light and `hal check` read: versioned JSON, written atomically.

It never carries raw output, command lines, paths, file names or content.
"""

import json
import os
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Self

SCHEMA = 2
LEGACY_SCHEMA = 1


class State(StrEnum):
    RUNNING = "running"
    OK = "ok"
    FAILED = "failed"


class Phase(StrEnum):
    PREPARE = "prepare"
    READINESS = "readiness"
    DUMP = "dump"
    MANIFEST = "manifest"
    BACKUP = "backup"
    FORGET = "forget"
    CHECK = "check"
    RESTORE = "restore"
    VERIFY = "verify"


class ExitCategory(StrEnum):
    CONFIGURATION = "configuration"
    NOT_READY = "not-ready"
    COMMAND_FAILED = "command-failed"
    VERIFICATION_FAILED = "verification-failed"
    INTERRUPTED = "interrupted"
    INTERNAL = "internal"


class StatusFileError(ValueError):
    """The previous status file cannot be read, so its history cannot be carried over."""


@dataclass(frozen=True)
class AppHistory:
    """What one app's runs have achieved: the last good snapshot and when it was proven."""

    last_snapshot_id: str | None = None
    last_successful_backup: datetime | None = None
    last_successful_restore_test: datetime | None = None

    def as_json(self) -> dict[str, object]:
        return {
            "last_snapshot_id": self.last_snapshot_id,
            "last_successful_backup": _optional_time(self.last_successful_backup),
            "last_successful_restore_test": _optional_time(self.last_successful_restore_test),
        }

    @classmethod
    def from_json(cls, record: dict) -> Self:
        return cls(
            last_snapshot_id=record["last_snapshot_id"],
            last_successful_backup=_parsed_time(record["last_successful_backup"]),
            last_successful_restore_test=_parsed_time(record["last_successful_restore_test"]),
        )


@dataclass(frozen=True)
class Status:
    """The run's verdict, and per app name (also its restic tag) the history of its successes.

    `unattributed` is what a schema-1 file claimed before there was more than one app: it moves
    to an app only on restic's evidence, and is never deleted.
    """

    state: State
    phase: Phase
    last_attempt: datetime
    apps: dict[str, AppHistory] = field(default_factory=dict)
    unattributed: AppHistory | None = None
    failing_phase: Phase | None = None
    failing_app: str | None = None
    exit_category: ExitCategory | None = None

    def as_json(self) -> dict[str, object]:
        document: dict[str, object] = {
            "schema": SCHEMA,
            "state": self.state.value,
            "phase": self.phase.value,
            "failing_phase": _optional_value(self.failing_phase),
            "failing_app": self.failing_app,
            "exit_category": _optional_value(self.exit_category),
            "last_attempt": self.last_attempt.isoformat(),
            "apps": {name: self.apps[name].as_json() for name in sorted(self.apps)},
        }
        if self.unattributed is not None:
            document["unattributed"] = self.unattributed.as_json()
        return document

    def attempt(self, started: datetime) -> Status:
        """A new run starts: history carries over, the verdict does not."""
        return Status(
            state=State.RUNNING,
            phase=Phase.PREPARE,
            last_attempt=started,
            apps=self.apps,
            unattributed=self.unattributed,
        )

    def snapshot_of(self, app: str) -> str | None:
        return self._history_of(app).last_snapshot_id

    def last_backup_of(self, app: str) -> datetime | None:
        return self._history_of(app).last_successful_backup

    def entering(self, phase: Phase) -> Status:
        return replace(self, phase=phase)

    def backed_up(self, app: str, at: datetime, snapshot_id: str) -> Status:
        previous = self._history_of(app)
        history = AppHistory(
            last_snapshot_id=snapshot_id,
            last_successful_backup=at,
            last_successful_restore_test=previous.last_successful_restore_test,
        )
        return self._with_history(app, history)

    def restore_tested(self, at: datetime, apps: Iterable[str]) -> Status:
        tested = {
            app: replace(self._history_of(app), last_successful_restore_test=at) for app in apps
        }
        return replace(self, apps={**self.apps, **tested})

    def attributed_to(self, app: str) -> Status:
        """The one move of legacy evidence, called only once restic has confirmed it."""
        assert self.unattributed is not None  # noqa: S101 - restic confirmed the move before this call
        return replace(self._with_history(app, self.unattributed), unattributed=None)

    def failed(
        self, category: ExitCategory, app: str | None = None, phase: Phase | None = None
    ) -> Status:
        return replace(
            self,
            state=State.FAILED,
            failing_phase=phase or self.phase,
            failing_app=app,
            exit_category=category,
        )

    def succeeded(self) -> Status:
        return replace(self, state=State.OK)

    def _history_of(self, app: str) -> AppHistory:
        return self.apps.get(app, AppHistory())

    def _with_history(self, app: str, history: AppHistory) -> Status:
        return replace(self, apps={**self.apps, app: history})


def first_attempt(started: datetime) -> Status:
    return Status(state=State.RUNNING, phase=Phase.PREPARE, last_attempt=started)


def read_status(path: Path) -> Status | None:
    """The one decoder: schema 1 is read into the schema-2 model, never kept as a second shape."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise StatusFileError(
            f"the previous status file is unreadable: {error.strerror}"
        ) from error
    try:
        return _parse(json.loads(raw))
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        raise StatusFileError("the previous status file is unreadable") from error


def write_status(path: Path, status: Status) -> None:
    """Temp file in the same directory, then rename: a reader never sees half a status."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(status.as_json(), handle, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _parse(document: dict) -> Status:
    schema = document["schema"]
    if schema == SCHEMA:
        apps = {name: AppHistory.from_json(record) for name, record in document["apps"].items()}
        unattributed = document.get("unattributed")
        return _parse_verdict(
            document,
            apps=apps,
            unattributed=None if unattributed is None else AppHistory.from_json(unattributed),
            failing_app=document["failing_app"],
        )
    if schema == LEGACY_SCHEMA:
        return _parse_verdict(
            document, apps={}, unattributed=AppHistory.from_json(document), failing_app=None
        )
    raise ValueError(f"schema {schema!r}")


def _parse_verdict(
    document: dict,
    *,
    apps: dict[str, AppHistory],
    unattributed: AppHistory | None,
    failing_app: str | None,
) -> Status:
    return Status(
        state=State(document["state"]),
        phase=Phase(document["phase"]),
        last_attempt=datetime.fromisoformat(document["last_attempt"]),
        apps=apps,
        unattributed=None if unattributed == AppHistory() else unattributed,
        failing_phase=_parsed(Phase, document["failing_phase"]),
        failing_app=failing_app,
        exit_category=_parsed(ExitCategory, document["exit_category"]),
    )


def _optional_value(member: StrEnum | None) -> str | None:
    return None if member is None else member.value


def _optional_time(moment: datetime | None) -> str | None:
    return None if moment is None else moment.isoformat()


def _parsed_time(text: str | None) -> datetime | None:
    return None if text is None else datetime.fromisoformat(text)


def _parsed[E: StrEnum](enum: type[E], text: str | None) -> E | None:
    return None if text is None else enum(text)
