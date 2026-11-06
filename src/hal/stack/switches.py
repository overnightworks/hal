"""The emergency switch: one marker file per switched-off unit, and the lock that orders stops.

`~/.local/state/edge/stopped/<unit>` holds the switch time (ISO 8601 with offset). The file is
the record (P7): every start path of the stack reads it, and only `hal start` clears it. A unit key
reaches this module only after the catalog resolved it, so no path is built from unchecked text.
The state directory is an argument; only the CLI entry resolves the real one.

`~/.local/state/edge/global-stop` is the global switch (`hal offline`), a fact of its own
beside `stopped/`, so no unit name can fake it. It is read, written and cleared the same way and
under the same lock.
"""

import fcntl
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

STOPPED_DIRECTORY = "stopped"
GLOBAL_STOP_FILE = "global-stop"
GLOBAL_STOP = "the global switch"
LOCK_FILE = "switch.lock"
UNKNOWN_SWITCH_TIME = "unknown time"
_PRIVATE_DIRECTORY = 0o700


class SwitchError(Exception):
    """The marker or the lock cannot be read or written; the message is one line."""


def default_state_directory() -> Path:
    return Path.home() / ".local" / "state" / "edge"


def describe_since(since: str) -> str:
    """`2026-10-17T22:10:04+02:00` as `17.10. 22:10`; text that is no time is shown as it is."""
    try:
        return datetime.fromisoformat(since).strftime("%d.%m. %H:%M")
    except ValueError:
        return since


@dataclass(frozen=True)
class Mark:
    """A marker as one reader saw it: its line and the file's identity.

    A repeated stop rewrites the line unchanged into a new file, so only the identity tells a
    start waiting at its prompt that a stop came in (rule 5).
    """

    since: str
    inode: int
    modified_ns: int


@dataclass(frozen=True)
class Changed:
    """The marker is no longer the one a reader saw; `current` is None when it is gone."""

    current: Mark | None


@dataclass(frozen=True)
class Switches:
    directory: Path

    @property
    def _stopped(self) -> Path:
        return self.directory / STOPPED_DIRECTORY

    def mark(self, unit: str) -> Mark | None:
        """The marker as it is now, or None when the unit is not switched off.

        The file is the record: an empty one still means switched off, at an unknown time.
        """
        return _read_mark(self._stopped / unit, f"the switch of {unit}")

    def global_mark(self) -> Mark | None:
        """The global switch as it is now, or None when the tunnel is not switched off."""
        return _read_mark(self.directory / GLOBAL_STOP_FILE, GLOBAL_STOP)

    def changed(self, unit: str, read: Mark | None) -> Changed | None:
        """What the marker is now when it is no longer the one the caller read, else None."""
        current = self.mark(unit)
        return Changed(current) if current != read else None

    def global_changed(self, read: Mark | None) -> Changed | None:
        """What the global switch is now when it is no longer the one the caller read, else None."""
        current = self.global_mark()
        return Changed(current) if current != read else None

    def since(self, unit: str) -> str | None:
        """The time the unit was switched off, or None when it is not switched off."""
        mark = self.mark(unit)
        return mark.since if mark else None

    def record(self, unit: str, now: datetime) -> None:
        """Write the marker into a new file; a unit keeps the time of its first switch."""
        self._record(self._stopped / unit, f"the switch of {unit}", self.mark(unit), now)

    def record_global(self, now: datetime) -> None:
        """Write the global switch into a new file; it keeps the time of its first stop."""
        self._record(self.directory / GLOBAL_STOP_FILE, GLOBAL_STOP, self.global_mark(), now)

    def clear(self, unit: str, expected: Mark) -> bool:
        """Remove the marker only if it is still the one the caller read."""
        if self.changed(unit, expected):
            return False
        _unlink(self._stopped / unit, f"the switch of {unit}")
        return True

    def clear_global(self, expected: Mark) -> bool:
        """Remove the global switch only if it is still the one the caller read."""
        if self.global_changed(expected):
            return False
        _unlink(self.directory / GLOBAL_STOP_FILE, GLOBAL_STOP)
        return True

    def _record(self, path: Path, what: str, recorded: Mark | None, now: datetime) -> None:
        first = recorded.since if recorded and recorded.since != UNKNOWN_SWITCH_TIME else None
        try:
            self._make_private_directories()
            write_atomically(
                path, first or now.isoformat(timespec="seconds"), keep_existing=recorded is None
            )
        except OSError as error:
            raise SwitchError(f"cannot record {what} ({error.strerror})") from error

    @contextmanager
    def lock(self) -> Iterator[None]:
        """Exclusive; held only around "read the marker, then `up`", around a `stop` and around a
        live restore's re-check of the marker and its load."""
        try:
            self._make_private_directories()
            descriptor = os.open(self.directory / LOCK_FILE, os.O_CREAT | os.O_WRONLY, 0o600)
        except OSError as error:
            raise SwitchError(f"cannot take the switch lock ({error.strerror})") from error
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def _make_private_directories(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self._stopped.mkdir(mode=_PRIVATE_DIRECTORY, exist_ok=True)
        self._stopped.chmod(_PRIVATE_DIRECTORY)


def _read_mark(path: Path, what: str) -> Mark | None:
    try:
        with path.open() as file:
            status = os.fstat(file.fileno())
            line = file.read().strip()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise SwitchError(f"cannot read {what} ({error.strerror})") from error
    return Mark(line or UNKNOWN_SWITCH_TIME, status.st_ino, status.st_mtime_ns)


def _unlink(path: Path, what: str) -> None:
    try:
        path.unlink()
    except OSError as error:
        raise SwitchError(f"cannot clear {what} ({error.strerror})") from error


def _link_unless_present(source: str, path: Path) -> None:
    # the first writer's time stands
    with suppress(FileExistsError):
        os.link(source, path)


def write_atomically(path: Path, text: str, *, keep_existing: bool) -> None:
    """Publish the file whole; `keep_existing` leaves a file another writer published meanwhile."""
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "w") as file:
            file.write(f"{text}\n")
            file.flush()
            os.fsync(file.fileno())
        if keep_existing:
            _link_unless_present(temporary, path)
        else:
            os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    Path(temporary).unlink(missing_ok=True)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
