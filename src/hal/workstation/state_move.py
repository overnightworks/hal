"""The mover of `hal migrate state`: hal's state leaves the directories its old names gave it.

This module alone names the old directories. Each source merges into its target on its own. A file
goes by `link`, then `unlink`, so it keeps its inode, and a name the target already has stays the
target's: the source's copy is named `remove`. A directory is never renamed or replaced, so a
writer holding a descriptor on a target is unaffected; it is created with the source's mode when
absent, its entries go the same way, then the source goes by `rmdir`. A file against a directory
is refused before anything moves. The old state's locks are not moved: they are unlinked while
held, then its directory goes; a name that appeared meanwhile fails that `rmdir`, loud. The old
locks are opened without creating them, so a refusal recreates nothing. A rerun
goes on from the disk, so a stop at any step loses no entry.
"""

import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

OLD_STATE = Path(".local/state/edge")  # below the home directory: the stack's, the backup's, locks
OLD_HOME_STATE = Path(".local/state/home")  # below the home directory: the check's and secrets'
OLD_CACHE = Path(".cache/edge-backup")  # below the home directory: the backup's staging
_PRIVATE_DIRECTORY = 0o700
_PRIVATE_FILE = 0o600


class Action(StrEnum):
    MOVE = "move"
    REMOVE = "remove"
    CLOSE = "close"


class Refusal(Exception):
    """A held lock or a file against a directory: nothing was changed. The message is one line."""


class Stopped(Exception):
    """The move stopped part way at `entry`; a rerun finishes it."""

    def __init__(self, entry: Path, reason: str, stays: bool = False) -> None:
        super().__init__(entry, reason, stays)
        self.entry = entry
        self.reason = reason
        self.stays = stays

    def describe(self, shown: str) -> str:
        what = f"{shown} stays" if self.stays else f"cannot move {shown}"
        return f"{what} ({self.reason})"


@dataclass(frozen=True)
class Targets:
    """Where each kind of state lives now, and the names of the locks, as their owners say."""

    state: Path
    cache: Path
    lock_names: frozenset[str]


@dataclass(frozen=True)
class SourcePlan:
    """One old directory: its directories with their modes, parents first, then its entries."""

    source: Path
    target: Path
    directories: tuple[tuple[Path, int], ...]
    entries: tuple[tuple[Action, Path], ...]

    def target_of(self, path: Path) -> Path:
        return self.target / path.relative_to(self.source)

    def names(self, action: Action) -> tuple[str, ...]:
        return tuple(
            path.relative_to(self.source).as_posix() for kind, path in self.entries if kind is action
        )


def make_plan(home: Path, targets: Targets) -> tuple[SourcePlan, ...]:
    """The sources that exist, in the order they move; raises Refusal."""
    sources = (
        (home / OLD_STATE, targets.state, targets.lock_names),
        (home / OLD_HOME_STATE, targets.state, frozenset()),
        (home / OLD_CACHE, targets.cache, frozenset()),
    )
    plans: list[SourcePlan] = []
    claimed: set[Path] = set()
    for source, target, locks in sources:
        if os.path.lexists(source):
            plan = _plan(source, target, locks, claimed)
            claimed.update(plan.target_of(path) for action, path in plan.entries if action is Action.MOVE)
            plans.append(plan)
    return tuple(plans)


def _plan(source: Path, target: Path, lock_names: frozenset[str], claimed: set[Path]) -> SourcePlan:
    directories: list[tuple[Path, int]] = []
    entries: list[tuple[Action, Path]] = []
    _walk(source, target, directories, entries, claimed)
    is_lock = {path: path.parent == source and path.name in lock_names for _, path in entries}
    moved = [(action, path) for action, path in entries if not is_lock[path]]
    closed = [(Action.CLOSE, path) for _, path in entries if is_lock[path]]
    return SourcePlan(source, target, tuple(directories), (*moved, *closed))


def _walk(
    source: Path, target: Path, directories: list, entries: list, claimed: set[Path]
) -> None:
    status = source.lstat()
    if not stat.S_ISDIR(status.st_mode):
        raise Refusal(f"{source} is no directory")
    directories.append((source, stat.S_IMODE(status.st_mode)))
    for name in sorted(os.listdir(source)):
        entry, counterpart = source / name, target / name
        entry_is_directory = _is_directory(entry)
        if os.path.lexists(counterpart) and entry_is_directory != _is_directory(counterpart):
            raise Refusal(f"{entry} and {counterpart} are not both directories")
        if entry_is_directory:
            _walk(entry, counterpart, directories, entries, claimed)
        else:
            taken = os.path.lexists(counterpart) or counterpart in claimed
            action = Action.REMOVE if taken else Action.MOVE
            entries.append((action, entry))


def _is_directory(path: Path) -> bool:
    return path.is_dir() and not path.is_symlink()


@contextmanager
def held_locks(home: Path, targets: Targets) -> Iterator[None]:
    """Both lock domains for the whole move, without waiting: the old state's, opened without
    creating anything, and the new state's. Raises Refusal while another process holds one."""
    old_state = home / OLD_STATE
    with ExitStack() as stack:
        for name in sorted(targets.lock_names):
            with suppress(FileNotFoundError):
                _hold(stack, old_state / name, os.O_WRONLY | os.O_CLOEXEC)
        if not targets.state.exists():
            targets.state.parent.mkdir(parents=True, exist_ok=True)
            source_mode = stat.S_IMODE(old_state.stat().st_mode) if old_state.is_dir() else None
            _make_directory(targets.state, source_mode or _PRIVATE_DIRECTORY)
        for name in sorted(targets.lock_names):
            _hold(stack, targets.state / name, os.O_WRONLY | os.O_CLOEXEC | os.O_CREAT)
        yield


def _hold(stack: ExitStack, path: Path, flags: int) -> None:
    descriptor = os.open(path, flags, _PRIVATE_FILE)
    stack.callback(os.close, descriptor)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise Refusal(f"{path} is held by another process") from None


def move(plan: SourcePlan) -> None:
    """One source into its target, as planned; raises Stopped."""
    try:
        for directory, mode in plan.directories:
            _make_directory(plan.target_of(directory), mode)
        for action, path in plan.entries:
            if action is Action.MOVE:
                _move_file(path, plan.target_of(path))
            elif action is Action.CLOSE or os.path.lexists(plan.target_of(path)):
                with suppress(FileNotFoundError):
                    os.unlink(path)
        for directory, _ in reversed(plan.directories):
            _remove_directory(directory)
    except OSError as error:
        entry = Path(os.fsdecode(error.filename)) if error.filename else plan.source
        raise Stopped(entry, error.strerror) from error


def _make_directory(path: Path, mode: int) -> None:
    try:
        os.mkdir(path, mode)
    except FileExistsError:
        return
    os.chmod(path, mode)


def _move_file(source: Path, target: Path) -> None:
    try:
        os.link(source, target, follow_symlinks=False)
    except FileNotFoundError, FileExistsError:
        return  # gone meanwhile, or a copy published meanwhile, which stays; then rmdir says so
    os.unlink(source)


def _remove_directory(path: Path) -> None:
    try:
        os.rmdir(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise Stopped(path, error.strerror, stays=True) from error
