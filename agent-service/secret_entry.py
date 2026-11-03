"""A secret file in a verified folder under ~/.secrets/agent-service, for agent-service/setup: its
entry read through the folder's descriptor, what the operator must fix about it, its leftovers,
and the steps every such file takes (the preflight, the check, acting under the folder's lock and
the confirmed replacement).

signing_key.py judges, makes and replaces the signing key's files on top of this. The
module also owns what the steps of `setup` raise (StepFailure, CannotTell) and the bounded read of
agent-runtime's secret-file reader, because `setup` is a script that its modules cannot import back.
"""

from __future__ import annotations

import contextlib
import errno
import os
import stat
from collections.abc import Callable, Collection, Iterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol

MAX_SECRET_FILE_BYTES = 16 * 1024  # reader: MAX_SECRET_FILE_BYTES
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class StepFailure(Exception):
    """A step cannot finish; the message says why in one line, never a secret."""


class CannotTell(StepFailure):
    """Docker or the host did not answer, so the state of a step is unknown."""


def read_within_limit(descriptor: int) -> bytes:
    """At most one byte more than the limit, looping on short reads as the reader does
    (secret_file.py:144-155, _read_within_limit): that many bytes mean the file is too big."""
    chunks: list[bytes] = []
    remaining = MAX_SECRET_FILE_BYTES + 1
    while remaining and (chunk := os.read(descriptor, remaining)):
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def size_refusal(contents: bytes) -> str | None:
    """The reader refuses a file over its limit; one within it was read whole."""
    if len(contents) > MAX_SECRET_FILE_BYTES:
        return f"is larger than {MAX_SECRET_FILE_BYTES} bytes"
    return None


@dataclass(frozen=True)
class Entry:
    """A secret file as one descriptor saw it; `problem` is a sentence naming what the operator
    fixes, and `unreadable` marks a file its owner cannot read (its mode says why)."""

    path: Path
    status: os.stat_result
    contents: bytes = b""
    problem: str | None = None
    unreadable: bool = False


class SecretTools(Protocol):
    service_uid: int
    say: Callable[[str], None]
    has_terminal: Callable[[], bool]
    confirm: Callable[[str], str]


class SecretHost(Protocol):
    """What `setup` lends a secret file: its folders, its locking and its owner verdicts."""

    tools: SecretTools

    def open_verified_directories(
        self, directories: tuple[Path, ...], tolerate_open_mode: bool = False
    ) -> int: ...

    def lock(self, directory: int) -> None: ...

    def directory_gap(self, directory: Path): ...  # a Gap or None

    def wrong_owner(self, path: Path, uid: int): ...  # a Gap

    def write_pending(self, directory: int, payload: bytes, name: str, mode: int) -> None: ...


class SecretFolder:
    """The last folder of `chain`, reached through verified descriptors, and its secret files."""

    def __init__(self, host: SecretHost, chain: tuple[Path, ...]) -> None:
        self.host = host
        self.chain = chain
        self.path = chain[-1]

    @contextlib.contextmanager
    def opened(self, locked: bool) -> Iterator[int]:
        """The folder's descriptor, held under its lock when `locked`, until the block ends."""
        directory = self.host.open_verified_directories(self.chain)
        try:
            if locked:
                self.host.lock(directory)
            yield directory
        finally:
            os.close(directory)

    def preflight(
        self, judge: Callable[[int], tuple[Enum, str]], unusable: Collection[Enum]
    ) -> None:
        """Refuse an unusable file or folder before `setup` changes anything else. Only a folder
        that is not made yet or is open to others passes: the folder steps of `setup` mend those."""
        try:
            directory = self.host.open_verified_directories(self.chain, tolerate_open_mode=True)
        except FileNotFoundError:
            return
        try:
            state, line = judge(directory)
        finally:
            os.close(directory)
        if state in unusable:
            raise StepFailure(line)

    def check(
        self, judge: Callable[[int], tuple[Enum, str]], sound: Enum, leftovers: tuple[str, ...]
    ) -> None:
        """Pass only a sound file with none of `leftovers` beside it; change nothing."""
        with self.opened(locked=False) as directory:
            state, line = judge(directory)
            found = list(self.leftover_statuses(directory, leftovers))
        if state is not sound:
            raise StepFailure(line)
        if found:
            names = ", ".join(found)
            raise StepFailure(f"{names} left by an interrupted run; `agent-service/setup` clears")

    def confirm_replacement(self, flag: str, warning: str, prompt: str) -> None:
        """Go on only at a terminal, in a folder setup has made, after the operator typed yes."""
        tools = self.host.tools
        if not tools.has_terminal():
            raise StepFailure(f"{flag} needs a terminal; nothing was changed")
        if gap := self.host.directory_gap(self.path):
            raise StepFailure(f"{gap.line}; run agent-service/setup first")
        tools.say(warning)
        try:
            answer = tools.confirm(prompt)
        except EOFError:
            answer = ""
        if answer.strip() != "yes":
            raise StepFailure("not confirmed; nothing was changed")

    def operator_problem(
        self, entries: Collection[Entry | None], leftovers: dict[str, os.stat_result]
    ) -> str | None:
        """The first entry or leftover the operator must fix himself, as one line, else None."""
        problems = [entry.problem for entry in entries if entry and entry.problem]
        problems += [self.entry_problem(self.path / name, s) for name, s in leftovers.items()]
        if problem := next(filter(None, problems), None):
            return f"{problem}; fix it yourself"
        return None

    @staticmethod
    def leftover_statuses(directory: int, names: tuple[str, ...]) -> dict[str, os.stat_result]:
        """Each temporary entry that exists, looked at without following a link."""
        statuses = {}
        for name in names:
            with contextlib.suppress(FileNotFoundError):
                statuses[name] = os.stat(name, dir_fd=directory, follow_symlinks=False)
        return statuses

    def entry_problem(self, path: Path, status: os.stat_result) -> str | None:
        """A link, no regular file or another owner is never narrowed or unlinked: it is the
        operator's to look at."""
        if stat.S_ISLNK(status.st_mode):
            return f"{path} is a symbolic link"
        if not stat.S_ISREG(status.st_mode):
            return f"{path} is not a regular file"
        if status.st_uid != self.host.tools.service_uid:
            return self.host.wrong_owner(path, status.st_uid).line
        return None

    def read_entry(self, directory: int, name: str) -> Entry | None:
        """The whole file when it is within the reader's limit, one byte past it when it is not."""
        path = self.path / name
        try:
            descriptor = os.open(name, READ_FLAGS, dir_fd=directory)
        except FileNotFoundError:
            return None
        except PermissionError:
            return self.entry_of_unreadable_file(directory, name)
        except OSError as error:
            if error.errno == errno.ELOOP:
                status = os.stat(name, dir_fd=directory, follow_symlinks=False)
                return Entry(path, status, problem=f"{path} is a symbolic link")
            raise
        try:
            status = os.fstat(descriptor)
            if problem := self.entry_problem(path, status):
                return Entry(path, status, problem=problem)
            return Entry(path, status, read_within_limit(descriptor))
        finally:
            os.close(descriptor)

    def entry_of_unreadable_file(self, directory: int, name: str) -> Entry:
        """Judged by its owner first: a file of another owner is the operator's fix whatever its
        mode, and only a file of the right owner that its mode lets read but that cannot be opened
        is a host failure, which stays one."""
        path = self.path / name
        status = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if problem := self.entry_problem(path, status):
            return Entry(path, status, problem=problem, unreadable=True)
        if status.st_mode & stat.S_IRUSR:
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(path))
        return Entry(path, status, unreadable=True)

    @staticmethod
    def link_into_place(directory: int, source: str, destination: str) -> None:
        """Exclusive: link(2) refuses any existing entry, so a file made meanwhile is never
        replaced."""
        os.link(source, destination, src_dir_fd=directory, dst_dir_fd=directory,
                follow_symlinks=False)  # fmt: skip
        os.unlink(source, dir_fd=directory)
        os.fsync(directory)

    @staticmethod
    def rename_into_place(directory: int, source: str, destination: str) -> None:
        os.replace(source, destination, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)

    @staticmethod
    def unlink_all(directory: int, names: tuple[str, ...]) -> None:
        for name in names:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(name, dir_fd=directory)
