"""What every `home` report shares: its Markdown building blocks, and the one way the secrets and check state files reach and leave disk."""

from __future__ import annotations

import contextlib
import os
import stat
import unicodedata
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from pathlib import Path


def findings_count(count: int) -> str:
    """English singular and plural: "1 finding", "0 findings", "2 findings"."""
    return "1 finding" if count == 1 else f"{count} findings"


class Level(IntEnum):
    """How much a finding matters today; an area stands at the worst level of its findings."""

    OK = 0
    NOTE = 1
    ACTION = 2

    @property
    def label(self) -> str:
        return {Level.OK: "OK", Level.NOTE: "Note", Level.ACTION: "Action needed"}[self]


@dataclass(frozen=True)
class Finding:
    """What a check reports: its identity is rule plus subject, so a finding's age or detail never makes it a new one."""

    rule: str
    subject: str
    detail: str

    @property
    def identity(self) -> str:
        return f"{self.rule}\t{self.subject}"


def render_findings_report(name: str, now: datetime, status_lines: Sequence[str], findings: Sequence[Finding]) -> str:
    """The report of one check: title with the count, the lines that state what was read, then the findings."""
    lines = [f"# {name} {now:%d.%m.%Y %H:%M} | {findings_count(len(findings))}", ""]
    lines += [f"- {line}" for line in status_lines]
    lines.append("")
    if findings:
        lines += markdown_table(["Rule", "Subject", "Finding"], [[f.rule, f.subject, f.detail] for f in findings])
    else:
        lines.append("No findings.")
    return "\n".join(lines) + "\n"


def _escape_cell(text: str) -> str:
    return "".join(_escape_character(character) for character in text)


def _escape_character(character: str) -> str:
    """A pipe would split the cell, a control character such as a newline the row, and a surrogate from a file name
    that is not UTF-8 the writing of the report, so each shows as an escape."""
    if character == "|":
        return "\\|"
    if unicodedata.category(character) in {"Cc", "Cs"}:
        return character.encode("unicode_escape").decode("ascii")
    return character


def markdown_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    """One line per row; an empty cell shows as "-" so no column ever looks shifted."""
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    lines.extend("| " + " | ".join(_escape_cell(cell) or "-" for cell in row) + " |" for row in rows)
    return lines


def write_state_file(home: Path, path: Path, text: str) -> None:
    """Replaces a file of home's state directory below `home`; a symlink on the way there is refused, never followed.

    The new text goes to a fresh file that is renamed over the old one, which is never opened: a symlink or hard link
    planted there is replaced, not written through. Either kind of link would otherwise let a report overwrite a file
    outside the state directory, a secret under ~/.secrets included.
    """
    directory = _open_state_directory(home, path.parent.relative_to(home))
    try:
        _replace(directory, path.name, text)
    finally:
        os.close(directory)


def read_state_file(home: Path, path: Path, *, create_directories: bool = True) -> str | None:
    """Reads a file of home's state directory below `home` without following a symlink anywhere on the way.

    None when the file does not exist yet. A symlink in its place raises instead of being read, because its target
    may lie outside the state directory, a secret under ~/.secrets included. Anything else that is not a regular file
    raises too; it is opened without blocking, because a FIFO planted there would otherwise wait forever for a writer.
    A reader that must not change the disk passes `create_directories=False`; a missing directory then raises.
    """
    directory = _open_state_directory(home, path.parent.relative_to(home), create_directories=create_directories)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return None
    finally:
        os.close(directory)
    with open(descriptor) as state_file:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"{path} is not a regular file")
        return state_file.read()


def _replace(directory: int, name: str, text: str) -> None:
    fresh = f".{name}.{uuid.uuid4().hex}"
    descriptor = os.open(fresh, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666, dir_fd=directory)
    try:
        with open(descriptor, "w") as fresh_file:
            fresh_file.write(text)
        os.replace(fresh, name, src_dir_fd=directory, dst_dir_fd=directory)
    except BaseException:
        os.unlink(fresh, dir_fd=directory)
        raise


def _open_state_directory(home: Path, below_home: Path, *, create_directories: bool = True) -> int:
    """Opens the directories below home one at a time without following a symlink, creating the missing ones if asked."""
    directory = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
    for name in below_home.parts:
        try:
            if create_directories:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(name, dir_fd=directory)
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        finally:
            os.close(directory)
        directory = child
    return directory
